#!/usr/bin/env node

const http = require('http');
const httpProxy = require('http-proxy');
const fs = require('fs');
const path = require('path');

// Load balancer configuration
const config = {
  port: process.env.LB_PORT || 3000,
  targets: [
    { host: 'localhost', port: 5000, weight: 1 },
    { host: 'localhost', port: 5001, weight: 1 },
    { host: 'localhost', port: 5002, weight: 1 },
  ],
  healthCheck: {
    interval: 30000, // 30 seconds
    timeout: 5000,   // 5 seconds
    path: '/health',
  },
  strategy: 'round-robin', // 'round-robin', 'least-connections', 'weighted'
};

class LoadBalancer {
  constructor(config) {
    this.config = config;
    this.targets = config.targets.map(target => ({
      ...target,
      healthy: true,
      connections: 0,
      lastHealthCheck: null,
    }));
    this.currentIndex = 0;
    this.proxy = httpProxy.createProxyServer({});
    this.server = null;
    
    this.setupProxyEvents();
    this.startHealthChecks();
  }
  
  setupProxyEvents() {
    this.proxy.on('error', (err, req, res) => {
      console.error('Proxy error:', err.message);
      
      if (res && !res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Bad Gateway',
          message: 'Unable to connect to backend server'
        }));
      }
    });
    
    this.proxy.on('proxyReq', (proxyReq, req, res, options) => {
      // Add load balancer headers
      proxyReq.setHeader('X-Forwarded-By', 'museum-load-balancer');
      proxyReq.setHeader('X-Forwarded-Proto', req.connection.encrypted ? 'https' : 'http');
      
      // Track connection
      const target = this.targets.find(t => 
        t.host === options.target.host && t.port === options.target.port
      );
      if (target) {
        target.connections++;
      }
    });
    
    this.proxy.on('proxyRes', (proxyRes, req, res, options) => {
      // Add response headers
      proxyRes.headers['X-Load-Balancer'] = 'museum-lb';
      proxyRes.headers['X-Backend-Server'] = `${options.target.host}:${options.target.port}`;
      
      // Track connection completion
      const target = this.targets.find(t => 
        t.host === options.target.host && t.port === options.target.port
      );
      if (target && target.connections > 0) {
        target.connections--;
      }
    });
  }
  
  getHealthyTargets() {
    return this.targets.filter(target => target.healthy);
  }
  
  selectTarget(req) {
    const healthyTargets = this.getHealthyTargets();
    
    if (healthyTargets.length === 0) {
      throw new Error('No healthy backend servers available');
    }
    
    switch (this.config.strategy) {
      case 'round-robin':
        return this.roundRobinSelection(healthyTargets);
      case 'least-connections':
        return this.leastConnectionsSelection(healthyTargets);
      case 'weighted':
        return this.weightedSelection(healthyTargets);
      default:
        return this.roundRobinSelection(healthyTargets);
    }
  }
  
  roundRobinSelection(targets) {
    const target = targets[this.currentIndex % targets.length];
    this.currentIndex++;
    return target;
  }
  
  leastConnectionsSelection(targets) {
    return targets.reduce((min, target) => 
      target.connections < min.connections ? target : min
    );
  }
  
  weightedSelection(targets) {
    const totalWeight = targets.reduce((sum, target) => sum + target.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const target of targets) {
      random -= target.weight;
      if (random <= 0) {
        return target;
      }
    }
    
    return targets[0]; // Fallback
  }
  
  async checkHealth(target) {
    return new Promise((resolve) => {
      const options = {
        hostname: target.host,
        port: target.port,
        path: this.config.healthCheck.path,
        method: 'GET',
        timeout: this.config.healthCheck.timeout,
      };
      
      const req = http.request(options, (res) => {
        const healthy = res.statusCode >= 200 && res.statusCode < 400;
        resolve(healthy);
      });
      
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
      
      req.end();
    });
  }
  
  async performHealthChecks() {
    for (const target of this.targets) {
      const wasHealthy = target.healthy;
      target.healthy = await this.checkHealth(target);
      target.lastHealthCheck = new Date();
      
      if (wasHealthy !== target.healthy) {
        const status = target.healthy ? 'HEALTHY' : 'UNHEALTHY';
        console.log(`[${new Date().toISOString()}] Target ${target.host}:${target.port} is now ${status}`);
      }
    }
  }
  
  startHealthChecks() {
    // Initial health check
    this.performHealthChecks();
    
    // Periodic health checks
    setInterval(() => {
      this.performHealthChecks();
    }, this.config.healthCheck.interval);
  }
  
  handleRequest(req, res) {
    try {
      // Handle load balancer status endpoint
      if (req.url === '/lb-status') {
        return this.handleStatusRequest(req, res);
      }
      
      const target = this.selectTarget(req);
      const targetUrl = `http://${target.host}:${target.port}`;
      
      console.log(`[${new Date().toISOString()}] Proxying ${req.method} ${req.url} to ${targetUrl}`);
      
      this.proxy.web(req, res, {
        target: targetUrl,
        changeOrigin: true,
        timeout: 30000, // 30 seconds
      });
      
    } catch (error) {
      console.error('Load balancer error:', error.message);
      
      if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Service Unavailable',
          message: error.message
        }));
      }
    }
  }
  
  handleStatusRequest(req, res) {
    const status = {
      loadBalancer: {
        uptime: process.uptime(),
        strategy: this.config.strategy,
        port: this.config.port,
      },
      targets: this.targets.map(target => ({
        host: target.host,
        port: target.port,
        healthy: target.healthy,
        connections: target.connections,
        weight: target.weight,
        lastHealthCheck: target.lastHealthCheck,
      })),
      stats: {
        totalTargets: this.targets.length,
        healthyTargets: this.getHealthyTargets().length,
        totalConnections: this.targets.reduce((sum, t) => sum + t.connections, 0),
      }
    };
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(status, null, 2));
  }
  
  start() {
    this.server = http.createServer((req, res) => {
      this.handleRequest(req, res);
    });
    
    this.server.listen(this.config.port, () => {
      console.log(`🔄 Load Balancer started on port ${this.config.port}`);
      console.log(`📊 Strategy: ${this.config.strategy}`);
      console.log(`🎯 Targets: ${this.targets.map(t => `${t.host}:${t.port}`).join(', ')}`);
      console.log(`💓 Health checks every ${this.config.healthCheck.interval / 1000}s`);
      console.log(`📈 Status endpoint: http://localhost:${this.config.port}/lb-status`);
    });
    
    // Graceful shutdown
    process.on('SIGTERM', () => this.shutdown());
    process.on('SIGINT', () => this.shutdown());
  }
  
  shutdown() {
    console.log('\n🛑 Shutting down load balancer...');
    
    if (this.server) {
      this.server.close(() => {
        console.log('✅ Load balancer stopped');
        process.exit(0);
      });
    }
  }
}

// Nginx configuration generator
function generateNginxConfig() {
  const nginxConfig = `
# Museum Collection Load Balancer Configuration
upstream museum_backend {
    least_conn;
    ${config.targets.map(target => 
      `server ${target.host}:${target.port} weight=${target.weight} max_fails=3 fail_timeout=30s;`
    ).join('\n    ')}
}

server {
    listen 80;
    server_name museum-app.com www.museum-app.com;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://museum_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    # Login endpoint with stricter rate limiting
    location /api/users/login {
        limit_req zone=login burst=5 nodelay;
        
        proxy_pass http://museum_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://museum_backend;
        access_log off;
    }
    
    # Static files (if serving from backend)
    location /static/ {
        proxy_pass http://museum_backend;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # Error pages
    error_page 502 503 504 /50x.html;
    location = /50x.html {
        root /usr/share/nginx/html;
    }
}

# HTTPS redirect (if using SSL)
server {
    listen 443 ssl http2;
    server_name museum-app.com www.museum-app.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Include the same location blocks as above
    include /etc/nginx/conf.d/museum-locations.conf;
}
`;
  
  return nginxConfig.trim();
}

// Main execution
if (require.main === module) {
  const command = process.argv[2];
  
  switch (command) {
    case 'start':
      const lb = new LoadBalancer(config);
      lb.start();
      break;
      
    case 'nginx-config':
      console.log(generateNginxConfig());
      break;
      
    default:
      console.log('Museum Collection Load Balancer');
      console.log('================================');
      console.log('');
      console.log('Usage:');
      console.log('  node load-balancer.js start        - Start the load balancer');
      console.log('  node load-balancer.js nginx-config - Generate Nginx configuration');
      console.log('');
      console.log('Environment Variables:');
      console.log('  LB_PORT - Load balancer port (default: 3000)');
      break;
  }
}

module.exports = { LoadBalancer, config, generateNginxConfig };

