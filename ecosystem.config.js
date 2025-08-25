module.exports = {
  apps: [
    {
      name: 'museum-backend',
      script: './server.js',
      instances: 'max', // Use all available CPU cores
      exec_mode: 'cluster', // Enable cluster mode for load balancing
      
      // Environment variables
      env: {
        NODE_ENV: 'development',
        PORT: 5000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 5000,
      },
      env_staging: {
        NODE_ENV: 'staging',
        PORT: 5001,
      },
      
      // Process management
      watch: false, // Disable in production, enable for development
      ignore_watch: ['node_modules', 'logs', 'uploads'],
      watch_options: {
        followSymlinks: false,
        usePolling: false,
      },
      
      // Restart policies
      max_restarts: 10,
      min_uptime: '10s',
      max_memory_restart: '1G',
      restart_delay: 4000,
      
      // Logging
      log_file: './logs/combined.log',
      out_file: './logs/out.log',
      error_file: './logs/error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      
      // Advanced options
      kill_timeout: 5000,
      listen_timeout: 3000,
      shutdown_with_message: true,
      
      // Health monitoring
      health_check_grace_period: 3000,
      
      // Source map support for better error tracking
      source_map_support: true,
      
      // Graceful shutdown
      kill_retry_time: 100,
      
      // Process title
      name: 'museum-backend-worker',
      
      // Cron restart (optional - restart every day at 2 AM)
      cron_restart: '0 2 * * *',
      
      // Autorestart
      autorestart: true,
      
      // Time zone
      time: true,
    }
  ],
  
  // Deployment configuration
  deploy: {
    production: {
      user: 'deploy',
      host: ['production-server.com'],
      ref: 'origin/main',
      repo: 'git@github.com:username/museum-backend.git',
      path: '/var/www/museum-backend',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env production',
      'pre-setup': 'apt update && apt install git -y'
    },
    staging: {
      user: 'deploy',
      host: ['staging-server.com'],
      ref: 'origin/develop',
      repo: 'git@github.com:username/museum-backend.git',
      path: '/var/www/museum-backend-staging',
      'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env staging',
      'pre-setup': 'apt update && apt install git -y'
    }
  }
};

