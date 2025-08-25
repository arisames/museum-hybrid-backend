# Museum Collection Platform - Backend Deployment Guide

## 🚀 Production Deployment

### Prerequisites

- **Node.js**: Version 18.x or higher
- **MongoDB**: Version 6.x or higher
- **PM2**: Process manager for Node.js applications
- **Nginx**: (Optional) For load balancing and reverse proxy
- **SSL Certificate**: For HTTPS in production

### Environment Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/museum-team/museum-backend.git
   cd museum-backend
   ```

2. **Install dependencies**:
   ```bash
   npm ci --only=production
   ```

3. **Environment Configuration**:
   ```bash
   cp .env.example .env
   # Edit .env with your production values
   ```

4. **Generate secure JWT secrets**:
   ```bash
   node -e "console.log(\'JWT_SECRET=\' + require(\'crypto\').randomBytes(64).toString(\'hex\'))"
   node -e "console.log(\'JWT_REFRESH_SECRET=\' + require(\'crypto\').randomBytes(64).toString(\'hex\'))"
   ```

### Production Environment Variables

```bash
# Required Production Variables
NODE_ENV=production
PORT=5000
MONGO_URI=mongodb://username:password@host:port/database
JWT_SECRET=your_secure_jwt_secret_here
JWT_REFRESH_SECRET=your_secure_refresh_secret_here
JWT_ACCESS_EXPIRE=15m
JWT_REFRESH_EXPIRE=7d
FRONTEND_URL=https://your-frontend-domain.com
FRONTEND_URL_STAGING=https://staging.your-frontend-domain.com
FRONTEND_URL_PRODUCTION=https://production.your-frontend-domain.com

# Optional Production Variables
LOG_LEVEL=info
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
CORS_ORIGIN=https://your-frontend-domain.com
EXPECT_CT_REPORT_URI=https://your-domain.com/report-ct
```

### Security Checklist

- [x] **Strong JWT Secrets**: Use cryptographically secure random strings (64+ characters)
- [x] **Environment Variables**: Never commit `.env` files to version control
- [x] **Database Security**: Use strong MongoDB credentials and enable authentication
- [x] **HTTPS**: Always use SSL/TLS in production
- [x] **Rate Limiting**: Configure appropriate rate limits for your use case
- [x] **CORS**: Configure CORS to only allow your frontend domain
- [x] **Helmet**: Security headers are automatically configured
- [x] **Input Validation**: All inputs are validated and sanitized
- [x] **Error Handling**: Sensitive information is not exposed in error messages
- [x] **Dependency Audits**: Regularly run `npm audit` and `npm run security-audit`
- [x] **Security Logging**: Monitor security logs for suspicious activities

## 🔧 Process Management with PM2

### Basic PM2 Commands

```bash
# Start the application
npm run pm2:start

# Stop the application
npm run pm2:stop

# Restart the application
npm run pm2:restart

# Reload the application (zero-downtime)
npm run pm2:reload

# View logs
npm run pm2:logs

# Monitor processes
npm run pm2:monit

# Delete the application from PM2
npm run pm2:delete
```

### PM2 Ecosystem Configuration

The `ecosystem.config.js` file provides advanced configuration:

- **Cluster Mode**: Utilizes all CPU cores for maximum performance
- **Auto-restart**: Automatically restarts on crashes
- **Memory Monitoring**: Restarts if memory usage exceeds 1GB
- **Log Management**: Centralized logging with rotation
- **Health Checks**: Built-in health monitoring
- **Graceful Shutdown**: Proper cleanup on process termination
- **Cron Restart**: Optional daily restarts for maintenance

### Environment-Specific Deployment

```bash
# Production deployment
npm run production:start

# Staging deployment
npm run staging:start

# Stop production
npm run production:stop
```

## 🔄 Load Balancing

### Node.js Load Balancer

For simple load balancing without external dependencies:

```bash
# Start the load balancer
npm run load-balancer

# Generate Nginx configuration
npm run nginx-config
```

The load balancer provides:
- **Round-robin** load distribution
- **Health checks** for backend instances
- **Automatic failover** for unhealthy servers
- **Connection tracking** and monitoring
- **Status endpoint** at `/lb-status`

### Nginx Load Balancer (Recommended)

1. **Install Nginx**:
   ```bash
   sudo apt update
   sudo apt install nginx
   ```

2. **Generate configuration**:
   ```bash
   npm run nginx-config > /etc/nginx/sites-available/museum-backend
   ```

3. **Enable the site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/museum-backend /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## 💾 Database Backup & Recovery

### Automated Backups

```bash
# Create a backup
npm run backup

# List available backups
npm run backup:list

# Clean up old backups
npm run backup:cleanup

# Restore from backup
npm run backup:restore <backup-filename>
```

### Backup Configuration

Set these environment variables for backup customization:

```bash
BACKUP_SCHEDULE=0 2 * * *           # Daily at 2 AM
BACKUP_RETENTION_DAYS=30            # Keep backups for 30 days
BACKUP_STORAGE_PATH=./backups       # Backup directory
```

### Backup Features

- **Compressed backups** using gzip
- **Automatic cleanup** based on retention policy
- **Incremental backups** support
- **Restore verification** with integrity checks
- **Remote storage** support (S3, Google Cloud, etc.)

## 📊 Monitoring & Logging

### Health Checks

```bash
# Check application health
npm run health-check

# PM2 monitoring
npm run pm2:monit
```

### Log Management

Logs are automatically managed by Winston and PM2:

- **Application logs**: `./logs/combined.log`
- **Error logs**: `./logs/error.log`
- **PM2 logs**: `./logs/out.log`, `./logs/error.log`

### Log Rotation

PM2 automatically handles log rotation. For custom log rotation:

```bash
# Install PM2 log rotate module
pm2 install pm2-logrotate

# Configure log rotation
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 30
pm2 set pm2-logrotate:compress true
```

## 🔒 Security Best Practices

### Environment Security

1. **Secure Environment Variables**:
   - Use a secrets management system (AWS Secrets Manager, HashiCorp Vault)
   - Never log sensitive environment variables
   - Rotate secrets regularly

2. **Database Security**:
   - Enable MongoDB authentication
   - Use connection string with credentials
   - Configure network access restrictions
   - Enable audit logging

3. **Application Security**:
   - Keep dependencies updated: `npm run deps-update`
   - Run security audits: `npm run security-audit`
   - Use HTTPS in production
   - Configure proper CORS policies

### Network Security

1. **Firewall Configuration**:
   ```bash
   # Allow only necessary ports
   sudo ufw allow 22    # SSH
   sudo ufw allow 80    # HTTP
   sudo ufw allow 443   # HTTPS
   sudo ufw enable
   ```

2. **Reverse Proxy**:
   - Use Nginx or similar for SSL termination
   - Hide backend server details
   - Implement rate limiting at proxy level

## 🚀 Deployment Strategies

### Blue-Green Deployment

1. **Setup two identical environments** (blue and green)
2. **Deploy to inactive environment** (e.g., green)
3. **Test the new deployment** thoroughly
4. **Switch traffic** from blue to green
5. **Keep blue as rollback** option

### Rolling Deployment

1. **Deploy to one instance** at a time
2. **Health check** each instance
3. **Continue to next instance** if healthy
4. **Automatic rollback** on failure

### Canary Deployment

1. **Deploy to small subset** of servers
2. **Monitor metrics** and error rates
3. **Gradually increase** traffic to new version
4. **Full rollout** if metrics are good

## 📋 Deployment Checklist

### Pre-Deployment

- [x] Code review completed
- [x] Tests passing
- [x] Security audit passed
- [x] Environment variables configured
- [x] Database migrations ready
- [x] Backup created

### Deployment

- [x] Application deployed
- [x] Health checks passing
- [x] Logs are clean
- [x] Performance metrics normal
- [x] SSL certificate valid
- [x] Load balancer configured

### Post-Deployment

- [x] Smoke tests completed
- [x] Monitoring alerts configured
- [x] Documentation updated
- [x] Team notified
- [x] Rollback plan ready

## 🆘 Troubleshooting

### Common Issues

1. **Application won't start**:
   - Check environment variables
   - Verify database connectivity
   - Review application logs

2. **High memory usage**:
   - Check for memory leaks
   - Adjust PM2 memory limits
   - Monitor database queries

3. **Slow response times**:
   - Check database indexes
   - Review rate limiting settings
   - Monitor server resources

4. **Database connection errors**:
   - Verify MongoDB is running
   - Check connection string
   - Review network connectivity

### Log Analysis

```bash
# View real-time logs
pm2 logs --lines 100

# Search for errors
grep -i error logs/combined.log

# Monitor specific process
pm2 logs museum-backend --lines 50
```

### Performance Monitoring

```bash
# Check system resources
htop
iostat -x 1
free -h

# Monitor database
mongo --eval "db.stats()"
mongo --eval "db.runCommand({serverStatus: 1})"
```

## 📞 Support

For deployment issues or questions:

- **Documentation**: Check this guide and README.md
- **Logs**: Review application and PM2 logs
- **Health Check**: Use `/health` endpoint
- **Monitoring**: Check PM2 monitoring dashboard

---

**Note**: This deployment guide assumes a Linux-based production environment. Adjust commands and paths as needed for your specific setup.

**Last Updated**: August 2025
**Version**: 1.0

## 🔧 Process Management with PM2

### Basic PM2 Commands

```bash
# Start the application
npm run pm2:start

# Stop the application
npm run pm2:stop

# Restart the application
npm run pm2:restart

# Reload the application (zero-downtime)
npm run pm2:reload

# View logs
npm run pm2:logs

# Monitor processes
npm run pm2:monit

# Delete the application from PM2
npm run pm2:delete
```

### PM2 Ecosystem Configuration

The `ecosystem.config.js` file provides advanced configuration:

- **Cluster Mode**: Utilizes all CPU cores for maximum performance
- **Auto-restart**: Automatically restarts on crashes
- **Memory Monitoring**: Restarts if memory usage exceeds 1GB
- **Log Management**: Centralized logging with rotation
- **Health Checks**: Built-in health monitoring
- **Graceful Shutdown**: Proper cleanup on process termination

### Environment-Specific Deployment

```bash
# Production deployment
npm run production:start

# Staging deployment
npm run staging:start

# Stop production
npm run production:stop
```

## 🔄 Load Balancing

### Node.js Load Balancer

For simple load balancing without external dependencies:

```bash
# Start the load balancer
npm run load-balancer

# Generate Nginx configuration
npm run nginx-config
```

The load balancer provides:
- **Round-robin** load distribution
- **Health checks** for backend instances
- **Automatic failover** for unhealthy servers
- **Connection tracking** and monitoring
- **Status endpoint** at `/lb-status`

### Nginx Load Balancer (Recommended)

1. **Install Nginx**:
   ```bash
   sudo apt update
   sudo apt install nginx
   ```

2. **Generate configuration**:
   ```bash
   npm run nginx-config > /etc/nginx/sites-available/museum-backend
   ```

3. **Enable the site**:
   ```bash
   sudo ln -s /etc/nginx/sites-available/museum-backend /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## 💾 Database Backup & Recovery

### Automated Backups

```bash
# Create a backup
npm run backup

# List available backups
npm run backup:list

# Clean up old backups
npm run backup:cleanup

# Restore from backup
npm run backup:restore <backup-filename>
```

### Backup Configuration

Set these environment variables for backup customization:

```bash
BACKUP_SCHEDULE=0 2 * * *           # Daily at 2 AM
BACKUP_RETENTION_DAYS=30            # Keep backups for 30 days
BACKUP_STORAGE_PATH=./backups       # Backup directory
```

### Backup Features

- **Compressed backups** using gzip
- **Automatic cleanup** based on retention policy
- **Incremental backups** support
- **Restore verification** with integrity checks
- **Remote storage** support (S3, Google Cloud, etc.)

## 📊 Monitoring & Logging

### Health Checks

```bash
# Check application health
npm run health-check

# PM2 monitoring
npm run pm2:monit
```

### Log Management

Logs are automatically managed by Winston and PM2:

- **Application logs**: `./logs/combined.log`
- **Error logs**: `./logs/error.log`
- **PM2 logs**: `./logs/out.log`, `./logs/error.log`

### Log Rotation

PM2 automatically handles log rotation. For custom log rotation:

```bash
# Install PM2 log rotate module
pm2 install pm2-logrotate

# Configure log rotation
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 30
pm2 set pm2-logrotate:compress true
```

## 🔒 Security Best Practices

### Environment Security

1. **Secure Environment Variables**:
   - Use a secrets management system (AWS Secrets Manager, HashiCorp Vault)
   - Never log sensitive environment variables
   - Rotate secrets regularly

2. **Database Security**:
   - Enable MongoDB authentication
   - Use connection string with credentials
   - Configure network access restrictions
   - Enable audit logging

3. **Application Security**:
   - Keep dependencies updated: `npm run deps-update`
   - Run security audits: `npm run security-audit`
   - Use HTTPS in production
   - Configure proper CORS policies

### Network Security

1. **Firewall Configuration**:
   ```bash
   # Allow only necessary ports
   sudo ufw allow 22    # SSH
   sudo ufw allow 80    # HTTP
   sudo ufw allow 443   # HTTPS
   sudo ufw enable
   ```

2. **Reverse Proxy**:
   - Use Nginx or similar for SSL termination
   - Hide backend server details
   - Implement rate limiting at proxy level

## 🚀 Deployment Strategies

### Blue-Green Deployment

1. **Setup two identical environments** (blue and green)
2. **Deploy to inactive environment** (e.g., green)
3. **Test the new deployment** thoroughly
4. **Switch traffic** from blue to green
5. **Keep blue as rollback** option

### Rolling Deployment

1. **Deploy to one instance** at a time
2. **Health check** each instance
3. **Continue to next instance** if healthy
4. **Automatic rollback** on failure

### Canary Deployment

1. **Deploy to small subset** of servers
2. **Monitor metrics** and error rates
3. **Gradually increase** traffic to new version
4. **Full rollout** if metrics are good

## 📋 Deployment Checklist

### Pre-Deployment

- [ ] Code review completed
- [ ] Tests passing
- [ ] Security audit passed
- [ ] Environment variables configured
- [ ] Database migrations ready
- [ ] Backup created

### Deployment

- [ ] Application deployed
- [ ] Health checks passing
- [ ] Logs are clean
- [ ] Performance metrics normal
- [ ] SSL certificate valid
- [ ] Load balancer configured

### Post-Deployment

- [ ] Smoke tests completed
- [ ] Monitoring alerts configured
- [ ] Documentation updated
- [ ] Team notified
- [ ] Rollback plan ready

## 🆘 Troubleshooting

### Common Issues

1. **Application won't start**:
   - Check environment variables
   - Verify database connectivity
   - Review application logs

2. **High memory usage**:
   - Check for memory leaks
   - Adjust PM2 memory limits
   - Monitor database queries

3. **Slow response times**:
   - Check database indexes
   - Review rate limiting settings
   - Monitor server resources

4. **Database connection errors**:
   - Verify MongoDB is running
   - Check connection string
   - Review network connectivity

### Log Analysis

```bash
# View real-time logs
pm2 logs --lines 100

# Search for errors
grep -i error logs/combined.log

# Monitor specific process
pm2 logs museum-backend --lines 50
```

### Performance Monitoring

```bash
# Check system resources
htop
iostat -x 1
free -h

# Monitor database
mongo --eval "db.stats()"
mongo --eval "db.runCommand({serverStatus: 1})"
```

## 📞 Support

For deployment issues or questions:

- **Documentation**: Check this guide and README.md
- **Logs**: Review application and PM2 logs
- **Health Check**: Use `/health` endpoint
- **Monitoring**: Check PM2 monitoring dashboard

---

**Note**: This deployment guide assumes a Linux-based production environment. Adjust commands and paths as needed for your specific setup.

