const logger = require("../utils/logger");
const { v4: uuidv4 } = require('uuid');

// Request ID middleware
const requestId = (req, res, next) => {
  req.requestId = uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  
  // Log request start
  logger.info(`${req.method} ${req.originalUrl} - Request started`, {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer'),
  });

  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const responseTime = Date.now() - startTime;
    
    // Log request completion
    logger.logRequest(req, res, responseTime);
    
    // Log slow requests
    if (responseTime > 1000) {
      logger.warn(`Slow request detected: ${req.method} ${req.originalUrl} - ${responseTime}ms`, {
        requestId: req.requestId,
        responseTime,
        statusCode: res.statusCode,
      });
    }

    originalEnd.call(this, chunk, encoding);
  };

  next();
};

// Performance monitoring middleware
const performanceMonitor = (req, res, next) => {
  const startTime = process.hrtime.bigint();
  
  res.on('finish', () => {
    const endTime = process.hrtime.bigint();
    const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    
    logger.logPerformance(`${req.method} ${req.originalUrl}`, duration, {
      requestId: req.requestId,
      statusCode: res.statusCode,
      contentLength: res.get('Content-Length'),
    });
  });

  next();
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Add HSTS header in production
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  next();
};

// Request size limiter
const requestSizeLimiter = (limit = '10mb') => {
  return (req, res, next) => {
    const contentLength = parseInt(req.get('Content-Length') || '0');
    const maxSize = parseSize(limit);
    
    if (contentLength > maxSize) {
      const error = new Error('Request entity too large');
      error.status = 413;
      error.code = 'REQUEST_TOO_LARGE';
      return next(error);
    }
    
    next();
  };
};

// Helper function to parse size strings
const parseSize = (size) => {
  if (typeof size === 'number') return size;
  
  const units = {
    b: 1,
    kb: 1024,
    mb: 1024 * 1024,
    gb: 1024 * 1024 * 1024,
  };
  
  const match = size.toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/);
  if (!match) return 0;
  
  const value = parseFloat(match[1]);
  const unit = match[2] || 'b';
  
  return value * units[unit];
};

// Request timeout middleware
const requestTimeout = (timeout = 30000) => {
  return (req, res, next) => {
    const timer = setTimeout(() => {
      if (!res.headersSent) {
        const error = new Error('Request timeout');
        error.status = 408;
        error.code = 'REQUEST_TIMEOUT';
        next(error);
      }
    }, timeout);

    res.on('finish', () => {
      clearTimeout(timer);
    });

    res.on('close', () => {
      clearTimeout(timer);
    });

    next();
  };
};

// IP whitelist middleware
const ipWhitelist = (allowedIPs = []) => {
  return (req, res, next) => {
    if (allowedIPs.length === 0) {
      return next(); // No restrictions if no IPs specified
    }

    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (!allowedIPs.includes(clientIP)) {
      logger.logSecurity('IP_BLOCKED', {
        ip: clientIP,
        url: req.originalUrl,
        method: req.method,
        userAgent: req.get('User-Agent'),
      });
      
      const error = new Error('Access denied');
      error.status = 403;
      error.code = 'IP_BLOCKED';
      return next(error);
    }

    next();
  };
};

// User agent validation middleware
const userAgentValidation = (blockedPatterns = []) => {
  return (req, res, next) => {
    const userAgent = req.get('User-Agent') || '';
    
    for (const pattern of blockedPatterns) {
      if (userAgent.match(pattern)) {
        logger.logSecurity('USER_AGENT_BLOCKED', {
          userAgent,
          ip: req.ip,
          url: req.originalUrl,
          method: req.method,
        });
        
        const error = new Error('Access denied');
        error.status = 403;
        error.code = 'USER_AGENT_BLOCKED';
        return next(error);
      }
    }

    next();
  };
};

module.exports = {
  requestId,
  requestLogger,
  performanceMonitor,
  securityHeaders,
  requestSizeLimiter,
  requestTimeout,
  ipWhitelist,
  userAgentValidation,
};

