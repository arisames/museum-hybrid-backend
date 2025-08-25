const rateLimit = require('express-rate-limit');
const { RateLimitError, TooManyRequestsError } = require('../utils/CustomError');
const logger = require('../utils/logger');

// Store for tracking failed login attempts per IP
const loginAttempts = new Map();

// Clean up old entries every hour
setInterval(() => {
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  for (const [ip, data] of loginAttempts.entries()) {
    if (data.lastAttempt < oneHourAgo) {
      loginAttempts.delete(ip);
    }
  }
}, 60 * 60 * 1000);

// Custom rate limit handler
const rateLimitHandler = (req, res, next) => {
  const error = new RateLimitError('Too many requests, please try again later', {
    retryAfter: Math.round(req.rateLimit.resetTime / 1000),
    limit: req.rateLimit.limit,
    remaining: req.rateLimit.remaining,
  });

  // Log rate limit violation
  logger.logSecurity('RATE_LIMIT_EXCEEDED', {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    endpoint: req.originalUrl,
    method: req.method,
    limit: req.rateLimit.limit,
    remaining: req.rateLimit.remaining,
    resetTime: new Date(req.rateLimit.resetTime),
    requestId: req.requestId,
  });

  throw error;
};

// Skip successful requests for certain endpoints
const skipSuccessfulRequests = (req, res) => {
  return res.statusCode < 400;
};

// General API rate limiting
const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: rateLimitHandler,
  skip: (req) => {
    // Skip rate limiting for health checks and static assets
    return req.path === '/health' || req.path.startsWith('/static/');
  }
});

// Strict rate limiting for authentication endpoints (enhanced version of loginLimiter)
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login attempts per windowMs
  message: {
    error: 'Too many login attempts from this IP, please try again later',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  skipSuccessfulRequests: true, // Don't count successful requests
});

// Legacy loginLimiter for backward compatibility
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 login attempts per 15 minutes per IP
  message: new TooManyRequestsError("Too many login attempts from this IP, please try again after 15 minutes"),
  handler: (req, res, next, options) => {
    res.status(options.statusCode).json(options.message);
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// More restrictive rate limiting for password reset
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 password reset attempts per hour
  message: {
    error: 'Too many password reset attempts from this IP, please try again later',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

// Rate limiting for user registration
const registrationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 registration attempts per hour
  message: {
    error: 'Too many registration attempts from this IP, please try again later',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

// Rate limiting for message sending
const messageRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Limit each IP to 10 messages per minute
  message: {
    error: 'Too many messages sent, please slow down',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  skipSuccessfulRequests: false,
});

// Rate limiting for search endpoints
const searchRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Limit each IP to 30 search requests per minute
  message: {
    error: 'Too many search requests, please slow down',
    retryAfter: '1 minute'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
  skipSuccessfulRequests: true,
});

// Rate limiting for file uploads
const uploadRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit each IP to 20 uploads per hour
  message: {
    error: 'Too many file uploads, please try again later',
    retryAfter: '1 hour'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: rateLimitHandler,
});

// Advanced login attempt tracking with progressive delays
const trackLoginAttempt = (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  
  if (!loginAttempts.has(ip)) {
    loginAttempts.set(ip, {
      count: 0,
      lastAttempt: now,
      lockedUntil: null
    });
  }
  
  const attempts = loginAttempts.get(ip);
  
  // Check if IP is currently locked
  if (attempts.lockedUntil && now < attempts.lockedUntil) {
    const remainingTime = Math.ceil((attempts.lockedUntil - now) / 1000);
    
    logger.logSecurity('LOGIN_ATTEMPT_BLOCKED', {
      ip,
      userAgent: req.get('User-Agent'),
      attemptCount: attempts.count,
      lockedUntil: new Date(attempts.lockedUntil),
      remainingTime,
      requestId: req.requestId,
    });
    
    const error = new RateLimitError(`IP temporarily locked due to too many failed login attempts. Try again in ${remainingTime} seconds.`, {
      retryAfter: remainingTime,
      attemptCount: attempts.count,
    });
    
    return next(error);
  }
  
  // Reset lock if expired
  if (attempts.lockedUntil && now >= attempts.lockedUntil) {
    attempts.count = 0;
    attempts.lockedUntil = null;
  }
  
  // Store original end function to intercept response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    // Check if login failed (status 401 or validation error)
    if (res.statusCode === 401 || (res.statusCode === 400 && req.body.email)) {
      attempts.count++;
      attempts.lastAttempt = now;
      
      // Progressive locking: 5 attempts = 5 min, 10 = 15 min, 15 = 30 min, 20+ = 1 hour
      if (attempts.count >= 20) {
        attempts.lockedUntil = now + 60 * 60 * 1000; // 1 hour
      } else if (attempts.count >= 15) {
        attempts.lockedUntil = now + 30 * 60 * 1000; // 30 minutes
      } else if (attempts.count >= 10) {
        attempts.lockedUntil = now + 15 * 60 * 1000; // 15 minutes
      } else if (attempts.count >= 5) {
        attempts.lockedUntil = now + 5 * 60 * 1000; // 5 minutes
      }
      
      logger.logSecurity('FAILED_LOGIN_ATTEMPT', {
        ip,
        userAgent: req.get('User-Agent'),
        email: req.body.email,
        attemptCount: attempts.count,
        lockedUntil: attempts.lockedUntil ? new Date(attempts.lockedUntil) : null,
        requestId: req.requestId,
      });
    } else if (res.statusCode === 200 && req.body.email) {
      // Successful login - reset attempts
      if (attempts.count > 0) {
        logger.logSecurity('LOGIN_ATTEMPTS_RESET', {
          ip,
          userAgent: req.get('User-Agent'),
          email: req.body.email,
          previousAttemptCount: attempts.count,
          requestId: req.requestId,
        });
      }
      
      attempts.count = 0;
      attempts.lockedUntil = null;
    }
    
    // Call original end function
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

// Middleware to add rate limit info to response headers
const addRateLimitHeaders = (req, res, next) => {
  // Add custom headers for client-side rate limit handling
  res.setHeader('X-RateLimit-Policy', 'dynamic');
  res.setHeader('X-RateLimit-Endpoint', req.route?.path || req.path);
  
  next();
};

// Create a rate limiter based on user role
const createRoleBasedRateLimit = (limits) => {
  return (req, res, next) => {
    const userRole = req.user?.role || 'anonymous';
    const limit = limits[userRole] || limits.default || limits.anonymous;
    
    if (!limit) {
      return next();
    }
    
    const rateLimiter = rateLimit({
      windowMs: limit.windowMs,
      max: limit.max,
      message: {
        error: `Rate limit exceeded for ${userRole} role`,
        retryAfter: Math.ceil(limit.windowMs / 1000) + ' seconds'
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: rateLimitHandler,
      keyGenerator: (req) => {
        // Use user ID if authenticated, otherwise fall back to IP
        return req.user?.id || req.ip;
      }
    });
    
    rateLimiter(req, res, next);
  };
};

// Admin endpoints rate limiting (more permissive for admins)
const adminRateLimit = createRoleBasedRateLimit({
  superadmin: { windowMs: 60 * 1000, max: 200 }, // 200 requests per minute
  admin: { windowMs: 60 * 1000, max: 100 }, // 100 requests per minute
  moderator: { windowMs: 60 * 1000, max: 50 }, // 50 requests per minute
  default: { windowMs: 60 * 1000, max: 20 } // 20 requests per minute for others
});

// API endpoints rate limiting based on user role
const apiRateLimit = createRoleBasedRateLimit({
  superadmin: { windowMs: 60 * 1000, max: 1000 }, // 1000 requests per minute
  admin: { windowMs: 60 * 1000, max: 500 }, // 500 requests per minute
  moderator: { windowMs: 60 * 1000, max: 200 }, // 200 requests per minute
  user: { windowMs: 60 * 1000, max: 100 }, // 100 requests per minute
  anonymous: { windowMs: 60 * 1000, max: 20 } // 20 requests per minute
});

module.exports = {
  // Legacy export for backward compatibility
  loginLimiter,
  
  // Enhanced rate limiters
  generalRateLimit,
  authRateLimit,
  passwordResetRateLimit,
  registrationRateLimit,
  messageRateLimit,
  searchRateLimit,
  uploadRateLimit,
  trackLoginAttempt,
  addRateLimitHeaders,
  createRoleBasedRateLimit,
  adminRateLimit,
  apiRateLimit,
  
  // Utility functions
  getLoginAttempts: (ip) => loginAttempts.get(ip),
  clearLoginAttempts: (ip) => loginAttempts.delete(ip),
  getLoginAttemptsStats: () => ({
    totalIPs: loginAttempts.size,
    lockedIPs: Array.from(loginAttempts.values()).filter(a => a.lockedUntil && a.lockedUntil > Date.now()).length
  })
};


