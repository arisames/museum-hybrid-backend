
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { asyncHandler } = require("./errorMiddleware");
const { UnauthorizedError, ForbiddenError, AuthenticationError } = require("../utils/CustomError");
const logger = require("../utils/logger");

// JWT token generation utilities
const generateTokens = (userId) => {
  const accessToken = jwt.sign(
    { id: userId },
    process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m',
      issuer: 'museum-platform',
      audience: 'museum-users',
    }
  );

  const refreshToken = jwt.sign(
    { id: userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    { 
      expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d',
      issuer: 'museum-platform',
      audience: 'museum-users',
    }
  );

  return { accessToken, refreshToken };
};

// Verify JWT token
const verifyToken = (token, secret) => {
  try {
    return jwt.verify(token, secret, {
      issuer: 'museum-platform',
      audience: 'museum-users',
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AuthenticationError('Token expired', { code: 'TOKEN_EXPIRED' });
    } else if (error.name === 'JsonWebTokenError') {
      throw new AuthenticationError('Invalid token', { code: 'INVALID_TOKEN' });
    } else {
      throw new AuthenticationError('Token verification failed', { code: 'TOKEN_VERIFICATION_FAILED' });
    }
  }
};

// Main authentication middleware
const protect = asyncHandler(async (req, res, next) => {
  let token;

  // Extract token from Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  }
  // Extract token from cookies (if using cookie-based auth)
  else if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }

  if (!token) {
    logger.logSecurity('MISSING_TOKEN', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new UnauthorizedError("Access denied. No token provided.");
  }

  try {
    // Verify the access token
    const decoded = verifyToken(token, process.env.JWT_SECRET);
    
    // Fetch user from database
    const user = await User.findById(decoded.id).select("-password");
    
    if (!user) {
      logger.logSecurity('USER_NOT_FOUND', {
        userId: decoded.id,
        ip: req.ip,
        requestId: req.requestId,
      });
      throw new UnauthorizedError("User not found");
    }

    // Check if user account is active
    if (user.status === 'inactive' || user.status === 'suspended') {
      logger.logSecurity('INACTIVE_USER_ACCESS', {
        userId: user.id,
        status: user.status,
        ip: req.ip,
        requestId: req.requestId,
      });
      throw new ForbiddenError(`Account is ${user.status}`);
    }

    // Check if user's password was changed after token was issued
    if (user.passwordChangedAt && decoded.iat < user.passwordChangedAt.getTime() / 1000) {
      logger.logSecurity('TOKEN_AFTER_PASSWORD_CHANGE', {
        userId: user.id,
        tokenIat: decoded.iat,
        passwordChangedAt: user.passwordChangedAt,
        requestId: req.requestId,
      });
      throw new UnauthorizedError("Password was changed. Please log in again.");
    }

    // Attach user to request object
    req.user = user;
    req.tokenPayload = decoded;

    // Log successful authentication
    logger.debug('User authenticated successfully', {
      userId: user.id,
      username: user.username,
      role: user.role,
      requestId: req.requestId,
    });

    next();
  } catch (error) {
    logger.logSecurity('AUTHENTICATION_FAILED', {
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw error;
  }
});

// Optional authentication middleware (doesn't throw error if no token)
const optionalAuth = asyncHandler(async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies && req.cookies.accessToken) {
    token = req.cookies.accessToken;
  }

  if (token) {
    try {
      const decoded = verifyToken(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select("-password");
      
      if (user && user.status === 'active') {
        req.user = user;
        req.tokenPayload = decoded;
      }
    } catch (error) {
      // Silently fail for optional auth
      logger.debug('Optional authentication failed', {
        error: error.message,
        requestId: req.requestId,
      });
    }
  }

  next();
});

// Admin role middleware
const admin = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    throw new UnauthorizedError("Authentication required");
  }

  if (req.user.role !== "admin") {
    logger.logSecurity('ADMIN_ACCESS_DENIED', {
      userId: req.user.id,
      role: req.user.role,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new ForbiddenError("Admin access required");
  }

  next();
});

// Moderator or admin role middleware
const moderator = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    throw new UnauthorizedError("Authentication required");
  }

  if (!["admin", "moderator"].includes(req.user.role)) {
    logger.logSecurity('MODERATOR_ACCESS_DENIED', {
      userId: req.user.id,
      role: req.user.role,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new ForbiddenError("Moderator or admin access required");
  }

  next();
});

// Self or admin access middleware (user can access their own data or admin can access any)
const selfOrAdmin = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    throw new UnauthorizedError("Authentication required");
  }

  const targetUserId = req.params.userId || req.params.id;
  
  if (req.user.role === "admin" || req.user.id.toString() === targetUserId) {
    next();
  } else {
    logger.logSecurity('SELF_OR_ADMIN_ACCESS_DENIED', {
      userId: req.user.id,
      targetUserId,
      role: req.user.role,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new ForbiddenError("Access denied. You can only access your own data.");
  }
});

// Refresh token middleware
const refreshToken = asyncHandler(async (req, res, next) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    throw new UnauthorizedError("Refresh token required");
  }

  try {
    // Verify refresh token
    const decoded = verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
    
    if (decoded.type !== 'refresh') {
      throw new AuthenticationError('Invalid token type');
    }

    // Fetch user from database
    const user = await User.findById(decoded.id).select("-password");
    
    if (!user) {
      throw new UnauthorizedError("User not found");
    }

    if (user.status !== 'active') {
      throw new ForbiddenError(`Account is ${user.status}`);
    }

    // Generate new tokens
    const tokens = generateTokens(user.id);

    // Log token refresh
    logger.info('Tokens refreshed successfully', {
      userId: user.id,
      username: user.username,
      ip: req.ip,
      requestId: req.requestId,
    });

    // Attach tokens and user to request
    req.tokens = tokens;
    req.user = user;

    next();
  } catch (error) {
    logger.logSecurity('TOKEN_REFRESH_FAILED', {
      error: error.message,
      ip: req.ip,
      requestId: req.requestId,
    });
    throw error;
  }
});

// Rate limiting for authentication attempts
const authRateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
  const attempts = new Map();

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    
    if (!attempts.has(key)) {
      attempts.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    const userAttempts = attempts.get(key);
    
    if (now > userAttempts.resetTime) {
      attempts.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (userAttempts.count >= maxAttempts) {
      logger.logSecurity('AUTH_RATE_LIMIT_EXCEEDED', {
        ip: req.ip,
        attempts: userAttempts.count,
        url: req.originalUrl,
        requestId: req.requestId,
      });
      throw new ForbiddenError("Too many authentication attempts. Please try again later.");
    }

    userAttempts.count++;
    next();
  };
};

// Session management utilities
const invalidateUserSessions = async (userId) => {
  // In a production environment, you would typically:
  // 1. Store active tokens in Redis or database
  // 2. Mark them as invalid
  // 3. Check token validity in the protect middleware
  
  // For now, we'll update the user's passwordChangedAt to invalidate all tokens
  await User.findByIdAndUpdate(userId, {
    passwordChangedAt: new Date(),
  });

  logger.info('User sessions invalidated', { userId });
};

// Logout middleware
const logout = asyncHandler(async (req, res, next) => {
  // Clear cookies if using cookie-based auth
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  logger.info('User logged out', {
    userId: req.user?.id,
    ip: req.ip,
    requestId: req.requestId,
  });

  next();
});

module.exports = {
  protect,
  optionalAuth,
  admin,
  moderator,
  selfOrAdmin,
  refreshToken,
  authRateLimit,
  generateTokens,
  verifyToken,
  invalidateUserSessions,
  logout,
};


