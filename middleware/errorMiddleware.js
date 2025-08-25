const { CustomError } = require("../utils/CustomError");
const logger = require("../utils/logger");

// Async error handler wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Not found middleware
const notFound = (req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  res.status(404);
  next(error);
};

// Main error handler middleware
const errorHandler = (err, req, res, next) => {
  let statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  let message = err.message;
  let errorCode = 'UNKNOWN_ERROR';
  let details = null;

  // Handle custom errors
  if (err instanceof CustomError) {
    statusCode = err.statusCode;
    errorCode = err.errorCode;
    details = err.details;
  }

  // Handle Mongoose errors
  if (err.name === "CastError" && err.kind === "ObjectId") {
    statusCode = 404;
    message = "Resource not found";
    errorCode = "INVALID_OBJECT_ID";
    details = { field: err.path, value: err.value };
  }

  // Handle Mongoose duplicate key errors
  if (err.code === 11000) {
    statusCode = 409;
    message = "Duplicate field value";
    errorCode = "DUPLICATE_FIELD";
    details = { 
      duplicateFields: Object.keys(err.keyValue),
      values: err.keyValue 
    };
  }

  // Handle Mongoose validation errors
  if (err.name === "ValidationError") {
    statusCode = 422;
    message = "Validation failed";
    errorCode = "VALIDATION_ERROR";
    details = Object.values(err.errors).map((error) => ({
      field: error.path,
      message: error.message,
      value: error.value,
    }));
  }

  // Handle JWT errors
  if (err.name === "JsonWebTokenError") {
    statusCode = 401;
    message = "Invalid token";
    errorCode = "INVALID_TOKEN";
  }

  if (err.name === "TokenExpiredError") {
    statusCode = 401;
    message = "Token expired";
    errorCode = "TOKEN_EXPIRED";
  }

  // Handle rate limit errors
  if (err.status === 429) {
    statusCode = 429;
    message = "Too many requests";
    errorCode = "RATE_LIMIT_EXCEEDED";
    details = {
      retryAfter: err.retryAfter,
      limit: err.limit,
      remaining: err.remaining,
    };
  }

  // Handle multer file upload errors
  if (err.code === "LIMIT_FILE_SIZE") {
    statusCode = 413;
    message = "File too large";
    errorCode = "FILE_TOO_LARGE";
    details = { limit: err.limit };
  }

  if (err.code === "LIMIT_UNEXPECTED_FILE") {
    statusCode = 400;
    message = "Unexpected file field";
    errorCode = "UNEXPECTED_FILE";
    details = { field: err.field };
  }

  // Handle database connection errors
  if (err.name === "MongoNetworkError" || err.name === "MongoTimeoutError") {
    statusCode = 503;
    message = "Database connection error";
    errorCode = "DATABASE_CONNECTION_ERROR";
  }

  // Log the error with context
  logger.logError(err, req, {
    statusCode,
    errorCode,
    details,
    userAgent: req.get('User-Agent'),
    referer: req.get('Referer'),
  });

  // Log security-related errors
  if (statusCode === 401 || statusCode === 403) {
    logger.logSecurity('AUTHENTICATION_FAILURE', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method,
    });
  }

  // Prepare error response
  const errorResponse = {
    success: false,
    error: {
      message,
      statusCode,
      errorCode,
      timestamp: new Date().toISOString(),
    },
  };

  // Add details in development or for validation errors
  if (process.env.NODE_ENV !== 'production' || statusCode === 422) {
    errorResponse.error.details = details;
  }

  // Add stack trace in development
  if (process.env.NODE_ENV !== 'production') {
    errorResponse.error.stack = err.stack;
  }

  // Add request ID if available
  if (req.requestId) {
    errorResponse.error.requestId = req.requestId;
  }

  res.status(statusCode).json(errorResponse);
};

// Global error handlers for uncaught exceptions and unhandled rejections
const setupGlobalErrorHandlers = () => {
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
  });

  process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    process.exit(0);
  });

  process.on('SIGINT', () => {
    logger.info('SIGINT received, shutting down gracefully');
    process.exit(0);
  });
};

module.exports = { 
  errorHandler, 
  notFound, 
  asyncHandler,
  setupGlobalErrorHandlers,
};



