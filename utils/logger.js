const winston = require("winston");
const path = require("path");

// Define log levels
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define log colors
const logColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(logColors);

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.colorize({ all: true }),
  winston.format.printf(
    (info) => `${info.timestamp} ${info.level}: ${info.message}${info.stack ? '\n' + info.stack : ''}`
  )
);

// Define file format (without colors)
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create transports
const transports = [
  // Console transport
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
    format: logFormat,
  }),
  
  // Error log file
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: fileFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 5,
  }),
  
  // Combined log file
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    format: fileFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 5,
  }),
  
  // HTTP requests log file
  new winston.transports.File({
    filename: path.join(logsDir, 'http.log'),
    level: 'http',
    format: fileFormat,
    maxsize: 5242880, // 5MB
    maxFiles: 3,
  }),
];

// Create logger instance
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
  levels: logLevels,
  format: fileFormat,
  transports,
  exitOnError: false,
});

// Add request logging method
logger.logRequest = (req, res, responseTime) => {
  const message = `${req.method} ${req.originalUrl} ${res.statusCode} - ${responseTime}ms - ${req.ip}`;
  logger.http(message);
};

// Add error logging method with context
logger.logError = (error, req = null, additionalInfo = {}) => {
  const errorInfo = {
    message: error.message,
    stack: error.stack,
    statusCode: error.statusCode || 500,
    errorCode: error.errorCode || 'UNKNOWN_ERROR',
    timestamp: new Date().toISOString(),
    ...additionalInfo,
  };

  if (req) {
    errorInfo.request = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
      params: req.params,
      query: req.query,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };
  }

  logger.error(JSON.stringify(errorInfo, null, 2));
};

// Add performance logging method
logger.logPerformance = (operation, duration, metadata = {}) => {
  const performanceInfo = {
    operation,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString(),
    ...metadata,
  };

  if (duration > 1000) {
    logger.warn(`Slow operation detected: ${JSON.stringify(performanceInfo)}`);
  } else {
    logger.info(`Performance: ${JSON.stringify(performanceInfo)}`);
  }
};

// Add security logging method
logger.logSecurity = (event, details = {}, level = 'warn') => {
  const securityInfo = {
    securityEvent: event,
    timestamp: new Date().toISOString(),
    ...details,
  };

  logger[level](`Security Event: ${JSON.stringify(securityInfo)}`);
};

// Add database logging method
logger.logDatabase = (operation, collection, duration, error = null) => {
  const dbInfo = {
    operation,
    collection,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString(),
  };

  if (error) {
    dbInfo.error = error.message;
    logger.error(`Database Error: ${JSON.stringify(dbInfo)}`);
  } else if (duration > 500) {
    logger.warn(`Slow Database Query: ${JSON.stringify(dbInfo)}`);
  } else {
    logger.debug(`Database Operation: ${JSON.stringify(dbInfo)}`);
  }
};

// Handle uncaught exceptions and unhandled rejections
if (process.env.NODE_ENV === 'production') {
  logger.add(new winston.transports.File({
    filename: path.join(logsDir, 'exceptions.log'),
    handleExceptions: true,
    handleRejections: true,
    format: fileFormat,
  }));
}

module.exports = logger;


