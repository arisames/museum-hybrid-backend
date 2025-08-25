const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const mongoose = require("mongoose");
const connectDB = require("./config/db");
const privateMessageRoutes = require("./routes/privateMessageRoutes");
const userProfileRoutes = require("./routes/userProfileRoutes");
const userRoutes = require("./routes/userRoutes");
const { errorHandler, notFound, setupGlobalErrorHandlers } = require("./middleware/errorMiddleware");
const { 
  requestId, 
  requestLogger, 
  performanceMonitor, 
  securityHeaders,
  requestTimeout 
} = require("./middleware/requestMiddleware");
const logger = require("./utils/logger");

dotenv.config();

// Setup global error handlers
setupGlobalErrorHandlers();

connectDB();

const app = express();

// Trust proxy for accurate IP addresses
app.set('trust proxy', 1);

// Request ID middleware (must be first)
app.use(requestId);

// Security headers
app.use(securityHeaders);

// Request timeout (30 seconds)
app.use(requestTimeout(30000));

// Enhanced CORS configuration with environment-based settings
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      "http://localhost:3000", 
      "http://localhost:5173", 
      "http://localhost:4173",
      process.env.FRONTEND_URL,
      process.env.FRONTEND_URL_STAGING,
      process.env.FRONTEND_URL_PRODUCTION,
    ].filter(Boolean);
    
    // In development, allow any localhost origin
    if (process.env.NODE_ENV === 'development') {
      if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
        return callback(null, true);
      }
    }
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.logSecurity('CORS_VIOLATION', {
        origin,
        allowedOrigins,
        userAgent: 'N/A', // Will be filled by request context
        timestamp: new Date().toISOString(),
      });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Request-ID',
    'X-Requested-With',
    'Accept',
    'Origin',
    'Cache-Control',
    'Pragma'
  ],
  exposedHeaders: [
    'X-Request-ID',
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'X-Response-Time'
  ],
  maxAge: 86400, // 24 hours for preflight cache
  optionsSuccessStatus: 200, // For legacy browser support
  preflightContinue: false,
};

app.use(cors(corsOptions));

// Use Helmet for security with comprehensive configuration
app.use(helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-eval'"], // unsafe-eval needed for some dev tools
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", "https:", "wss:"],
      mediaSrc: ["'self'"],
      objectSrc: ["'none'"],
      childSrc: ["'self'"],
      frameSrc: ["'none'"],
      workerSrc: ["'self'"],
      manifestSrc: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
    reportOnly: process.env.NODE_ENV === 'development', // Report-only in development
  },
  
  // HTTP Strict Transport Security
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  
  // X-Frame-Options
  frameguard: {
    action: 'deny'
  },
  
  // X-Content-Type-Options
  noSniff: true,
  
  // X-XSS-Protection
  xssFilter: true,
  
  // Referrer Policy
  referrerPolicy: {
    policy: ['no-referrer', 'strict-origin-when-cross-origin']
  },
  
  // X-Permitted-Cross-Domain-Policies
  permittedCrossDomainPolicies: false,
  
  // X-DNS-Prefetch-Control
  dnsPrefetchControl: {
    allow: false
  },
  
  // Expect-CT
  expectCt: {
    maxAge: 86400, // 24 hours
    enforce: process.env.NODE_ENV === 'production',
    reportUri: process.env.EXPECT_CT_REPORT_URI
  },
  
  // Feature Policy / Permissions Policy
  permissionsPolicy: {
    camera: [],
    microphone: [],
    geolocation: [],
    payment: [],
    usb: [],
    magnetometer: [],
    gyroscope: [],
    accelerometer: [],
    ambient_light_sensor: [],
    autoplay: ['self'],
    encrypted_media: ['self'],
    fullscreen: ['self'],
    picture_in_picture: ['self'],
  },
  
  // Cross-Origin-Embedder-Policy
  crossOriginEmbedderPolicy: process.env.NODE_ENV === 'production',
  
  // Cross-Origin-Opener-Policy
  crossOriginOpenerPolicy: {
    policy: 'same-origin'
  },
  
  // Cross-Origin-Resource-Policy
  crossOriginResourcePolicy: {
    policy: 'cross-origin'
  },
  
  // Hide X-Powered-By header
  hidePoweredBy: true,
}));

// HTTP request logging
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined', {
    stream: { write: (message) => logger.http(message.trim()) }
  }));
} else {
  app.use(morgan('dev'));
}

// Custom request logging and performance monitoring
app.use(requestLogger);
app.use(performanceMonitor);

// Input sanitization middleware (before body parsing)
const { sanitizeAllInputs } = require("./utils/sanitize");
app.use(sanitizeAllInputs);

// Body parser with size limits
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || "1.0.0",
  });
});

// API status endpoint
app.get("/", (req, res) => {
  res.json({
    message: "Museum Collection Platform API",
    version: "1.0.0",
    status: "running",
    timestamp: new Date().toISOString(),
    endpoints: {
      users: "/api/users",
      messages: "/api/messages",
      profile: "/api/profile",
      health: "/health",
    },
  });
});

// API routes
app.use("/api/users", userRoutes);
app.use("/api/messages", privateMessageRoutes);
app.use("/api/profile", userProfileRoutes);

// 404 handler for undefined routes
app.use(notFound);

// Error handling middleware (must be last)
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully`);
  
  server.close(() => {
    logger.info('HTTP server closed');
    
    // Close database connection
    if (mongoose.connection.readyState === 1) {
      mongoose.connection.close(() => {
        logger.info('Database connection closed');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });

  // Force close after 10 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;


