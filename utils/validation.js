const Joi = require('joi');
const { body, query, param, validationResult } = require('express-validator');
const validator = require('validator');
const xss = require('xss');
const { ValidationError } = require('./CustomError');

// Custom Joi extensions
const customJoi = Joi.extend((joi) => ({
  type: 'string',
  base: joi.string(),
  messages: {
    'string.mongoId': '{{#label}} must be a valid MongoDB ObjectId',
    'string.strongPassword': '{{#label}} must contain at least 8 characters, including uppercase, lowercase, number, and special character',
  },
  rules: {
    mongoId: {
      validate(value, helpers) {
        if (!validator.isMongoId(value)) {
          return helpers.error('string.mongoId');
        }
        return value;
      },
    },
    strongPassword: {
      validate(value, helpers) {
        const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!strongPasswordRegex.test(value)) {
          return helpers.error('string.strongPassword');
        }
        return value;
      },
    },
  },
}));

// Common validation schemas
const commonSchemas = {
  // MongoDB ObjectId validation
  mongoId: customJoi.string().mongoId().required(),
  
  // Email validation
  email: customJoi.string().email().lowercase().trim().required(),
  
  // Password validation
  password: customJoi.string().strongPassword().required(),
  
  // Username validation
  username: customJoi.string()
    .alphanum()
    .min(3)
    .max(30)
    .lowercase()
    .trim()
    .required(),
  
  // Text content validation
  text: customJoi.string().trim().min(1).max(1000),
  
  // URL validation
  url: customJoi.string().uri().trim(),
  
  // Phone number validation
  phone: customJoi.string().pattern(/^\+?[1-9]\d{1,14}$/),
  
  // Date validation
  date: customJoi.date().iso(),
  
  // Pagination validation
  pagination: {
    page: customJoi.number().integer().min(1).default(1),
    limit: customJoi.number().integer().min(1).max(100).default(10),
    sort: customJoi.string().valid('asc', 'desc').default('desc'),
    sortBy: customJoi.string().default('createdAt'),
  },
};

// User validation schemas
const userSchemas = {
  register: customJoi.object({
    username: commonSchemas.username,
    email: commonSchemas.email,
    password: commonSchemas.password,
    firstName: customJoi.string().trim().min(1).max(50).required(),
    lastName: customJoi.string().trim().min(1).max(50).required(),
    role: customJoi.string().valid('user', 'admin', 'moderator').default('user'),
  }),
  
  login: customJoi.object({
    email: commonSchemas.email,
    password: customJoi.string().required(),
  }),
  
  updateProfile: customJoi.object({
    firstName: customJoi.string().trim().min(1).max(50),
    lastName: customJoi.string().trim().min(1).max(50),
    bio: customJoi.string().trim().max(500),
    location: customJoi.string().trim().max(100),
    website: commonSchemas.url,
    avatar: commonSchemas.url,
  }),
  
  changePassword: customJoi.object({
    currentPassword: customJoi.string().required(),
    newPassword: commonSchemas.password,
    confirmPassword: customJoi.string().valid(customJoi.ref('newPassword')).required(),
  }),
  
  search: customJoi.object({
    q: customJoi.string().trim().min(1).max(100).required(),
    ...commonSchemas.pagination,
  }),
};

// Message validation schemas
const messageSchemas = {
  create: customJoi.object({
    recipientId: commonSchemas.mongoId,
    subject: customJoi.string().trim().min(1).max(200).required(),
    content: customJoi.string().trim().min(1).max(5000).required(),
    priority: customJoi.string().valid('low', 'normal', 'high').default('normal'),
    attachments: customJoi.array().items(customJoi.object({
      filename: customJoi.string().required(),
      url: commonSchemas.url.required(),
      size: customJoi.number().integer().min(0).max(10485760), // 10MB
      mimeType: customJoi.string().required(),
    })).max(5),
  }),
  
  update: customJoi.object({
    subject: customJoi.string().trim().min(1).max(200),
    content: customJoi.string().trim().min(1).max(5000),
    priority: customJoi.string().valid('low', 'normal', 'high'),
    isRead: customJoi.boolean(),
    isArchived: customJoi.boolean(),
  }),
  
  list: customJoi.object({
    status: customJoi.string().valid('all', 'unread', 'read', 'archived').default('all'),
    priority: customJoi.string().valid('low', 'normal', 'high'),
    search: customJoi.string().trim().max(100),
    ...commonSchemas.pagination,
  }),
};

// Profile validation schemas
const profileSchemas = {
  update: customJoi.object({
    bio: customJoi.string().trim().max(1000),
    location: customJoi.string().trim().max(100),
    website: commonSchemas.url,
    socialLinks: customJoi.object({
      twitter: commonSchemas.url,
      linkedin: commonSchemas.url,
      github: commonSchemas.url,
      facebook: commonSchemas.url,
    }),
    preferences: customJoi.object({
      emailNotifications: customJoi.boolean().default(true),
      pushNotifications: customJoi.boolean().default(true),
      theme: customJoi.string().valid('light', 'dark', 'auto').default('auto'),
      language: customJoi.string().valid('en', 'es', 'fr', 'de').default('en'),
    }),
    privacy: customJoi.object({
      profileVisibility: customJoi.string().valid('public', 'private', 'friends').default('public'),
      showEmail: customJoi.boolean().default(false),
      showLocation: customJoi.boolean().default(true),
    }),
  }),
};

// Validation middleware factory
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const data = req[source];
    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true,
      convert: true,
    });

    if (error) {
      const details = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value,
      }));

      return next(new ValidationError('Validation failed', details));
    }

    // Replace the original data with validated and sanitized data
    req[source] = value;
    next();
  };
};

// Express-validator middleware for complex validations
const expressValidators = {
  // User registration validation
  userRegister: [
    body('username')
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be between 3 and 30 characters')
      .isAlphanumeric()
      .withMessage('Username must contain only letters and numbers')
      .toLowerCase()
      .trim(),
    
    body('email')
      .isEmail()
      .withMessage('Must be a valid email address')
      .normalizeEmail()
      .toLowerCase(),
    
    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('Password must contain uppercase, lowercase, number, and special character'),
    
    body('firstName')
      .isLength({ min: 1, max: 50 })
      .withMessage('First name must be between 1 and 50 characters')
      .trim()
      .escape(),
    
    body('lastName')
      .isLength({ min: 1, max: 50 })
      .withMessage('Last name must be between 1 and 50 characters')
      .trim()
      .escape(),
  ],

  // Message creation validation
  messageCreate: [
    body('recipientId')
      .isMongoId()
      .withMessage('Recipient ID must be a valid MongoDB ObjectId'),
    
    body('subject')
      .isLength({ min: 1, max: 200 })
      .withMessage('Subject must be between 1 and 200 characters')
      .trim()
      .escape(),
    
    body('content')
      .isLength({ min: 1, max: 5000 })
      .withMessage('Content must be between 1 and 5000 characters')
      .trim(),
    
    body('priority')
      .optional()
      .isIn(['low', 'normal', 'high'])
      .withMessage('Priority must be low, normal, or high'),
  ],

  // Query parameter validation
  pagination: [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer')
      .toInt(),
    
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100')
      .toInt(),
    
    query('sort')
      .optional()
      .isIn(['asc', 'desc'])
      .withMessage('Sort must be asc or desc'),
    
    query('search')
      .optional()
      .isLength({ max: 100 })
      .withMessage('Search query must be less than 100 characters')
      .trim()
      .escape(),
  ],

  // MongoDB ObjectId parameter validation
  mongoIdParam: (paramName = 'id') => [
    param(paramName)
      .isMongoId()
      .withMessage(`${paramName} must be a valid MongoDB ObjectId`),
  ],
};

// Validation result handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const details = errors.array().map(error => ({
      field: error.param,
      message: error.msg,
      value: error.value,
      location: error.location,
    }));

    return next(new ValidationError('Validation failed', details));
  }
  
  next();
};

// Input sanitization utilities
const sanitize = {
  // HTML sanitization to prevent XSS
  html: (input) => {
    if (typeof input !== 'string') return input;
    return xss(input, {
      whiteList: {
        p: [],
        br: [],
        strong: [],
        em: [],
        u: [],
        ol: [],
        ul: [],
        li: [],
        blockquote: [],
        h1: [],
        h2: [],
        h3: [],
        h4: [],
        h5: [],
        h6: [],
      },
      stripIgnoreTag: true,
      stripIgnoreTagBody: ['script'],
    });
  },

  // Text sanitization for plain text fields
  text: (input) => {
    if (typeof input !== 'string') return input;
    return validator.escape(input.trim());
  },

  // Email sanitization
  email: (input) => {
    if (typeof input !== 'string') return input;
    return validator.normalizeEmail(input.toLowerCase().trim());
  },

  // URL sanitization
  url: (input) => {
    if (typeof input !== 'string') return input;
    const trimmed = input.trim();
    return validator.isURL(trimmed) ? trimmed : '';
  },

  // Phone number sanitization
  phone: (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[^\d+]/g, '');
  },

  // Remove SQL injection patterns
  sql: (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[';\\x00\\n\\r\\x1a"]/g, '');
  },

  // Remove NoSQL injection patterns
  nosql: (obj) => {
    if (typeof obj !== 'object' || obj === null) return obj;
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      // Remove keys that start with $ (MongoDB operators)
      if (key.startsWith('$')) continue;
      
      if (typeof value === 'object' && value !== null) {
        sanitized[key] = sanitize.nosql(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  },
};

// Sanitization middleware
const sanitizeInput = (req, res, next) => {
  // Sanitize body
  if (req.body && typeof req.body === 'object') {
    req.body = sanitize.nosql(req.body);
  }

  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    req.query = sanitize.nosql(req.query);
  }

  // Sanitize URL parameters
  if (req.params && typeof req.params === 'object') {
    req.params = sanitize.nosql(req.params);
  }

  next();
};

// File upload validation
const validateFileUpload = (options = {}) => {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB
    allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'],
    maxFiles = 5,
  } = options;

  return (req, res, next) => {
    if (!req.files || req.files.length === 0) {
      return next();
    }

    if (req.files.length > maxFiles) {
      return next(new ValidationError(`Maximum ${maxFiles} files allowed`));
    }

    for (const file of req.files) {
      if (file.size > maxSize) {
        return next(new ValidationError(`File ${file.originalname} exceeds maximum size of ${maxSize} bytes`));
      }

      if (!allowedMimeTypes.includes(file.mimetype)) {
        return next(new ValidationError(`File ${file.originalname} has unsupported type ${file.mimetype}`));
      }
    }

    next();
  };
};

module.exports = {
  // Joi schemas
  commonSchemas,
  userSchemas,
  messageSchemas,
  profileSchemas,
  
  // Validation middleware
  validate,
  expressValidators,
  handleValidationErrors,
  
  // Sanitization utilities
  sanitize,
  sanitizeInput,
  
  // File validation
  validateFileUpload,
  
  // Custom Joi instance
  customJoi,
};

