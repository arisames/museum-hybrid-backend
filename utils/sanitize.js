const DOMPurify = require("dompurify");
const { JSDOM } = require("jsdom");
const validator = require('validator');
const xss = require('xss');

const window = new JSDOM("").window;
const purify = DOMPurify(window);

/**
 * Sanitize HTML content to prevent XSS attacks
 * @param {string} dirty - The potentially unsafe HTML string
 * @param {object} options - Sanitization options
 * @returns {string} - The sanitized HTML string
 */
const sanitizeHtml = (dirty, options = {}) => {
  if (typeof dirty !== "string") {
    return "";
  }
  
  const defaultOptions = {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "u", "br", "p", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "blockquote"],
    ALLOWED_ATTR: [],
    KEEP_CONTENT: true,
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
    FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover'],
  };
  
  const config = { ...defaultOptions, ...options };
  return purify.sanitize(dirty, config);
};

/**
 * Sanitize plain text input by removing HTML tags and trimming whitespace
 * @param {string} input - The input string to sanitize
 * @returns {string} - The sanitized string
 */
const sanitizeText = (input) => {
  if (typeof input !== "string") {
    return "";
  }
  const withoutHtml = purify.sanitize(input, { ALLOWED_TAGS: [], KEEP_CONTENT: true });
  return withoutHtml.trim().replace(/\s+/g, " ");
};

/**
 * Sanitize email addresses
 * @param {string} email - The email to sanitize
 * @returns {string} - The sanitized email
 */
const sanitizeEmail = (email) => {
  if (typeof email !== 'string') return '';
  const normalized = validator.normalizeEmail(email.toLowerCase().trim());
  return normalized || '';
};

/**
 * Sanitize URLs
 * @param {string} url - The URL to sanitize
 * @returns {string} - The sanitized URL
 */
const sanitizeUrl = (url) => {
  if (typeof url !== 'string') return '';
  const trimmed = url.trim();
  
  // Add protocol if missing
  if (trimmed && !trimmed.match(/^https?:\/\//)) {
    const withProtocol = `https://${trimmed}`;
    return validator.isURL(withProtocol) ? withProtocol : '';
  }
  
  return validator.isURL(trimmed) ? trimmed : '';
};

/**
 * Sanitize username
 * @param {string} username - The username to sanitize
 * @returns {string} - The sanitized username
 */
const sanitizeUsername = (username) => {
  if (typeof username !== 'string') return '';
  return username.toLowerCase().trim().replace(/[^a-z0-9_]/g, '');
};

/**
 * Sanitize phone numbers
 * @param {string} phone - The phone number to sanitize
 * @returns {string} - The sanitized phone number
 */
const sanitizePhone = (phone) => {
  if (typeof phone !== 'string') return '';
  return phone.replace(/[^\d+\-\s()]/g, '').trim();
};

/**
 * Sanitize search queries
 * @param {string} query - The search query to sanitize
 * @returns {string} - The sanitized query
 */
const sanitizeSearchQuery = (query) => {
  if (typeof query !== 'string') return '';
  return query
    .trim()
    .replace(/[<>'"]/g, '')
    .replace(/\s+/g, ' ')
    .substring(0, 100);
};

/**
 * Prevent NoSQL injection by sanitizing objects
 * @param {object} obj - The object to sanitize
 * @returns {object} - The sanitized object
 */
const sanitizeNoSQL = (obj) => {
  if (typeof obj !== 'object' || obj === null) return obj;
  
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    // Remove dangerous keys
    if (key.startsWith('$') || key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    
    if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeNoSQL(value);
    } else if (typeof value === 'string') {
      sanitized[key] = value.trim();
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
};

/**
 * Sanitize file names
 * @param {string} filename - The filename to sanitize
 * @returns {string} - The sanitized filename
 */
const sanitizeFilename = (filename) => {
  if (typeof filename !== 'string') return '';
  return filename
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/_{2,}/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
};

/**
 * Prevent header injection
 * @param {string} header - The header value to sanitize
 * @returns {string} - The sanitized header
 */
const sanitizeHeader = (header) => {
  if (typeof header !== 'string') return '';
  return header.replace(/[\r\n]/g, '');
};

/**
 * Comprehensive input sanitization
 * @param {any} input - The input to sanitize
 * @param {string} type - The type of sanitization to apply
 * @returns {any} - The sanitized input
 */
const sanitizeInput = (input, type = 'text') => {
  if (typeof input === 'string') {
    switch (type) {
      case 'html':
        return sanitizeHtml(input);
      case 'email':
        return sanitizeEmail(input);
      case 'url':
        return sanitizeUrl(input);
      case 'username':
        return sanitizeUsername(input);
      case 'phone':
        return sanitizePhone(input);
      case 'search':
        return sanitizeSearchQuery(input);
      case 'filename':
        return sanitizeFilename(input);
      case 'header':
        return sanitizeHeader(input);
      case 'text':
      default:
        return sanitizeText(input);
    }
  }
  
  if (typeof input === 'object' && input !== null) {
    return sanitizeNoSQL(input);
  }
  
  return input;
};

/**
 * Middleware to sanitize all request inputs
 */
const sanitizeAllInputs = (req, res, next) => {
  // Sanitize request body
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeNoSQL(req.body);
  }

  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeNoSQL(req.query);
  }

  // Sanitize URL parameters
  if (req.params && typeof req.params === 'object') {
    req.params = sanitizeNoSQL(req.params);
  }

  // Sanitize specific headers
  const headersToSanitize = ['user-agent', 'referer', 'x-forwarded-for'];
  headersToSanitize.forEach(header => {
    if (req.headers[header]) {
      req.headers[header] = sanitizeHeader(req.headers[header]);
    }
  });

  next();
};

/**
 * Content-specific sanitization functions
 */
const sanitizeContent = {
  userProfile: (data) => ({
    ...data,
    firstName: sanitizeText(data.firstName),
    lastName: sanitizeText(data.lastName),
    username: sanitizeUsername(data.username),
    email: sanitizeEmail(data.email),
    bio: sanitizeHtml(data.bio),
    location: sanitizeText(data.location),
    website: sanitizeUrl(data.website),
  }),

  message: (data) => ({
    ...data,
    subject: sanitizeText(data.subject),
    content: sanitizeHtml(data.content),
    recipientId: sanitizeText(data.recipientId),
  }),

  search: (data) => ({
    ...data,
    q: sanitizeSearchQuery(data.q),
    category: sanitizeText(data.category),
    tags: Array.isArray(data.tags) ? data.tags.map(tag => sanitizeText(tag)) : [],
  }),
};

/**
 * Validation helpers to check if content is clean
 */
const isClean = {
  xss: (input) => {
    if (typeof input !== 'string') return true;
    const dangerous = /<script|javascript:|on\w+\s*=|<iframe|<object|<embed/i;
    return !dangerous.test(input);
  },

  sql: (input) => {
    if (typeof input !== 'string') return true;
    const dangerous = /('|(\\x27)|(\\x2D\\x2D)|(\;)|(\|)|(\*)|(\%27)|(\%2D\%2D)|(\%3B)|(\%7C)|(\%2A))/i;
    return !dangerous.test(input);
  },

  nosql: (obj) => {
    if (typeof obj !== 'object' || obj === null) return true;
    
    const checkKeys = (o) => {
      for (const key in o) {
        if (key.startsWith('$') || key === '__proto__') return false;
        if (typeof o[key] === 'object' && o[key] !== null) {
          if (!checkKeys(o[key])) return false;
        }
      }
      return true;
    };
    
    return checkKeys(obj);
  },
};

module.exports = { 
  sanitizeHtml, 
  sanitizeText,
  sanitizeEmail,
  sanitizeUrl,
  sanitizeUsername,
  sanitizePhone,
  sanitizeSearchQuery,
  sanitizeNoSQL,
  sanitizeFilename,
  sanitizeHeader,
  sanitizeInput,
  sanitizeAllInputs,
  sanitizeContent,
  isClean,
};


