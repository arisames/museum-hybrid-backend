class CustomError extends Error {
  constructor(message, statusCode, errorCode = null, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.isOperational = true; // Mark as operational errors
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      message: this.message,
      statusCode: this.statusCode,
      errorCode: this.errorCode,
      details: this.details,
      timestamp: this.timestamp,
      stack: process.env.NODE_ENV === 'production' ? undefined : this.stack,
    };
  }
}

class BadRequestError extends CustomError {
  constructor(message = 'Bad Request', details = null) {
    super(message, 400, 'BAD_REQUEST', details);
  }
}

class UnauthorizedError extends CustomError {
  constructor(message = 'Unauthorized', details = null) {
    super(message, 401, 'UNAUTHORIZED', details);
  }
}

class ForbiddenError extends CustomError {
  constructor(message = 'Forbidden', details = null) {
    super(message, 403, 'FORBIDDEN', details);
  }
}

class NotFoundError extends CustomError {
  constructor(message = 'Not Found', details = null) {
    super(message, 404, 'NOT_FOUND', details);
  }
}

class ConflictError extends CustomError {
  constructor(message = 'Conflict', details = null) {
    super(message, 409, 'CONFLICT', details);
  }
}

class ValidationError extends CustomError {
  constructor(message = 'Validation Error', details = null) {
    super(message, 422, 'VALIDATION_ERROR', details);
  }
}

class InternalServerError extends CustomError {
  constructor(message = 'Internal Server Error', details = null) {
    super(message, 500, 'INTERNAL_SERVER_ERROR', details);
  }
}

class ServiceUnavailableError extends CustomError {
  constructor(message = 'Service Unavailable', details = null) {
    super(message, 503, 'SERVICE_UNAVAILABLE', details);
  }
}

class DatabaseError extends CustomError {
  constructor(message = 'Database Error', details = null) {
    super(message, 500, 'DATABASE_ERROR', details);
  }
}

class AuthenticationError extends CustomError {
  constructor(message = 'Authentication Failed', details = null) {
    super(message, 401, 'AUTHENTICATION_ERROR', details);
  }
}

class AuthorizationError extends CustomError {
  constructor(message = 'Authorization Failed', details = null) {
    super(message, 403, 'AUTHORIZATION_ERROR', details);
  }
}

class RateLimitError extends CustomError {
  constructor(message = 'Rate Limit Exceeded', details = null) {
    super(message, 429, 'RATE_LIMIT_EXCEEDED', details);
  }
}

class FileUploadError extends CustomError {
  constructor(message = 'File Upload Error', details = null) {
    super(message, 400, 'FILE_UPLOAD_ERROR', details);
  }
}

class ExternalServiceError extends CustomError {
  constructor(message = 'External Service Error', details = null) {
    super(message, 502, 'EXTERNAL_SERVICE_ERROR', details);
  }
}

module.exports = {
  CustomError,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  ValidationError,
  InternalServerError,
  ServiceUnavailableError,
  DatabaseError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  FileUploadError,
  ExternalServiceError,
};

