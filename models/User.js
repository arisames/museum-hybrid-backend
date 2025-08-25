const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Please add a username"],
    unique: true,
    trim: true,
    minlength: [3, "Username must be at least 3 characters long"],
    maxlength: [30, "Username cannot be more than 30 characters long"],
    match: [/^[a-zA-Z0-9_]+$/, "Username can only contain letters, numbers, and underscores"],
    validate: {
      validator: function(v) {
        // Username cannot start or end with underscore
        return !/^_|_$/.test(v);
      },
      message: "Username cannot start or end with underscore"
    }
  },
  email: {
    type: String,
    required: [true, "Please add an email"],
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: validator.isEmail,
      message: "Please provide a valid email address"
    }
  },
  password: {
    type: String,
    required: [true, "Please add a password"],
    minlength: [8, "Password must be at least 8 characters long"],
    select: false, // Don't include password in queries by default
    validate: {
      validator: function(v) {
        // Password complexity: at least one uppercase, one lowercase, one number, one special char
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\]:",.<>/?]).{8,}$/.test(v);
      },
      message: "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    }
  },
  firstName: {
    type: String,
    required: [true, "Please add a first name"],
    trim: true,
    minlength: [1, "First name cannot be empty"],
    maxlength: [50, "First name cannot be more than 50 characters long"],
    match: [/^[a-zA-Z\s'-]+$/, "First name can only contain letters, spaces, hyphens, and apostrophes"]
  },
  lastName: {
    type: String,
    required: [true, "Please add a last name"],
    trim: true,
    minlength: [1, "Last name cannot be empty"],
    maxlength: [50, "Last name cannot be more than 50 characters long"],
    match: [/^[a-zA-Z\s'-]+$/, "Last name can only contain letters, spaces, hyphens, and apostrophes"]
  },
  bio: {
    type: String,
    trim: true,
    maxlength: [500, "Bio cannot be more than 500 characters long"],
    default: ""
  },
  location: {
    type: String,
    trim: true,
    maxlength: [100, "Location cannot be more than 100 characters long"],
    default: ""
  },
  website: {
    type: String,
    trim: true,
    validate: {
      validator: function(v) {
        if (!v) return true; // Allow empty string
        return validator.isURL(v, {
          protocols: ['http', 'https'],
          require_protocol: true
        });
      },
      message: "Please provide a valid website URL (must include http:// or https://)"
    },
    default: ""
  },
  avatar: {
    type: String,
    trim: true,
    validate: {
      validator: function(v) {
        if (!v) return true; // Allow empty string
        return validator.isURL(v);
      },
      message: "Please provide a valid avatar URL"
    },
    default: ""
  },
  role: {
    type: String,
    enum: {
      values: ["user", "moderator", "admin", "superadmin"],
      message: "Role must be one of: user, moderator, admin, superadmin"
    },
    default: "user"
  },
  status: {
    type: String,
    enum: {
      values: ["active", "inactive", "suspended", "banned"],
      message: "Status must be one of: active, inactive, suspended, banned"
    },
    default: "active"
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    select: false
  },
  emailVerificationExpires: {
    type: Date,
    select: false
  },
  passwordResetToken: {
    type: String,
    select: false
  },
  passwordResetExpires: {
    type: Date,
    select: false
  },
  passwordChangedAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginCount: {
    type: Number,
    default: 0,
    min: [0, "Login count cannot be negative"]
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
    min: [0, "Failed login attempts cannot be negative"],
    max: [10, "Failed login attempts cannot exceed 10"]
  },
  accountLockedUntil: {
    type: Date,
    default: null
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    select: false
  },
  preferences: {
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      },
      messages: {
        type: Boolean,
        default: true
      }
    },
    privacy: {
      profileVisibility: {
        type: String,
        enum: ["public", "private", "friends"],
        default: "public"
      },
      showEmail: {
        type: Boolean,
        default: false
      },
      showLocation: {
        type: Boolean,
        default: true
      }
    },
    theme: {
      type: String,
      enum: ["light", "dark", "auto"],
      default: "auto"
    },
    language: {
      type: String,
      default: "en",
      match: [/^[a-z]{2}(-[A-Z]{2})?$/, "Language must be a valid locale code (e.g., 'en', 'en-US')"]
    }
  },
  socialLinks: {
    twitter: {
      type: String,
      trim: true,
      validate: {
        validator: function(v) {
          if (!v) return true;
          return /^https?:\/\/(www\.)?twitter\.com\/[a-zA-Z0-9_]+\/?$/.test(v);
        },
        message: "Please provide a valid Twitter URL"
      },
      default: ""
    },
    linkedin: {
      type: String,
      trim: true,
      validate: {
        validator: function(v) {
          if (!v) return true;
          return /^https?:\/\/(www\.)?linkedin\.com\/in\/[a-zA-Z0-9-]+\/?$/.test(v);
        },
        message: "Please provide a valid LinkedIn URL"
      },
      default: ""
    },
    github: {
      type: String,
      trim: true,
      validate: {
        validator: function(v) {
          if (!v) return true;
          return /^https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9-]+\/?$/.test(v);
        },
        message: "Please provide a valid GitHub URL"
      },
      default: ""
    }
  },
  refreshToken: {
    type: String,
    select: false
  },
  refreshTokenExpires: {
    type: Date,
    select: false
  },
  // Audit fields
  statusUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },
  statusUpdatedAt: {
    type: Date,
    default: null
  },
  roleUpdatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },
  roleUpdatedAt: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true // Cannot be changed after creation
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true, // Automatically manage createdAt and updatedAt
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive fields from JSON output
      delete ret.password;
      delete ret.refreshToken;
      delete ret.refreshTokenExpires;
      delete ret.emailVerificationToken;
      delete ret.emailVerificationExpires;
      delete ret.passwordResetToken;
      delete ret.passwordResetExpires;
      delete ret.twoFactorSecret;
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Virtual for full name
UserSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account locked status
UserSchema.virtual('isLocked').get(function() {
  return !!(this.accountLockedUntil && this.accountLockedUntil > Date.now());
});

// Virtual for profile completion percentage
UserSchema.virtual('profileCompletion').get(function() {
  let completed = 0;
  const fields = ['firstName', 'lastName', 'bio', 'location', 'website', 'avatar'];
  
  fields.forEach(field => {
    if (this[field] && this[field].trim() !== '') {
      completed++;
    }
  });
  
  // Check social links
  const socialFields = ['twitter', 'linkedin', 'github'];
  socialFields.forEach(field => {
    if (this.socialLinks[field] && this.socialLinks[field].trim() !== '') {
      completed++;
    }
  });
  
  return Math.round((completed / (fields.length + socialFields.length)) * 100);
});

// Indexes for performance
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ username: 1 }, { unique: true });
UserSchema.index({ status: 1 });
UserSchema.index({ role: 1 });
UserSchema.index({ createdAt: -1 });
UserSchema.index({ lastLogin: -1 });
UserSchema.index({ 'preferences.privacy.profileVisibility': 1 });

// Compound indexes for common queries
UserSchema.index({ status: 1, role: 1 });
UserSchema.index({ status: 1, createdAt: -1 });
UserSchema.index({ username: 'text', firstName: 'text', lastName: 'text' }, {
  weights: { username: 10, firstName: 5, lastName: 5 },
  name: 'user_search_index'
});

// Pre-save middleware
UserSchema.pre("save", async function (next) {
  // Hash password if modified
  if (this.isModified("password")) {
    // Only hash if it's not already hashed (for validation)
    if (!this.password.startsWith('$2a$') && !this.password.startsWith('$2b$')) {
      const salt = await bcrypt.genSalt(12);
      this.password = await bcrypt.hash(this.password, salt);
    }
    this.passwordChangedAt = new Date();
  }

  // Update updatedAt timestamp
  if (this.isModified() && !this.isNew) {
    this.updatedAt = new Date();
  }

  // Normalize email
  if (this.isModified("email")) {
    this.email = this.email.toLowerCase().trim();
  }

  // Normalize username
  if (this.isModified("username")) {
    this.username = this.username.trim();
  }

  // Validate unique fields manually for better error messages
  if (this.isModified("email")) {
    const existingUser = await this.constructor.findOne({ 
      email: this.email, 
      _id: { $ne: this._id } 
    });
    if (existingUser) {
      const error = new Error("Email address is already in use");
      error.name = "ValidationError";
      error.errors = {
        email: {
          message: "Email address is already in use",
          kind: "unique",
          path: "email",
          value: this.email
        }
      };
      return next(error);
    }
  }

  if (this.isModified("username")) {
    const existingUser = await this.constructor.findOne({ 
      username: this.username, 
      _id: { $ne: this._id } 
    });
    if (existingUser) {
      const error = new Error("Username is already taken");
      error.name = "ValidationError";
      error.errors = {
        username: {
          message: "Username is already taken",
          kind: "unique",
          path: "username",
          value: this.username
        }
      };
      return next(error);
    }
  }

  next();
});

// Instance methods
UserSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

UserSchema.methods.incrementLoginCount = function() {
  this.loginCount += 1;
  this.lastLogin = new Date();
  this.failedLoginAttempts = 0; // Reset failed attempts on successful login
  return this.save();
};

UserSchema.methods.incrementFailedLoginAttempts = function() {
  this.failedLoginAttempts += 1;
  
  // Lock account after 5 failed attempts for 30 minutes
  if (this.failedLoginAttempts >= 5) {
    this.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  }
  
  return this.save();
};

UserSchema.methods.resetFailedLoginAttempts = function() {
  this.failedLoginAttempts = 0;
  this.accountLockedUntil = null;
  return this.save();
};

UserSchema.methods.generatePasswordResetToken = function() {
  const crypto = require('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  
  return resetToken;
};

UserSchema.methods.generateEmailVerificationToken = function() {
  const crypto = require('crypto');
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.emailVerificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
  this.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  
  return verificationToken;
};

UserSchema.methods.verifyEmail = function() {
  this.emailVerified = true;
  this.emailVerificationToken = undefined;
  this.emailVerificationExpires = undefined;
  return this.save();
};

UserSchema.methods.toPublicJSON = function() {
  const userObject = this.toObject();
  
  // Remove sensitive information
  delete userObject.password;
  delete userObject.refreshToken;
  delete userObject.refreshTokenExpires;
  delete userObject.emailVerificationToken;
  delete userObject.emailVerificationExpires;
  delete userObject.passwordResetToken;
  delete userObject.passwordResetExpires;
  delete userObject.twoFactorSecret;
  delete userObject.failedLoginAttempts;
  delete userObject.accountLockedUntil;
  
  // Apply privacy settings
  if (this.preferences.privacy.profileVisibility === 'private') {
    delete userObject.bio;
    delete userObject.location;
    delete userObject.website;
    delete userObject.socialLinks;
  }
  
  if (!this.preferences.privacy.showEmail) {
    delete userObject.email;
  }
  
  if (!this.preferences.privacy.showLocation) {
    delete userObject.location;
  }
  
  return userObject;
};

// Static methods
UserSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase().trim() });
};

UserSchema.statics.findByUsername = function(username) {
  return this.findOne({ username: username.trim() });
};

UserSchema.statics.findActiveUsers = function() {
  return this.find({ status: 'active' });
};

UserSchema.statics.searchUsers = function(query, options = {}) {
  const {
    limit = 10,
    skip = 0,
    sortBy = 'username',
    sortOrder = 1
  } = options;
  
  return this.find(
    { 
      $text: { $search: query },
      status: 'active',
      'preferences.privacy.profileVisibility': { $ne: 'private' }
    },
    { score: { $meta: 'textScore' } }
  )
  .sort({ score: { $meta: 'textScore' }, [sortBy]: sortOrder })
  .limit(limit)
  .skip(skip);
};

module.exports = mongoose.model("User", UserSchema);


