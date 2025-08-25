const mongoose = require('mongoose');
const validator = require('validator');

const PrivateMessageSchema = new mongoose.Schema({
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Sender is required'],
    validate: {
      validator: function(v) {
        return mongoose.Types.ObjectId.isValid(v);
      },
      message: 'Sender must be a valid user ID'
    }
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Recipient is required'],
    validate: {
      validator: function(v) {
        return mongoose.Types.ObjectId.isValid(v);
      },
      message: 'Recipient must be a valid user ID'
    }
  },
  subject: {
    type: String,
    required: [true, 'Subject is required'],
    trim: true,
    minlength: [1, 'Subject cannot be empty'],
    maxlength: [200, 'Subject cannot be more than 200 characters long'],
    validate: {
      validator: function(v) {
        // Subject cannot be only whitespace
        return v.trim().length > 0;
      },
      message: 'Subject cannot be only whitespace'
    }
  },
  content: {
    type: String,
    required: [true, 'Content is required'],
    trim: true,
    minlength: [1, 'Content cannot be empty'],
    maxlength: [5000, 'Content cannot be more than 5000 characters long'],
    validate: {
      validator: function(v) {
        // Content cannot be only whitespace
        return v.trim().length > 0;
      },
      message: 'Content cannot be only whitespace'
    }
  },
  status: {
    type: String,
    enum: {
      values: ['sent', 'read', 'archived', 'deleted'],
      message: 'Status must be one of: sent, read, archived, deleted'
    },
    default: 'sent'
  },
  priority: {
    type: String,
    enum: {
      values: ['low', 'normal', 'high', 'urgent'],
      message: 'Priority must be one of: low, normal, high, urgent'
    },
    default: 'normal'
  },
  sentAt: {
    type: Date,
    default: Date.now,
    immutable: true // Cannot be changed after creation
  },
  readAt: {
    type: Date,
    default: null
  },
  parentMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PrivateMessage',
    default: null,
    validate: {
      validator: function(v) {
        if (!v) return true; // Allow null
        return mongoose.Types.ObjectId.isValid(v);
      },
      message: 'Parent message must be a valid message ID'
    }
  },
  threadId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'PrivateMessage',
    default: null // Will be set to the root message ID for threading
  },
  attachments: [{
    filename: {
      type: String,
      required: true,
      trim: true,
      maxlength: [255, 'Filename cannot be more than 255 characters long']
    },
    originalName: {
      type: String,
      required: true,
      trim: true,
      maxlength: [255, 'Original filename cannot be more than 255 characters long']
    },
    path: {
      type: String,
      required: true,
      trim: true
    },
    mimetype: {
      type: String,
      required: true,
      validate: {
        validator: function(v) {
          // Allow common file types
          const allowedTypes = [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'application/pdf', 'text/plain', 'text/csv',
            'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
          ];
          return allowedTypes.includes(v);
        },
        message: 'File type not allowed'
      }
    },
    size: {
      type: Number,
      required: true,
      min: [1, 'File size must be greater than 0'],
      max: [10 * 1024 * 1024, 'File size cannot exceed 10MB'] // 10MB limit
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  // Message flags
  isSystemMessage: {
    type: Boolean,
    default: false
  },
  isImportant: {
    type: Boolean,
    default: false
  },
  isEncrypted: {
    type: Boolean,
    default: false
  },
  // Soft delete flags
  deletedBySender: {
    type: Boolean,
    default: false
  },
  deletedByRecipient: {
    type: Boolean,
    default: false
  },
  deletedAt: {
    type: Date,
    default: null
  },
  // Moderation fields
  flagged: {
    type: Boolean,
    default: false
  },
  flaggedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  flaggedAt: {
    type: Date,
    default: null
  },
  flagReason: {
    type: String,
    trim: true,
    maxlength: [500, 'Flag reason cannot be more than 500 characters long'],
    default: ''
  },
  moderatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  moderatedAt: {
    type: Date,
    default: null
  },
  // Metadata
  ipAddress: {
    type: String,
    validate: {
      validator: function(v) {
        if (!v) return true; // Allow empty
        return validator.isIP(v);
      },
      message: 'Invalid IP address format'
    }
  },
  userAgent: {
    type: String,
    trim: true,
    maxlength: [500, 'User agent cannot be more than 500 characters long']
  },
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
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
      delete ret.__v;
      delete ret.ipAddress;
      delete ret.userAgent;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Virtual for message age
PrivateMessageSchema.virtual('age').get(function() {
  return Date.now() - this.sentAt.getTime();
});

// Virtual for read status
PrivateMessageSchema.virtual('isRead').get(function() {
  return this.status === 'read' && this.readAt !== null;
});

// Virtual for thread depth (if part of a conversation)
PrivateMessageSchema.virtual('isReply').get(function() {
  return this.parentMessage !== null;
});

// Virtual for attachment count
PrivateMessageSchema.virtual('attachmentCount').get(function() {
  return this.attachments ? this.attachments.length : 0;
});

// Virtual for total attachment size
PrivateMessageSchema.virtual('totalAttachmentSize').get(function() {
  if (!this.attachments || this.attachments.length === 0) return 0;
  return this.attachments.reduce((total, attachment) => total + attachment.size, 0);
});

// Indexes for performance optimization

// Primary indexes for message retrieval
PrivateMessageSchema.index({ recipient: 1, status: 1, sentAt: -1 }); // Inbox queries
PrivateMessageSchema.index({ sender: 1, sentAt: -1 }); // Sent messages
PrivateMessageSchema.index({ recipient: 1, sentAt: -1 }); // All recipient messages
PrivateMessageSchema.index({ sender: 1, recipient: 1, sentAt: -1 }); // Conversation queries

// Status and filtering indexes
PrivateMessageSchema.index({ status: 1, sentAt: -1 });
PrivateMessageSchema.index({ priority: 1, sentAt: -1 });
PrivateMessageSchema.index({ isSystemMessage: 1, sentAt: -1 });
PrivateMessageSchema.index({ flagged: 1, flaggedAt: -1 });

// Threading indexes
PrivateMessageSchema.index({ parentMessage: 1, sentAt: 1 });
PrivateMessageSchema.index({ threadId: 1, sentAt: 1 });

// Soft delete indexes
PrivateMessageSchema.index({ deletedBySender: 1, deletedByRecipient: 1 });
PrivateMessageSchema.index({ deletedAt: 1 });

// Search indexes
PrivateMessageSchema.index({ 
  subject: 'text', 
  content: 'text' 
}, {
  weights: { subject: 10, content: 5 },
  name: 'message_search_index'
});

// Compound indexes for complex queries
PrivateMessageSchema.index({ 
  recipient: 1, 
  deletedByRecipient: 1, 
  status: 1, 
  sentAt: -1 
}); // Efficient inbox queries

PrivateMessageSchema.index({ 
  sender: 1, 
  deletedBySender: 1, 
  sentAt: -1 
}); // Efficient sent messages queries

PrivateMessageSchema.index({
  $or: [
    { sender: 1, recipient: 1 },
    { sender: 1, recipient: 1 }
  ],
  sentAt: -1
}); // Conversation queries

// Pre-save middleware
PrivateMessageSchema.pre('save', function(next) {
  // Validate that sender and recipient are different
  if (this.sender && this.recipient && this.sender.toString() === this.recipient.toString()) {
    const error = new Error('Sender and recipient cannot be the same');
    error.name = 'ValidationError';
    error.errors = {
      recipient: {
        message: 'Cannot send message to yourself',
        kind: 'user',
        path: 'recipient',
        value: this.recipient
      }
    };
    return next(error);
  }

  // Set threadId for threading
  if (this.parentMessage && !this.threadId) {
    // If this is a reply, find the root message
    this.constructor.findById(this.parentMessage)
      .then(parentMsg => {
        if (parentMsg) {
          this.threadId = parentMsg.threadId || parentMsg._id;
        }
        next();
      })
      .catch(next);
  } else if (!this.parentMessage && !this.threadId) {
    // This is a root message, set threadId to its own ID after save
    this.threadId = this._id;
    next();
  } else {
    next();
  }

  // Update updatedAt timestamp
  if (this.isModified() && !this.isNew) {
    this.updatedAt = new Date();
  }
});

// Post-save middleware to set threadId for root messages
PrivateMessageSchema.post('save', function(doc) {
  if (!doc.parentMessage && (!doc.threadId || doc.threadId.toString() !== doc._id.toString())) {
    doc.threadId = doc._id;
    doc.save();
  }
});

// Instance methods
PrivateMessageSchema.methods.markAsRead = function() {
  if (this.status === 'sent') {
    this.status = 'read';
    this.readAt = new Date();
    this.updatedAt = new Date();
    return this.save();
  }
  return Promise.resolve(this);
};

PrivateMessageSchema.methods.markAsDeleted = function(userId) {
  if (this.sender.toString() === userId.toString()) {
    this.deletedBySender = true;
  } else if (this.recipient.toString() === userId.toString()) {
    this.deletedByRecipient = true;
  }
  
  // If both users have deleted, mark with deletion timestamp
  if (this.deletedBySender && this.deletedByRecipient) {
    this.deletedAt = new Date();
  }
  
  this.updatedAt = new Date();
  return this.save();
};

PrivateMessageSchema.methods.flag = function(userId, reason = '') {
  this.flagged = true;
  this.flaggedBy = userId;
  this.flaggedAt = new Date();
  this.flagReason = reason;
  this.updatedAt = new Date();
  return this.save();
};

PrivateMessageSchema.methods.unflag = function(moderatorId) {
  this.flagged = false;
  this.flaggedBy = null;
  this.flaggedAt = null;
  this.flagReason = '';
  this.moderatedBy = moderatorId;
  this.moderatedAt = new Date();
  this.updatedAt = new Date();
  return this.save();
};

PrivateMessageSchema.methods.isVisibleTo = function(userId) {
  const userIdStr = userId.toString();
  const senderStr = this.sender.toString();
  const recipientStr = this.recipient.toString();
  
  // Check if user is sender or recipient
  if (userIdStr !== senderStr && userIdStr !== recipientStr) {
    return false;
  }
  
  // Check soft delete status
  if (userIdStr === senderStr && this.deletedBySender) {
    return false;
  }
  
  if (userIdStr === recipientStr && this.deletedByRecipient) {
    return false;
  }
  
  return true;
};

PrivateMessageSchema.methods.toSafeJSON = function(userId) {
  const messageObject = this.toObject();
  
  // Remove sensitive information based on user role
  if (!this.isVisibleTo(userId)) {
    return null;
  }
  
  // Remove moderation fields for non-moderators
  delete messageObject.ipAddress;
  delete messageObject.userAgent;
  delete messageObject.flaggedBy;
  delete messageObject.moderatedBy;
  
  return messageObject;
};

// Static methods
PrivateMessageSchema.statics.findByConversation = function(userId1, userId2, options = {}) {
  const {
    limit = 50,
    skip = 0,
    sortOrder = 1 // 1 for ascending (oldest first), -1 for descending
  } = options;
  
  return this.find({
    $or: [
      { sender: userId1, recipient: userId2 },
      { sender: userId2, recipient: userId1 }
    ],
    $and: [
      {
        $or: [
          { sender: userId1, deletedBySender: false },
          { sender: userId2, deletedBySender: false }
        ]
      },
      {
        $or: [
          { recipient: userId1, deletedByRecipient: false },
          { recipient: userId2, deletedByRecipient: false }
        ]
      }
    ]
  })
  .populate('sender', 'username firstName lastName avatar')
  .populate('recipient', 'username firstName lastName avatar')
  .sort({ sentAt: sortOrder })
  .limit(limit)
  .skip(skip);
};

PrivateMessageSchema.statics.findInbox = function(userId, options = {}) {
  const {
    status,
    limit = 20,
    skip = 0,
    search
  } = options;
  
  let query = {
    recipient: userId,
    deletedByRecipient: false
  };
  
  if (status) {
    query.status = status;
  }
  
  if (search) {
    query.$text = { $search: search };
  }
  
  return this.find(query)
    .populate('sender', 'username firstName lastName avatar')
    .sort({ sentAt: -1 })
    .limit(limit)
    .skip(skip);
};

PrivateMessageSchema.statics.findSent = function(userId, options = {}) {
  const {
    limit = 20,
    skip = 0,
    search
  } = options;
  
  let query = {
    sender: userId,
    deletedBySender: false
  };
  
  if (search) {
    query.$text = { $search: search };
  }
  
  return this.find(query)
    .populate('recipient', 'username firstName lastName avatar')
    .sort({ sentAt: -1 })
    .limit(limit)
    .skip(skip);
};

PrivateMessageSchema.statics.countUnread = function(userId) {
  return this.countDocuments({
    recipient: userId,
    status: 'sent',
    deletedByRecipient: false
  });
};

PrivateMessageSchema.statics.markMultipleAsRead = function(messageIds, userId) {
  return this.updateMany(
    {
      _id: { $in: messageIds },
      recipient: userId,
      status: 'sent'
    },
    {
      status: 'read',
      readAt: new Date(),
      updatedAt: new Date()
    }
  );
};

module.exports = mongoose.model('PrivateMessage', PrivateMessageSchema);
