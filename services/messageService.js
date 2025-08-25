const PrivateMessage = require("../models/PrivateMessage");
const User = require("../models/User");
const { 
  NotFoundError, 
  ValidationError, 
  ForbiddenError,
  BadRequestError 
} = require("../utils/CustomError");
const logger = require("../utils/logger");

class MessageService {
  /**
   * Create a new private message
   * @param {string} senderId - Sender's user ID
   * @param {string} recipientId - Recipient's user ID
   * @param {string} subject - Message subject
   * @param {string} content - Message content
   * @returns {Object} Created message
   */
  async createMessage(senderId, recipientId, subject, content) {
    try {
      // Validate that sender and recipient exist and are different
      if (senderId === recipientId) {
        throw new ValidationError("Cannot send message to yourself");
      }

      const [sender, recipient] = await Promise.all([
        User.findById(senderId),
        User.findById(recipientId),
      ]);

      if (!sender) {
        throw new NotFoundError("Sender not found");
      }

      if (!recipient) {
        throw new NotFoundError("Recipient not found");
      }

      if (recipient.status !== 'active') {
        throw new ValidationError("Cannot send message to inactive user");
      }

      // Create message
      const message = await PrivateMessage.create({
        sender: senderId,
        recipient: recipientId,
        subject: subject.trim(),
        content: content.trim(),
        status: 'sent',
        sentAt: new Date(),
      });

      // Populate sender and recipient data
      await message.populate([
        { path: 'sender', select: 'username email firstName lastName' },
        { path: 'recipient', select: 'username email firstName lastName' }
      ]);

      logger.info('Private message created', {
        messageId: message._id,
        senderId,
        recipientId,
        subject: subject.substring(0, 50),
      });

      return {
        id: message._id,
        sender: {
          id: message.sender._id,
          username: message.sender.username,
          email: message.sender.email,
          firstName: message.sender.firstName,
          lastName: message.sender.lastName,
        },
        recipient: {
          id: message.recipient._id,
          username: message.recipient.username,
          email: message.recipient.email,
          firstName: message.recipient.firstName,
          lastName: message.recipient.lastName,
        },
        subject: message.subject,
        content: message.content,
        status: message.status,
        sentAt: message.sentAt,
        readAt: message.readAt,
        createdAt: message.createdAt,
      };
    } catch (error) {
      logger.error('Error creating message', {
        error: error.message,
        senderId,
        recipientId,
        subject: subject?.substring(0, 50),
      });
      throw error;
    }
  }

  /**
   * Get messages for a user (inbox/sent)
   * @param {string} userId - User's ID
   * @param {Object} options - Query options
   * @returns {Object} Messages with pagination
   */
  async getUserMessages(userId, options = {}) {
    try {
      const {
        type = 'inbox', // 'inbox', 'sent', 'all'
        page = 1,
        limit = 20,
        status,
        search,
        sortBy = 'createdAt',
        sortOrder = 'desc',
      } = options;

      let query = {};

      // Set query based on message type
      switch (type) {
        case 'inbox':
          query.recipient = userId;
          break;
        case 'sent':
          query.sender = userId;
          break;
        case 'all':
          query.$or = [{ sender: userId }, { recipient: userId }];
          break;
        default:
          throw new ValidationError("Invalid message type. Must be 'inbox', 'sent', or 'all'");
      }

      // Add status filter
      if (status) {
        query.status = status;
      }

      // Add search filter
      if (search) {
        const searchRegex = new RegExp(search, 'i');
        query.$and = [
          query.$and || {},
          {
            $or: [
              { subject: searchRegex },
              { content: searchRegex },
            ],
          },
        ];
      }

      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      const [messages, total] = await Promise.all([
        PrivateMessage.find(query)
          .populate('sender', 'username email firstName lastName')
          .populate('recipient', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(limit),
        PrivateMessage.countDocuments(query),
      ]);

      const totalPages = Math.ceil(total / limit);

      return {
        messages: messages.map(message => ({
          id: message._id,
          sender: {
            id: message.sender._id,
            username: message.sender.username,
            email: message.sender.email,
            firstName: message.sender.firstName,
            lastName: message.sender.lastName,
          },
          recipient: {
            id: message.recipient._id,
            username: message.recipient.username,
            email: message.recipient.email,
            firstName: message.recipient.firstName,
            lastName: message.recipient.lastName,
          },
          subject: message.subject,
          content: message.content,
          status: message.status,
          sentAt: message.sentAt,
          readAt: message.readAt,
          createdAt: message.createdAt,
          updatedAt: message.updatedAt,
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
        type,
      };
    } catch (error) {
      logger.error('Error getting user messages', {
        error: error.message,
        userId,
        options,
      });
      throw error;
    }
  }

  /**
   * Get a specific message by ID
   * @param {string} messageId - Message ID
   * @param {string} userId - User ID (for authorization)
   * @returns {Object} Message data
   */
  async getMessageById(messageId, userId) {
    try {
      const message = await PrivateMessage.findById(messageId)
        .populate('sender', 'username email firstName lastName')
        .populate('recipient', 'username email firstName lastName');

      if (!message) {
        throw new NotFoundError("Message not found");
      }

      // Check if user is authorized to view this message
      const isAuthorized = message.sender._id.toString() === userId || 
                          message.recipient._id.toString() === userId;

      if (!isAuthorized) {
        throw new ForbiddenError("Not authorized to view this message");
      }

      // Mark as read if user is the recipient and message is unread
      if (message.recipient._id.toString() === userId && !message.readAt) {
        message.readAt = new Date();
        message.status = 'read';
        await message.save();

        logger.info('Message marked as read', {
          messageId: message._id,
          recipientId: userId,
        });
      }

      return {
        id: message._id,
        sender: {
          id: message.sender._id,
          username: message.sender.username,
          email: message.sender.email,
          firstName: message.sender.firstName,
          lastName: message.sender.lastName,
        },
        recipient: {
          id: message.recipient._id,
          username: message.recipient.username,
          email: message.recipient.email,
          firstName: message.recipient.firstName,
          lastName: message.recipient.lastName,
        },
        subject: message.subject,
        content: message.content,
        status: message.status,
        sentAt: message.sentAt,
        readAt: message.readAt,
        createdAt: message.createdAt,
        updatedAt: message.updatedAt,
      };
    } catch (error) {
      logger.error('Error getting message by ID', {
        error: error.message,
        messageId,
        userId,
      });
      throw error;
    }
  }

  /**
   * Update message status
   * @param {string} messageId - Message ID
   * @param {string} status - New status
   * @param {string} userId - User ID (for authorization)
   * @returns {Object} Updated message
   */
  async updateMessageStatus(messageId, status, userId) {
    try {
      const validStatuses = ['sent', 'read', 'archived', 'deleted'];
      
      if (!validStatuses.includes(status)) {
        throw new ValidationError(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
      }

      const message = await PrivateMessage.findById(messageId);

      if (!message) {
        throw new NotFoundError("Message not found");
      }

      // Check authorization - only recipient can update status (except for sender marking as deleted)
      const isRecipient = message.recipient.toString() === userId;
      const isSender = message.sender.toString() === userId;
      
      if (!isRecipient && !(isSender && status === 'deleted')) {
        throw new ForbiddenError("Not authorized to update this message");
      }

      // Update message
      const updateData = { status, updatedAt: new Date() };
      
      if (status === 'read' && !message.readAt) {
        updateData.readAt = new Date();
      }

      const updatedMessage = await PrivateMessage.findByIdAndUpdate(
        messageId,
        updateData,
        { new: true }
      ).populate([
        { path: 'sender', select: 'username email firstName lastName' },
        { path: 'recipient', select: 'username email firstName lastName' }
      ]);

      logger.info('Message status updated', {
        messageId,
        oldStatus: message.status,
        newStatus: status,
        userId,
      });

      return {
        id: updatedMessage._id,
        status: updatedMessage.status,
        readAt: updatedMessage.readAt,
        updatedAt: updatedMessage.updatedAt,
      };
    } catch (error) {
      logger.error('Error updating message status', {
        error: error.message,
        messageId,
        status,
        userId,
      });
      throw error;
    }
  }

  /**
   * Delete a message
   * @param {string} messageId - Message ID
   * @param {string} userId - User ID (for authorization)
   */
  async deleteMessage(messageId, userId) {
    try {
      const message = await PrivateMessage.findById(messageId);

      if (!message) {
        throw new NotFoundError("Message not found");
      }

      // Check authorization - only sender or recipient can delete
      const isAuthorized = message.sender.toString() === userId || 
                          message.recipient.toString() === userId;

      if (!isAuthorized) {
        throw new ForbiddenError("Not authorized to delete this message");
      }

      await PrivateMessage.findByIdAndDelete(messageId);

      logger.info('Message deleted', {
        messageId,
        userId,
        subject: message.subject.substring(0, 50),
      });
    } catch (error) {
      logger.error('Error deleting message', {
        error: error.message,
        messageId,
        userId,
      });
      throw error;
    }
  }

  /**
   * Get message statistics for a user
   * @param {string} userId - User ID
   * @returns {Object} Message statistics
   */
  async getMessageStats(userId) {
    try {
      const [
        totalReceived,
        totalSent,
        unreadCount,
        archivedCount,
      ] = await Promise.all([
        PrivateMessage.countDocuments({ recipient: userId }),
        PrivateMessage.countDocuments({ sender: userId }),
        PrivateMessage.countDocuments({ recipient: userId, status: 'sent' }),
        PrivateMessage.countDocuments({ 
          $or: [{ sender: userId }, { recipient: userId }],
          status: 'archived'
        }),
      ]);

      return {
        totalReceived,
        totalSent,
        unreadCount,
        archivedCount,
        totalMessages: totalReceived + totalSent,
      };
    } catch (error) {
      logger.error('Error getting message stats', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Mark multiple messages as read
   * @param {string[]} messageIds - Array of message IDs
   * @param {string} userId - User ID (for authorization)
   * @returns {Object} Update result
   */
  async markMessagesAsRead(messageIds, userId) {
    try {
      if (!Array.isArray(messageIds) || messageIds.length === 0) {
        throw new ValidationError("Message IDs array is required");
      }

      const result = await PrivateMessage.updateMany(
        {
          _id: { $in: messageIds },
          recipient: userId,
          status: 'sent',
        },
        {
          status: 'read',
          readAt: new Date(),
          updatedAt: new Date(),
        }
      );

      logger.info('Multiple messages marked as read', {
        userId,
        messageIds: messageIds.length,
        modifiedCount: result.modifiedCount,
      });

      return {
        modifiedCount: result.modifiedCount,
        requestedCount: messageIds.length,
      };
    } catch (error) {
      logger.error('Error marking messages as read', {
        error: error.message,
        userId,
        messageCount: messageIds?.length,
      });
      throw error;
    }
  }

  /**
   * Get conversation between two users
   * @param {string} userId1 - First user ID
   * @param {string} userId2 - Second user ID
   * @param {string} requesterId - Requester's user ID (for authorization)
   * @param {Object} options - Query options
   * @returns {Object} Conversation messages
   */
  async getConversation(userId1, userId2, requesterId, options = {}) {
    try {
      // Check authorization - requester must be one of the participants
      if (requesterId !== userId1 && requesterId !== userId2) {
        throw new ForbiddenError("Not authorized to view this conversation");
      }

      const {
        page = 1,
        limit = 50,
        sortOrder = 'asc', // Show oldest messages first in conversation
      } = options;

      const query = {
        $or: [
          { sender: userId1, recipient: userId2 },
          { sender: userId2, recipient: userId1 },
        ],
      };

      const skip = (page - 1) * limit;
      const sort = { createdAt: sortOrder === 'desc' ? -1 : 1 };

      const [messages, total] = await Promise.all([
        PrivateMessage.find(query)
          .populate('sender', 'username email firstName lastName')
          .populate('recipient', 'username email firstName lastName')
          .sort(sort)
          .skip(skip)
          .limit(limit),
        PrivateMessage.countDocuments(query),
      ]);

      const totalPages = Math.ceil(total / limit);

      return {
        messages: messages.map(message => ({
          id: message._id,
          sender: {
            id: message.sender._id,
            username: message.sender.username,
            firstName: message.sender.firstName,
            lastName: message.sender.lastName,
          },
          recipient: {
            id: message.recipient._id,
            username: message.recipient.username,
            firstName: message.recipient.firstName,
            lastName: message.recipient.lastName,
          },
          subject: message.subject,
          content: message.content,
          status: message.status,
          sentAt: message.sentAt,
          readAt: message.readAt,
          createdAt: message.createdAt,
        })),
        participants: [userId1, userId2],
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error('Error getting conversation', {
        error: error.message,
        userId1,
        userId2,
        requesterId,
      });
      throw error;
    }
  }
}

module.exports = new MessageService();

