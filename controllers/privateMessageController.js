const { asyncHandler } = require("../middleware/errorMiddleware");
const { messageService } = require("../services");
const { sanitizeContent } = require("../utils/sanitize");
const { ValidationError } = require("../utils/CustomError");
const logger = require("../utils/logger");

// @desc    Create a new private message
// @route   POST /api/messages
// @access  Private
const createMessage = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { recipientId, subject, content } = req.body;

    // Validate required fields
    if (!recipientId || !subject || !content) {
      throw new ValidationError('Recipient, subject, and content are required', {
        required: ['recipientId', 'subject', 'content'],
        provided: Object.keys(req.body),
      });
    }

    // Sanitize inputs
    const sanitizedData = sanitizeContent.message({
      subject: subject.trim(),
      content: content.trim(),
    });

    // Additional validation
    if (sanitizedData.subject.length < 1 || sanitizedData.subject.length > 200) {
      throw new ValidationError('Subject must be between 1 and 200 characters');
    }

    if (sanitizedData.content.length < 1 || sanitizedData.content.length > 5000) {
      throw new ValidationError('Content must be between 1 and 5000 characters');
    }

    const message = await messageService.createMessage(
      req.user.id,
      recipientId,
      sanitizedData.subject,
      sanitizedData.content
    );

    logger.logPerformance('createMessage', Date.now() - startTime, {
      userId: req.user.id,
      success: true,
    });

    res.status(201).json({
      success: true,
      data: message,
    });
  } catch (error) {
    logger.logPerformance('createMessage', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Get user messages (inbox/sent)
// @route   GET /api/messages
// @access  Private
const getUserMessages = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const {
      type = 'inbox',
      page = 1,
      limit = 20,
      status,
      search,
      sortBy = 'createdAt',
      sortOrder = 'desc',
    } = req.query;

    // Validate and sanitize query parameters
    const sanitizedOptions = {
      type: ['inbox', 'sent', 'all'].includes(type) ? type : 'inbox',
      page: Math.max(1, parseInt(page) || 1),
      limit: Math.min(50, Math.max(1, parseInt(limit) || 20)),
      status: status ? sanitizeContent.search({ q: status }).q : undefined,
      search: search ? sanitizeContent.search({ q: search }).q : undefined,
      sortBy: ['createdAt', 'subject', 'sentAt'].includes(sortBy) ? sortBy : 'createdAt',
      sortOrder: ['asc', 'desc'].includes(sortOrder) ? sortOrder : 'desc',
    };

    const result = await messageService.getUserMessages(req.user.id, sanitizedOptions);

    logger.logPerformance('getUserMessages', Date.now() - startTime, {
      userId: req.user.id,
      type: sanitizedOptions.type,
      resultsCount: result.messages.length,
      success: true,
    });

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.logPerformance('getUserMessages', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Get a specific message by ID
// @route   GET /api/messages/:id
// @access  Private
const getMessageById = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { id } = req.params;

    const message = await messageService.getMessageById(id, req.user.id);

    logger.logPerformance('getMessageById', Date.now() - startTime, {
      userId: req.user.id,
      messageId: id,
      success: true,
    });

    res.json({
      success: true,
      data: message,
    });
  } catch (error) {
    logger.logPerformance('getMessageById', Date.now() - startTime, {
      userId: req.user.id,
      messageId: req.params.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Update message status
// @route   PUT /api/messages/:id/status
// @access  Private
const updateMessageStatus = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      throw new ValidationError('Status is required');
    }

    const sanitizedStatus = sanitizeContent.search({ q: status }).q;

    const updatedMessage = await messageService.updateMessageStatus(
      id,
      sanitizedStatus,
      req.user.id
    );

    logger.logPerformance('updateMessageStatus', Date.now() - startTime, {
      userId: req.user.id,
      messageId: id,
      status: sanitizedStatus,
      success: true,
    });

    res.json({
      success: true,
      data: updatedMessage,
    });
  } catch (error) {
    logger.logPerformance('updateMessageStatus', Date.now() - startTime, {
      userId: req.user.id,
      messageId: req.params.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Delete a message
// @route   DELETE /api/messages/:id
// @access  Private
const deleteMessage = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { id } = req.params;

    await messageService.deleteMessage(id, req.user.id);

    logger.logPerformance('deleteMessage', Date.now() - startTime, {
      userId: req.user.id,
      messageId: id,
      success: true,
    });

    res.json({
      success: true,
      message: 'Message deleted successfully',
    });
  } catch (error) {
    logger.logPerformance('deleteMessage', Date.now() - startTime, {
      userId: req.user.id,
      messageId: req.params.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Get message statistics
// @route   GET /api/messages/stats
// @access  Private
const getMessageStats = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const stats = await messageService.getMessageStats(req.user.id);

    logger.logPerformance('getMessageStats', Date.now() - startTime, {
      userId: req.user.id,
      success: true,
    });

    res.json({
      success: true,
      data: stats,
    });
  } catch (error) {
    logger.logPerformance('getMessageStats', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Mark multiple messages as read
// @route   PUT /api/messages/mark-read
// @access  Private
const markMessagesAsRead = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { messageIds } = req.body;

    if (!Array.isArray(messageIds)) {
      throw new ValidationError('messageIds must be an array');
    }

    const result = await messageService.markMessagesAsRead(messageIds, req.user.id);

    logger.logPerformance('markMessagesAsRead', Date.now() - startTime, {
      userId: req.user.id,
      messageCount: messageIds.length,
      modifiedCount: result.modifiedCount,
      success: true,
    });

    res.json({
      success: true,
      data: result,
    });
  } catch (error) {
    logger.logPerformance('markMessagesAsRead', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Get conversation between two users
// @route   GET /api/messages/conversation/:userId
// @access  Private
const getConversation = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { userId } = req.params;
    const {
      page = 1,
      limit = 50,
      sortOrder = 'asc',
    } = req.query;

    const sanitizedOptions = {
      page: Math.max(1, parseInt(page) || 1),
      limit: Math.min(100, Math.max(1, parseInt(limit) || 50)),
      sortOrder: ['asc', 'desc'].includes(sortOrder) ? sortOrder : 'asc',
    };

    const conversation = await messageService.getConversation(
      req.user.id,
      userId,
      req.user.id,
      sanitizedOptions
    );

    logger.logPerformance('getConversation', Date.now() - startTime, {
      userId: req.user.id,
      otherUserId: userId,
      messageCount: conversation.messages.length,
      success: true,
    });

    res.json({
      success: true,
      data: conversation,
    });
  } catch (error) {
    logger.logPerformance('getConversation', Date.now() - startTime, {
      userId: req.user.id,
      otherUserId: req.params.userId,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// Legacy method names for backward compatibility
const sendMessage = createMessage;
const getMessages = getUserMessages;
const markMessageReadStatus = updateMessageStatus;
const getUnreadMessageCount = getMessageStats;

module.exports = {
  createMessage,
  getUserMessages,
  getMessageById,
  updateMessageStatus,
  deleteMessage,
  getMessageStats,
  markMessagesAsRead,
  getConversation,
  // Legacy exports for backward compatibility
  sendMessage,
  getMessages,
  markMessageReadStatus,
  getUnreadMessageCount,
};
