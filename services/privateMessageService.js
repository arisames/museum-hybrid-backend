const PrivateMessage = require("../models/PrivateMessage");
const User = require("../models/User");
const { NotFoundError, ForbiddenError } = require("../utils/CustomError");

const sendMessage = async (senderId, receiverId, subject, content, parentMessageId) => {
  const receiver = await User.findById(receiverId);
  if (!receiver) {
    throw new NotFoundError("Receiver not found");
  }

  const message = new PrivateMessage({
    sender: senderId,
    receiver: receiverId,
    subject,
    content,
    parentMessage: parentMessageId || null,
  });

  await message.save();
  return message;
};

const getMessages = async (userId, type, page = 1, limit = 10, search = '', readStatus = 'all') => {
  const skip = (page - 1) * limit;
  let query = {};

  if (type === "sent") {
    query = { sender: userId, deletedBySender: false };
  } else {
    query = { receiver: userId, deletedByReceiver: false };
  }

  if (search) {
    query.$or = [
      { subject: { $regex: search, $options: "i" } },
      { content: { $regex: search, $options: "i" } },
    ];
  }

  if (readStatus !== 'all') {
    query.read = readStatus === 'read';
  }

  const messages = await PrivateMessage.find(query)
    .populate(type === "sent" ? "receiver" : "sender", "username email")
    .sort({ sentAt: -1 })
    .skip(skip)
    .limit(limit);

  const totalMessages = await PrivateMessage.countDocuments(query);

  return { messages, totalMessages, page, pages: Math.ceil(totalMessages / limit) };
};

const getMessageById = async (messageId, userId) => {
  const message = await PrivateMessage.findById(messageId)
    .populate("sender", "username email")
    .populate("receiver", "username email")
    .populate("parentMessage");

  if (!message) {
    throw new NotFoundError("Message not found");
  }

  if (message.sender.toString() !== userId && message.receiver.toString() !== userId) {
    throw new ForbiddenError("Not authorized to view this message");
  }

  if (message.receiver.toString() === userId && !message.read) {
    message.read = true;
    await message.save();
  }
  return message;
};

const markMessageReadStatus = async (messageId, userId, readStatus) => {
  const message = await PrivateMessage.findById(messageId);

  if (!message) {
    throw new NotFoundError("Message not found");
  }

  if (message.receiver.toString() !== userId) {
    throw new ForbiddenError("Not authorized to modify this message");
  }

  message.read = readStatus;
  await message.save();
  return message;
};

const deleteMessage = async (messageId, userId) => {
  const message = await PrivateMessage.findById(messageId);

  if (!message) {
    throw new NotFoundError("Message not found");
  }

  if (message.sender.toString() === userId) {
    message.deletedBySender = true;
  } else if (message.receiver.toString() === userId) {
    message.deletedByReceiver = true;
  } else {
    throw new ForbiddenError("Not authorized to delete this message");
  }

  if (message.deletedBySender && message.deletedByReceiver) {
    await message.deleteOne();
    return { message: "Message permanently deleted" };
  } else {
    await message.save();
    return { message: "Message soft-deleted" };
  }
};

const getUnreadMessageCount = async (userId) => {
  const count = await PrivateMessage.countDocuments({
    receiver: userId,
    read: false,
    deletedByReceiver: false,
  });
  return { count };
};

module.exports = {
  sendMessage,
  getMessages,
  getMessageById,
  markMessageReadStatus,
  deleteMessage,
  getUnreadMessageCount,
};


