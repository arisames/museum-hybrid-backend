const Joi = require("joi");

const sendMessageSchema = Joi.object({
  receiverId: Joi.string().hex().length(24).required(),
  subject: Joi.string().min(1).max(200).required(),
  content: Joi.string().min(1).max(5000).required(),
  parentMessageId: Joi.string().hex().length(24).allow(null).optional(),
});

const markMessageReadStatusSchema = Joi.object({
  read: Joi.boolean().required(),
});

module.exports = {
  sendMessageSchema,
  markMessageReadStatusSchema,
};

