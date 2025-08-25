const Joi = require("joi");

const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const searchUsersSchema = Joi.object({
  query: Joi.string().min(1).required(),
});

module.exports = {
  registerSchema,
  loginSchema,
  searchUsersSchema,
};

