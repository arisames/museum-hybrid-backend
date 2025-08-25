const Joi = require("joi");

const createOrUpdateProfileSchema = Joi.object({
  bio: Joi.string().max(500).allow("").optional(),
  location: Joi.string().max(100).allow("").optional(),
  website: Joi.string().uri().max(200).allow("").optional(),
  twitter: Joi.string().max(100).allow("").optional(),
  linkedin: Joi.string().max(100).allow("").optional(),
  github: Joi.string().max(100).allow("").optional(),
  forumSignature: Joi.string().max(250).allow("").optional(),
});

module.exports = {
  createOrUpdateProfileSchema,
};

