const Joi = require("joi");
const { BadRequestError } = require("../utils/CustomError");

const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body, { abortEarly: false });

  if (error) {
    const errors = error.details.map((err) => err.message);
    throw new BadRequestError(errors.join(", "));
  }
  next();
};

const validateQuery = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.query, { abortEarly: false });

  if (error) {
    const errors = error.details.map((err) => err.message);
    throw new BadRequestError(errors.join(", "));
  }
  next();
};

module.exports = { validate, validateQuery };


