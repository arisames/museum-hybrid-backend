/**
 * Service Layer Index
 * 
 * This file exports all service modules for easy importing throughout the application.
 * Services contain business logic and act as an intermediary layer between controllers and models.
 */

const userService = require('./userService');
const messageService = require('./messageService');

module.exports = {
  userService,
  messageService,
};

/**
 * Service Layer Architecture Guidelines:
 * 
 * 1. Services should contain all business logic
 * 2. Controllers should be thin and only handle HTTP concerns
 * 3. Services should handle data validation and transformation
 * 4. Services should manage database transactions
 * 5. Services should handle error logging and throwing appropriate errors
 * 6. Services should be testable and independent of HTTP layer
 * 7. Services can call other services but should avoid circular dependencies
 * 8. Services should use async/await consistently
 * 9. Services should provide comprehensive JSDoc documentation
 * 10. Services should handle edge cases and provide meaningful error messages
 */

