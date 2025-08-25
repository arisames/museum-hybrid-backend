const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { generateTokens } = require("../middleware/authMiddleware");
const { 
  BadRequestError, 
  UnauthorizedError, 
  NotFoundError, 
  ConflictError,
  ValidationError 
} = require("../utils/CustomError");
const logger = require("../utils/logger");

class UserService {
  /**
   * Register a new user
   * @param {string} username - User's username
   * @param {string} email - User's email
   * @param {string} password - User's password
   * @param {string} firstName - User's first name
   * @param {string} lastName - User's last name
   * @returns {Object} User data and tokens
   */
  async registerUser(username, email, password, firstName, lastName) {
    try {
      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { username }]
      });

      if (existingUser) {
        if (existingUser.email === email) {
          throw new ConflictError("User with this email already exists");
        }
        if (existingUser.username === username) {
          throw new ConflictError("Username is already taken");
        }
      }

      // Hash password
      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create user
      const user = await User.create({
        username,
        email: email.toLowerCase(),
        password: hashedPassword,
        firstName,
        lastName,
        role: 'user',
        status: 'active',
      });

      // Generate tokens
      const tokens = generateTokens(user._id);

      // Log user creation
      logger.info('New user registered', {
        userId: user._id,
        username: user.username,
        email: user.email,
      });

      return {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          status: user.status,
          createdAt: user.createdAt,
        },
        ...tokens,
      };
    } catch (error) {
      logger.error('Error registering user', {
        error: error.message,
        username,
        email,
      });
      throw error;
    }
  }

  /**
   * Authenticate user login
   * @param {string} email - User's email
   * @param {string} password - User's password
   * @returns {Object} User data and tokens
   */
  async loginUser(email, password) {
    try {
      // Find user by email
      const user = await User.findOne({ email: email.toLowerCase() }).select('+password');

      if (!user) {
        throw new UnauthorizedError("Invalid email or password");
      }

      // Check if account is active
      if (user.status !== 'active') {
        throw new UnauthorizedError(`Account is ${user.status}. Please contact support.`);
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        throw new UnauthorizedError("Invalid email or password");
      }

      // Update last login
      await User.findByIdAndUpdate(user._id, {
        lastLogin: new Date(),
        $inc: { loginCount: 1 },
      });

      // Generate tokens
      const tokens = generateTokens(user._id);

      logger.info('User logged in successfully', {
        userId: user._id,
        username: user.username,
        email: user.email,
      });

      return {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          status: user.status,
          lastLogin: new Date(),
        },
        ...tokens,
      };
    } catch (error) {
      logger.error('Error logging in user', {
        error: error.message,
        email,
      });
      throw error;
    }
  }

  /**
   * Get user by ID
   * @param {string} userId - User's ID
   * @returns {Object} User data
   */
  async getUserById(userId) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new NotFoundError("User not found");
      }

      return {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        bio: user.bio,
        location: user.location,
        website: user.website,
        role: user.role,
        status: user.status,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        lastLogin: user.lastLogin,
      };
    } catch (error) {
      logger.error('Error getting user by ID', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Search users by username or email
   * @param {string} query - Search query
   * @param {number} page - Page number
   * @param {number} limit - Results per page
   * @returns {Object} Search results with pagination
   */
  async searchUsers(query, page = 1, limit = 10) {
    try {
      const searchRegex = new RegExp(query, 'i');
      
      const searchQuery = {
        status: 'active', // Only search active users
        $or: [
          { username: searchRegex },
          { email: searchRegex },
          { firstName: searchRegex },
          { lastName: searchRegex },
        ],
      };

      const skip = (page - 1) * limit;

      const [users, total] = await Promise.all([
        User.find(searchQuery)
          .select('username email firstName lastName createdAt')
          .sort({ username: 1 })
          .skip(skip)
          .limit(limit),
        User.countDocuments(searchQuery),
      ]);

      const totalPages = Math.ceil(total / limit);

      return {
        users: users.map(user => ({
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          createdAt: user.createdAt,
        })),
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
      logger.error('Error searching users', {
        error: error.message,
        query,
        page,
        limit,
      });
      throw error;
    }
  }

  /**
   * Update user profile
   * @param {string} userId - User's ID
   * @param {Object} updateData - Data to update
   * @returns {Object} Updated user data
   */
  async updateUserProfile(userId, updateData) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Check if username is being updated and if it's available
      if (updateData.username && updateData.username !== user.username) {
        const existingUser = await User.findOne({ 
          username: updateData.username,
          _id: { $ne: userId } 
        });

        if (existingUser) {
          throw new ConflictError("Username is already taken");
        }
      }

      // Update user
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { ...updateData, updatedAt: new Date() },
        { new: true, runValidators: true }
      );

      logger.info('User profile updated', {
        userId,
        updatedFields: Object.keys(updateData),
      });

      return {
        id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        bio: updatedUser.bio,
        location: updatedUser.location,
        website: updatedUser.website,
        role: updatedUser.role,
        status: updatedUser.status,
        updatedAt: updatedUser.updatedAt,
      };
    } catch (error) {
      logger.error('Error updating user profile', {
        error: error.message,
        userId,
        updateData: Object.keys(updateData),
      });
      throw error;
    }
  }

  /**
   * Change user password
   * @param {string} userId - User's ID
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   */
  async changePassword(userId, currentPassword, newPassword) {
    try {
      const user = await User.findById(userId).select('+password');

      if (!user) {
        throw new NotFoundError("User not found");
      }

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

      if (!isCurrentPasswordValid) {
        throw new UnauthorizedError("Current password is incorrect");
      }

      // Check if new password is different from current
      const isSamePassword = await bcrypt.compare(newPassword, user.password);

      if (isSamePassword) {
        throw new ValidationError("New password must be different from current password");
      }

      // Hash new password
      const salt = await bcrypt.genSalt(12);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);

      // Update password and set passwordChangedAt
      await User.findByIdAndUpdate(userId, {
        password: hashedNewPassword,
        passwordChangedAt: new Date(),
        updatedAt: new Date(),
      });

      logger.info('User password changed', {
        userId,
        username: user.username,
      });
    } catch (error) {
      logger.error('Error changing user password', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @returns {Object} New tokens and user data
   */
  async refreshAccessToken(refreshToken) {
    try {
      const { verifyToken } = require("../middleware/authMiddleware");
      
      // Verify refresh token
      const decoded = verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
      
      if (decoded.type !== 'refresh') {
        throw new UnauthorizedError('Invalid token type');
      }

      // Get user
      const user = await User.findById(decoded.id);
      
      if (!user) {
        throw new NotFoundError("User not found");
      }

      if (user.status !== 'active') {
        throw new UnauthorizedError(`Account is ${user.status}`);
      }

      // Generate new tokens
      const tokens = generateTokens(user._id);

      return {
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
        },
        ...tokens,
      };
    } catch (error) {
      logger.error('Error refreshing access token', {
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get user statistics
   * @param {string} userId - User's ID
   * @returns {Object} User statistics
   */
  async getUserStats(userId) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new NotFoundError("User not found");
      }

      // This would typically aggregate data from other collections
      // For now, returning basic user stats
      return {
        userId: user._id,
        username: user.username,
        joinDate: user.createdAt,
        lastLogin: user.lastLogin,
        loginCount: user.loginCount || 0,
        status: user.status,
        role: user.role,
      };
    } catch (error) {
      logger.error('Error getting user stats', {
        error: error.message,
        userId,
      });
      throw error;
    }
  }

  /**
   * Update user status (admin only)
   * @param {string} userId - User's ID
   * @param {string} status - New status
   * @param {string} adminId - Admin's ID
   * @returns {Object} Updated user data
   */
  async updateUserStatus(userId, status, adminId) {
    try {
      const validStatuses = ['active', 'inactive', 'suspended'];
      
      if (!validStatuses.includes(status)) {
        throw new ValidationError(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
      }

      const user = await User.findById(userId);

      if (!user) {
        throw new NotFoundError("User not found");
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { 
          status,
          statusUpdatedBy: adminId,
          statusUpdatedAt: new Date(),
          updatedAt: new Date(),
        },
        { new: true }
      );

      logger.info('User status updated', {
        userId,
        oldStatus: user.status,
        newStatus: status,
        adminId,
      });

      return {
        id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        status: updatedUser.status,
        statusUpdatedAt: updatedUser.statusUpdatedAt,
      };
    } catch (error) {
      logger.error('Error updating user status', {
        error: error.message,
        userId,
        status,
        adminId,
      });
      throw error;
    }
  }

  /**
   * Update user role (admin only)
   * @param {string} userId - User's ID
   * @param {string} role - New role
   * @param {string} adminId - Admin's ID
   * @returns {Object} Updated user data
   */
  async updateUserRole(userId, role, adminId) {
    try {
      const validRoles = ['user', 'moderator', 'admin'];
      
      if (!validRoles.includes(role)) {
        throw new ValidationError(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
      }

      const user = await User.findById(userId);

      if (!user) {
        throw new NotFoundError("User not found");
      }

      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { 
          role,
          roleUpdatedBy: adminId,
          roleUpdatedAt: new Date(),
          updatedAt: new Date(),
        },
        { new: true }
      );

      logger.info('User role updated', {
        userId,
        oldRole: user.role,
        newRole: role,
        adminId,
      });

      return {
        id: updatedUser._id,
        username: updatedUser.username,
        email: updatedUser.email,
        role: updatedUser.role,
        roleUpdatedAt: updatedUser.roleUpdatedAt,
      };
    } catch (error) {
      logger.error('Error updating user role', {
        error: error.message,
        userId,
        role,
        adminId,
      });
      throw error;
    }
  }

  /**
   * Get all users (admin only) with pagination and filtering
   * @param {Object} options - Query options
   * @returns {Object} Users list with pagination
   */
  async getAllUsers(options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        status,
        role,
        search,
        sortBy = 'createdAt',
        sortOrder = 'desc',
      } = options;

      const query = {};

      // Add filters
      if (status) query.status = status;
      if (role) query.role = role;
      if (search) {
        const searchRegex = new RegExp(search, 'i');
        query.$or = [
          { username: searchRegex },
          { email: searchRegex },
          { firstName: searchRegex },
          { lastName: searchRegex },
        ];
      }

      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      const [users, total] = await Promise.all([
        User.find(query)
          .select('username email firstName lastName role status createdAt lastLogin')
          .sort(sort)
          .skip(skip)
          .limit(limit),
        User.countDocuments(query),
      ]);

      const totalPages = Math.ceil(total / limit);

      return {
        users: users.map(user => ({
          id: user._id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          status: user.status,
          createdAt: user.createdAt,
          lastLogin: user.lastLogin,
        })),
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
      logger.error('Error getting all users', {
        error: error.message,
        options,
      });
      throw error;
    }
  }
}

module.exports = new UserService();


