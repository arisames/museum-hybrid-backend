const { asyncHandler } = require("../middleware/errorMiddleware");
const { sanitizeContent } = require("../utils/sanitize");
const { BadRequestError, ValidationError } = require("../utils/CustomError");
const userService = require("../services/userService");
const logger = require("../utils/logger");

// @desc    Register new user
// @route   POST /api/users/register
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { username, email, password, firstName, lastName } = req.body;

    // Validate required fields
    if (!username || !email || !password || !firstName || !lastName) {
      throw new ValidationError('All fields are required', {
        required: ['username', 'email', 'password', 'firstName', 'lastName'],
        provided: Object.keys(req.body),
      });
    }

    // Sanitize inputs
    const sanitizedData = sanitizeContent.userProfile({
      username,
      email,
      firstName,
      lastName,
    });

    // Password complexity validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\]:",.<>/?]).{8,}$/;
    if (!passwordRegex.test(password)) {
      throw new ValidationError(
        "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
        { field: 'password', requirements: 'Strong password required' }
      );
    }

    // Additional validation
    if (sanitizedData.username.length < 3 || sanitizedData.username.length > 30) {
      throw new ValidationError('Username must be between 3 and 30 characters', {
        field: 'username',
        length: sanitizedData.username.length,
      });
    }

    const { user, accessToken, refreshToken } = await userService.registerUser(
      sanitizedData.username,
      sanitizedData.email,
      password,
      sanitizedData.firstName,
      sanitizedData.lastName
    );

    // Log successful registration
    logger.info('User registered successfully', {
      userId: user.id,
      username: user.username,
      email: user.email,
      requestId: req.requestId,
    });

    res.status(201).json({
      success: true,
      data: {
        _id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    logger.logPerformance('registerUser', Date.now() - startTime, {
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      throw new ValidationError('Email and password are required', {
        required: ['email', 'password'],
        provided: Object.keys(req.body),
      });
    }

    // Sanitize inputs
    const sanitizedEmail = sanitizeContent.userProfile({ email }).email;

    const { user, accessToken, refreshToken } = await userService.loginUser(
      sanitizedEmail,
      password
    );

    // Log successful login
    logger.info('User logged in successfully', {
      userId: user.id,
      username: user.username,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
    });

    res.json({
      success: true,
      data: {
        _id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    // Log failed login attempt
    logger.logSecurity('LOGIN_FAILED', {
      email: req.body.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      error: error.message,
      requestId: req.requestId,
    });
    
    logger.logPerformance('loginUser', Date.now() - startTime, {
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Get user data
// @route   GET /api/users/me
// @access  Private
const getMe = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const user = await userService.getUserById(req.user.id);
    
    logger.logPerformance('getMe', Date.now() - startTime, {
      userId: req.user.id,
      success: true,
    });

    res.status(200).json({
      success: true,
      data: {
        _id: user.id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (error) {
    logger.logPerformance('getMe', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Search for users by username or email
// @route   GET /api/users/search
// @access  Private
const searchUsers = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { q: query, page = 1, limit = 10 } = req.query;

    // Validate query parameter
    if (!query || query.trim().length < 2) {
      throw new ValidationError('Search query must be at least 2 characters long', {
        field: 'q',
        minLength: 2,
        provided: query ? query.length : 0,
      });
    }

    // Sanitize and validate pagination
    const sanitizedQuery = sanitizeContent.search({ q: query }).q;
    const pageNum = Math.max(1, parseInt(page) || 1);
    const limitNum = Math.min(50, Math.max(1, parseInt(limit) || 10));

    const { users, total, totalPages } = await userService.searchUsers(
      sanitizedQuery,
      pageNum,
      limitNum
    );

    logger.logPerformance('searchUsers', Date.now() - startTime, {
      query: sanitizedQuery,
      resultsCount: users.length,
      page: pageNum,
      limit: limitNum,
      userId: req.user.id,
    });

    res.status(200).json({
      success: true,
      data: {
        users: users.map(user => ({
          _id: user.id,
          username: user.username,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        })),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total,
          totalPages,
          hasNext: pageNum < totalPages,
          hasPrev: pageNum > 1,
        },
      },
    });
  } catch (error) {
    logger.logPerformance('searchUsers', Date.now() - startTime, {
      success: false,
      error: error.message,
      userId: req.user.id,
    });
    throw error;
  }
});

// @desc    Update user profile
// @route   PUT /api/users/profile
// @access  Private
const updateProfile = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { firstName, lastName, bio, location, website } = req.body;

    // Sanitize inputs
    const sanitizedData = sanitizeContent.userProfile({
      firstName,
      lastName,
      bio,
      location,
      website,
    });

    // Remove empty fields
    const updateData = Object.fromEntries(
      Object.entries(sanitizedData).filter(([_, value]) => value !== '' && value != null)
    );

    if (Object.keys(updateData).length === 0) {
      throw new ValidationError('At least one field must be provided for update');
    }

    const updatedUser = await userService.updateUserProfile(req.user.id, updateData);

    logger.info('User profile updated', {
      userId: req.user.id,
      updatedFields: Object.keys(updateData),
      requestId: req.requestId,
    });

    logger.logPerformance('updateProfile', Date.now() - startTime, {
      userId: req.user.id,
      success: true,
    });

    res.json({
      success: true,
      data: {
        _id: updatedUser.id,
        username: updatedUser.username,
        email: updatedUser.email,
        firstName: updatedUser.firstName,
        lastName: updatedUser.lastName,
        bio: updatedUser.bio,
        location: updatedUser.location,
        website: updatedUser.website,
        updatedAt: updatedUser.updatedAt,
      },
    });
  } catch (error) {
    logger.logPerformance('updateProfile', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Change user password
// @route   PUT /api/users/password
// @access  Private
const changePassword = asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    // Validate required fields
    if (!currentPassword || !newPassword || !confirmPassword) {
      throw new ValidationError('All password fields are required', {
        required: ['currentPassword', 'newPassword', 'confirmPassword'],
        provided: Object.keys(req.body),
      });
    }

    // Validate password confirmation
    if (newPassword !== confirmPassword) {
      throw new ValidationError('New password and confirmation do not match');
    }

    // Password complexity validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\]:",.<>/?]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      throw new ValidationError(
        "New password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
        { field: 'newPassword', requirements: 'Strong password required' }
      );
    }

    await userService.changePassword(req.user.id, currentPassword, newPassword);

    // Log password change
    logger.logSecurity('PASSWORD_CHANGED', {
      userId: req.user.id,
      username: req.user.username,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
    });

    logger.logPerformance('changePassword', Date.now() - startTime, {
      userId: req.user.id,
      success: true,
    });

    res.json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error) {
    logger.logSecurity('PASSWORD_CHANGE_FAILED', {
      userId: req.user.id,
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
    });

    logger.logPerformance('changePassword', Date.now() - startTime, {
      userId: req.user.id,
      success: false,
      error: error.message,
    });
    throw error;
  }
});

// @desc    Refresh access token
// @route   POST /api/users/refresh
// @access  Public
const refreshAccessToken = asyncHandler(async (req, res) => {
  // The refreshToken middleware has already validated the token and attached new tokens
  res.json({
    success: true,
    data: {
      accessToken: req.tokens.accessToken,
      refreshToken: req.tokens.refreshToken,
      user: {
        _id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        firstName: req.user.firstName,
        lastName: req.user.lastName,
        role: req.user.role,
      },
    },
  });
});

// @desc    Logout user
// @route   POST /api/users/logout
// @access  Private
const logoutUser = asyncHandler(async (req, res) => {
  // The logout middleware handles the actual logout logic
  res.json({
    success: true,
    message: 'Logged out successfully',
  });
});

// @desc    Get user permissions
// @route   GET /api/users/permissions
// @access  Private
const getUserPermissions = asyncHandler(async (req, res) => {
  const { getUserPermissions } = require("../middleware/rbacMiddleware");
  
  const permissions = getUserPermissions(req.user.role);
  
  res.json({
    success: true,
    data: {
      role: req.user.role,
      permissions,
    },
  });
});

module.exports = {
  registerUser,
  loginUser,
  getMe,
  searchUsers,
  updateProfile,
  changePassword,
  refreshAccessToken,
  logoutUser,
  getUserPermissions,
};

