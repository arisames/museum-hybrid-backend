const express = require("express");
const router = express.Router();
const { 
  registerUser, 
  loginUser, 
  getMe, 
  searchUsers, 
  updateProfile,
  changePassword,
  refreshAccessToken,
  logoutUser,
  getUserPermissions,
} = require("../controllers/userController");
const { 
  protect, 
  refreshToken, 
  logout, 
  authRateLimit 
} = require("../middleware/authMiddleware");
const { sanitizeAllInputs } = require("../utils/sanitize");
const { 
  validate, 
  userSchemas, 
  expressValidators, 
  handleValidationErrors 
} = require("../utils/validation");
const { 
  authorizeRoles, 
  requirePermissions, 
  requireOwnership 
} = require("../middleware/rbacMiddleware");
const { 
  loginLimiter,
  registrationRateLimit,
  searchRateLimit,
  passwordResetRateLimit,
  trackLoginAttempt,
  adminRateLimit
} = require("../middleware/rateLimitMiddleware");

// Apply input sanitization to all routes
router.use(sanitizeAllInputs);

// Public routes with validation and rate limiting
router.post(
  "/register", 
  registrationRateLimit, // 3 attempts per hour
  validate(userSchemas.register),
  registerUser
);

router.post(
  "/login", 
  loginLimiter, // Legacy rate limiter
  trackLoginAttempt, // Advanced login attempt tracking
  validate(userSchemas.login),
  loginUser
);

router.post(
  "/refresh",
  refreshToken,
  refreshAccessToken
);

// Protected routes - apply authentication middleware
router.use(protect);

router.get("/me", getMe);

router.get("/permissions", getUserPermissions);

router.post(
  "/logout",
  logout,
  logoutUser
);

router.get(
  "/search", 
  searchRateLimit, // 30 requests per minute
  requirePermissions('read:user_profiles'),
  validate(userSchemas.search, 'query'),
  searchUsers
);

router.put(
  "/profile",
  requirePermissions('update:own_profile'),
  validate(userSchemas.updateProfile),
  updateProfile
);

router.put(
  "/password",
  passwordResetRateLimit, // 3 attempts per hour
  requirePermissions('update:own_profile'),
  validate(userSchemas.changePassword),
  changePassword
);

// Admin-only routes with admin rate limiting
router.use("/admin", adminRateLimit); // Role-based rate limiting for admin endpoints

router.get(
  "/admin/users",
  authorizeRoles("admin", "superadmin"),
  (req, res) => {
    res.json({ message: "Admin users endpoint - to be implemented" });
  }
);

router.put(
  "/admin/users/:id/role",
  authorizeRoles("admin", "superadmin"),
  requirePermissions('manage:roles'),
  (req, res) => {
    res.json({ message: "Update user role endpoint - to be implemented" });
  }
);

router.put(
  "/admin/users/:id/status",
  authorizeRoles("admin", "moderator", "superadmin"),
  requirePermissions('suspend:users'),
  (req, res) => {
    res.json({ message: "Update user status endpoint - to be implemented" });
  }
);

module.exports = router;


