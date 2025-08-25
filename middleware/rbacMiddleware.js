const { ForbiddenError, UnauthorizedError } = require("../utils/CustomError");
const logger = require("../utils/logger");

// Define role hierarchy (higher number = more permissions)
const ROLE_HIERARCHY = {
  user: 1,
  moderator: 2,
  admin: 3,
  superadmin: 4,
};

// Define permissions for each role
const ROLE_PERMISSIONS = {
  user: [
    'read:own_profile',
    'update:own_profile',
    'read:messages',
    'create:messages',
    'update:own_messages',
    'delete:own_messages',
    'read:public_content',
  ],
  moderator: [
    'read:own_profile',
    'update:own_profile',
    'read:messages',
    'create:messages',
    'update:own_messages',
    'delete:own_messages',
    'read:public_content',
    'moderate:content',
    'read:user_profiles',
    'suspend:users',
    'delete:inappropriate_content',
  ],
  admin: [
    'read:own_profile',
    'update:own_profile',
    'read:messages',
    'create:messages',
    'update:own_messages',
    'delete:own_messages',
    'read:public_content',
    'moderate:content',
    'read:user_profiles',
    'suspend:users',
    'delete:inappropriate_content',
    'manage:users',
    'read:all_messages',
    'update:any_profile',
    'delete:any_content',
    'access:admin_panel',
    'manage:roles',
  ],
  superadmin: [
    '*', // All permissions
  ],
};

// Resource ownership patterns
const OWNERSHIP_PATTERNS = {
  '/api/users/:id': (req) => req.user.id === req.params.id,
  '/api/messages/:id': async (req) => {
    // This would need to check if the message belongs to the user
    // Implementation depends on your message model
    return true; // Placeholder
  },
  '/api/profile/:id': (req) => req.user.id === req.params.id,
};

// Basic role authorization middleware
const authorizeRoles = (...roles) => (req, res, next) => {
  if (!req.user || !req.user.role) {
    logger.logSecurity('RBAC_NO_USER_OR_ROLE', {
      ip: req.ip,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new ForbiddenError("Authentication required to access this resource");
  }

  if (!roles.includes(req.user.role)) {
    logger.logSecurity('RBAC_ROLE_ACCESS_DENIED', {
      userId: req.user.id,
      userRole: req.user.role,
      requiredRoles: roles,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new ForbiddenError(`Access denied. Required roles: ${roles.join(', ')}`);
  }

  logger.debug('Role authorization successful', {
    userId: req.user.id,
    userRole: req.user.role,
    requiredRoles: roles,
    requestId: req.requestId,
  });

  next();
};

// Minimum role level authorization
const requireMinimumRole = (minimumRole) => (req, res, next) => {
  if (!req.user || !req.user.role) {
    throw new ForbiddenError("Authentication required to access this resource");
  }

  const userRoleLevel = ROLE_HIERARCHY[req.user.role] || 0;
  const requiredRoleLevel = ROLE_HIERARCHY[minimumRole] || 0;

  if (userRoleLevel < requiredRoleLevel) {
    logger.logSecurity('RBAC_INSUFFICIENT_ROLE_LEVEL', {
      userId: req.user.id,
      userRole: req.user.role,
      userRoleLevel,
      minimumRole,
      requiredRoleLevel,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });
    throw new ForbiddenError(`Access denied. Minimum role required: ${minimumRole}`);
  }

  next();
};

// Permission-based authorization
const requirePermissions = (...permissions) => (req, res, next) => {
  if (!req.user || !req.user.role) {
    throw new ForbiddenError("Authentication required to access this resource");
  }

  const userPermissions = ROLE_PERMISSIONS[req.user.role] || [];
  
  // Superadmin has all permissions
  if (userPermissions.includes('*')) {
    return next();
  }

  // Check if user has all required permissions
  const hasAllPermissions = permissions.every(permission => 
    userPermissions.includes(permission)
  );

  if (!hasAllPermissions) {
    const missingPermissions = permissions.filter(permission => 
      !userPermissions.includes(permission)
    );

    logger.logSecurity('RBAC_INSUFFICIENT_PERMISSIONS', {
      userId: req.user.id,
      userRole: req.user.role,
      userPermissions,
      requiredPermissions: permissions,
      missingPermissions,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });

    throw new ForbiddenError(`Access denied. Missing permissions: ${missingPermissions.join(', ')}`);
  }

  next();
};

// Resource ownership authorization
const requireOwnership = (resourceType) => async (req, res, next) => {
  if (!req.user) {
    throw new UnauthorizedError("Authentication required");
  }

  // Admin can access any resource
  if (req.user.role === 'admin' || req.user.role === 'superadmin') {
    return next();
  }

  try {
    let isOwner = false;

    // Check ownership based on resource type
    switch (resourceType) {
      case 'profile':
        isOwner = req.user.id === (req.params.userId || req.params.id);
        break;
      
      case 'message':
        // This would need to query the database to check message ownership
        // For now, we'll use a simple check
        isOwner = req.user.id === req.params.senderId || req.user.id === req.params.recipientId;
        break;
      
      default:
        // Generic ownership check based on user ID in params
        isOwner = req.user.id === (req.params.userId || req.params.id);
    }

    if (!isOwner) {
      logger.logSecurity('RBAC_OWNERSHIP_ACCESS_DENIED', {
        userId: req.user.id,
        resourceType,
        resourceId: req.params.id || req.params.userId,
        url: req.originalUrl,
        method: req.method,
        requestId: req.requestId,
      });
      throw new ForbiddenError("Access denied. You can only access your own resources.");
    }

    next();
  } catch (error) {
    if (error instanceof ForbiddenError || error instanceof UnauthorizedError) {
      throw error;
    }
    
    logger.error('Error checking resource ownership', {
      error: error.message,
      userId: req.user.id,
      resourceType,
      requestId: req.requestId,
    });
    throw new ForbiddenError("Unable to verify resource ownership");
  }
};

// Dynamic role authorization based on context
const dynamicAuthorize = (options = {}) => async (req, res, next) => {
  if (!req.user) {
    throw new UnauthorizedError("Authentication required");
  }

  const {
    roles = [],
    permissions = [],
    allowOwner = false,
    resourceType = null,
    customCheck = null,
  } = options;

  try {
    // Check roles if specified
    if (roles.length > 0 && roles.includes(req.user.role)) {
      return next();
    }

    // Check permissions if specified
    if (permissions.length > 0) {
      const userPermissions = ROLE_PERMISSIONS[req.user.role] || [];
      if (userPermissions.includes('*') || permissions.every(p => userPermissions.includes(p))) {
        return next();
      }
    }

    // Check ownership if allowed
    if (allowOwner && resourceType) {
      const isOwner = await checkResourceOwnership(req, resourceType);
      if (isOwner) {
        return next();
      }
    }

    // Custom authorization check
    if (customCheck && typeof customCheck === 'function') {
      const customResult = await customCheck(req);
      if (customResult) {
        return next();
      }
    }

    // If none of the checks passed, deny access
    logger.logSecurity('RBAC_DYNAMIC_ACCESS_DENIED', {
      userId: req.user.id,
      userRole: req.user.role,
      options,
      url: req.originalUrl,
      method: req.method,
      requestId: req.requestId,
    });

    throw new ForbiddenError("Access denied based on authorization rules");
  } catch (error) {
    if (error instanceof ForbiddenError || error instanceof UnauthorizedError) {
      throw error;
    }
    
    logger.error('Error in dynamic authorization', {
      error: error.message,
      userId: req.user.id,
      options,
      requestId: req.requestId,
    });
    throw new ForbiddenError("Authorization check failed");
  }
};

// Helper function to check resource ownership
const checkResourceOwnership = async (req, resourceType) => {
  switch (resourceType) {
    case 'profile':
      return req.user.id === (req.params.userId || req.params.id);
    
    case 'message':
      // This would need database queries to check message ownership
      // Implementation depends on your message model structure
      return req.user.id === req.params.senderId || req.user.id === req.params.recipientId;
    
    default:
      return req.user.id === (req.params.userId || req.params.id);
  }
};

// Middleware to check if user can perform action on specific resource
const canPerformAction = (action, resourceType) => async (req, res, next) => {
  if (!req.user) {
    throw new UnauthorizedError("Authentication required");
  }

  const permission = `${action}:${resourceType}`;
  const userPermissions = ROLE_PERMISSIONS[req.user.role] || [];

  // Check if user has the specific permission
  if (userPermissions.includes('*') || userPermissions.includes(permission)) {
    return next();
  }

  // Check if user can perform action on their own resources
  const ownResourcePermission = `${action}:own_${resourceType}`;
  if (userPermissions.includes(ownResourcePermission)) {
    const isOwner = await checkResourceOwnership(req, resourceType);
    if (isOwner) {
      return next();
    }
  }

  logger.logSecurity('RBAC_ACTION_ACCESS_DENIED', {
    userId: req.user.id,
    userRole: req.user.role,
    action,
    resourceType,
    permission,
    url: req.originalUrl,
    method: req.method,
    requestId: req.requestId,
  });

  throw new ForbiddenError(`Access denied. Cannot ${action} ${resourceType}`);
};

// Get user permissions (utility function)
const getUserPermissions = (role) => {
  return ROLE_PERMISSIONS[role] || [];
};

// Check if user has specific permission (utility function)
const hasPermission = (userRole, permission) => {
  const permissions = ROLE_PERMISSIONS[userRole] || [];
  return permissions.includes('*') || permissions.includes(permission);
};

module.exports = {
  authorizeRoles,
  requireMinimumRole,
  requirePermissions,
  requireOwnership,
  dynamicAuthorize,
  canPerformAction,
  getUserPermissions,
  hasPermission,
  ROLE_HIERARCHY,
  ROLE_PERMISSIONS,
};


