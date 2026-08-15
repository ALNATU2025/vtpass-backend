// middleware/rbac.js - Complete RBAC Middleware
// COPY AND PASTE THIS ENTIRE FILE

/**
 * ROLE DEFINITIONS
 * 
 * ROLE HIERARCHY:
 * - super_admin  (Level 5) - Full system access
 * - admin        (Level 4) - Admin dashboard & management
 * - finance      (Level 3) - Financial operations, refunds, disputes
 * - support      (Level 2) - Customer support, user assistance
 * - user         (Level 0) - Basic user access
 */

const ROLE_DEFINITIONS = {
  super_admin: {
    level: 5,
    label: 'Super Administrator',
    description: 'Full system access with all permissions',
    permissions: ['*'],
    inherits: ['admin', 'finance', 'support', 'user']
  },
  admin: {
    level: 4,
    label: 'Administrator',
    description: 'Admin dashboard, user management, settings',
    permissions: [
      'view_dashboard', 'view_users', 'manage_users', 'view_transactions',
      'view_all_transactions', 'update_transaction_status', 'manage_admins',
      'manage_settings', 'view_reports', 'export_data', 'manage_notifications'
    ],
    inherits: ['finance', 'support']
  },
  finance: {
    level: 3,
    label: 'Finance Officer',
    description: 'Financial operations, refunds, disputes',
    permissions: [
      'view_transactions', 'view_all_transactions', 'process_refunds',
      'view_disputes', 'resolve_disputes', 'view_reports',
      'view_financial_reports', 'manage_wallet'
    ],
    inherits: ['support']
  },
  support: {
    level: 2,
    label: 'Support Agent',
    description: 'Customer support, user assistance',
    permissions: [
      'view_users', 'view_transactions', 'view_disputes',
      'create_disputes', 'resolve_disputes', 'send_notifications',
      'update_user_status'
    ],
    inherits: ['user']
  },
  user: {
    level: 0,
    label: 'User',
    description: 'Basic user access',
    permissions: [
      'view_profile', 'update_profile', 'view_own_transactions',
      'make_transactions', 'create_own_disputes', 'view_own_disputes',
      'view_commission'
    ]
  }
};

/**
 * Check if user has a specific permission
 */
const hasPermission = (user, permission) => {
  if (!user) return false;
  
  // Super admin has all permissions
  if (user.isSuperAdmin || user.role === 'super_admin') {
    return true;
  }
  
  // Check user's permissions array (custom permissions)
  if (user.permissions && user.permissions.includes(permission)) {
    return true;
  }
  
  // Check role permissions
  const roleDef = ROLE_DEFINITIONS[user.role];
  if (roleDef && roleDef.permissions) {
    if (roleDef.permissions.includes('*')) return true;
    if (roleDef.permissions.includes(permission)) return true;
    
    // Check inherited permissions
    if (roleDef.inherits) {
      for (const inheritedRole of roleDef.inherits) {
        const inheritedDef = ROLE_DEFINITIONS[inheritedRole];
        if (inheritedDef && inheritedDef.permissions) {
          if (inheritedDef.permissions.includes('*')) return true;
          if (inheritedDef.permissions.includes(permission)) return true;
        }
      }
    }
  }
  
  // Backward compatibility
  if (user.isAdmin) {
    const adminPermissions = [
      'view_dashboard', 'view_users', 'manage_users', 'view_transactions',
      'view_all_transactions', 'update_transaction_status'
    ];
    if (adminPermissions.includes(permission)) return true;
  }
  
  return false;
};

/**
 * Middleware: Check if user has specific role
 */
const hasRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const userRole = req.user.role || 'user';
    
    // Super admin bypass
    if (req.user.isSuperAdmin || userRole === 'super_admin') {
      return next();
    }
    
    if (allowedRoles.includes(userRole) || allowedRoles.includes('*')) {
      return next();
    }
    
    return res.status(403).json({
      success: false,
      message: 'Access denied. Insufficient role privileges.',
      code: 'ROLE_ACCESS_DENIED',
      requiredRoles: allowedRoles,
      userRole: userRole
    });
  };
};

/**
 * Middleware: Check if user has specific permission
 */
const hasPermissionMiddleware = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    if (hasPermission(req.user, permission)) {
      return next();
    }
    
    return res.status(403).json({
      success: false,
      message: `Permission denied: ${permission} required`,
      code: 'PERMISSION_DENIED',
      requiredPermission: permission,
      userRole: req.user.role
    });
  };
};

/**
 * Middleware: Check if user has any of the specified permissions
 */
const hasAnyPermission = (permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    for (const permission of permissions) {
      if (hasPermission(req.user, permission)) {
        return next();
      }
    }
    
    return res.status(403).json({
      success: false,
      message: 'Access denied. Required permissions not met.',
      code: 'PERMISSION_DENIED',
      requiredPermissions: permissions,
      userRole: req.user.role
    });
  };
};

/**
 * Admin protect middleware (Enhanced)
 */
const adminProtect = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required',
      code: 'AUTH_REQUIRED'
    });
  }
  
  // Check if user has admin role or is super admin
  const isAdmin = req.user.isAdmin || 
                  req.user.role === 'admin' || 
                  req.user.role === 'super_admin' ||
                  req.user.isSuperAdmin;
  
  if (isAdmin) {
    return next();
  }
  
  // Check specific admin user ID (backward compatibility)
  const specificAdminUserId = process.env.SPECIFIC_ADMIN_USER_ID || "690088325ca99bed6ab8d4a5";
  if (req.user._id.toString() === specificAdminUserId) {
    return next();
  }
  
  return res.status(403).json({
    success: false,
    message: 'Admin access required',
    code: 'ADMIN_ACCESS_DENIED'
  });
};

// Export all
module.exports = {
  ROLE_DEFINITIONS,
  hasPermission,
  hasRole,
  hasPermissionMiddleware,
  hasAnyPermission,
  adminProtect
};
