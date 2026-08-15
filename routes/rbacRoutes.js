// routes/rbacRoutes.js - Single RBAC Endpoint
// COPY AND PASTE THIS ENTIRE FILE

const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { hasPermission, ROLE_DEFINITIONS, adminProtect } = require('../middleware/rbac');

/**
 * @route   POST /api/rbac
 * @desc    Unified RBAC endpoint - Single endpoint for all role/permission operations
 * @access  Private
 * 
 * OPERATIONS:
 * 1. get_roles - Get all roles and their permissions (Admin+)
 * 2. get_role - Get specific role details (Admin+)
 * 3. assign_role - Assign role to user (Super Admin only)
 * 4. remove_role - Remove role from user (Super Admin only)
 * 5. get_user_role - Get user's role and permissions (Self/Admin)
 * 6. check_permission - Check if user has permission (Self/Admin)
 * 7. get_users_by_role - Get all users with specific role (Admin+)
 * 8. update_permissions - Update user permissions (Super Admin only)
 * 9. get_available_permissions - Get all available permissions (Admin+)
 * 10. get_role_stats - Get role statistics (Admin+)
 * 11. can_access - Check if user can access resource (Self/Admin)
 */
router.post('/', [
  body('operation').isString().notEmpty().withMessage('Operation is required'),
  body('targetUserId').optional().isString().withMessage('Invalid user ID'),
  body('role').optional().isString().withMessage('Invalid role'),
  body('permissions').optional().isArray().withMessage('Permissions must be an array'),
  body('resource').optional().isString().withMessage('Invalid resource'),
  body('action').optional().isString().withMessage('Invalid action'),
  body('checkPermission').optional().isString().withMessage('Invalid permission'),
  body('resourceId').optional().isString().withMessage('Invalid resource ID')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: errors.array()[0].msg,
      errors: errors.array()
    });
  }

  try {
    const { 
      operation, 
      targetUserId, 
      role, 
      permissions, 
      resource, 
      action,
      checkPermission,
      resourceId
    } = req.body;
    
    const currentUser = req.user;

    // Helper: Check if user is admin
    const isAdmin = currentUser.isAdmin || 
                    currentUser.role === 'admin' || 
                    currentUser.role === 'super_admin' ||
                    currentUser.isSuperAdmin;

    // Helper: Check if user is super admin
    const isSuperAdmin = currentUser.isSuperAdmin || currentUser.role === 'super_admin';

    // ================================================
    // OPERATION 1: Get all roles
    // ================================================
    if (operation === 'get_roles') {
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Admin access required to view roles',
          code: 'ADMIN_ACCESS_DENIED'
        });
      }

      const roles = Object.entries(ROLE_DEFINITIONS).map(([key, value]) => ({
        role: key,
        label: value.label,
        description: value.description,
        level: value.level,
        permissions: value.permissions,
        inherits: value.inherits || [],
        count: 0
      }));

      // Get count for each role
      for (const roleItem of roles) {
        const count = await User.countDocuments({
          $or: [
            { role: roleItem.role },
            { isAdmin: roleItem.role === 'admin' || roleItem.role === 'super_admin' }
          ]
        });
        roleItem.count = count;
      }

      return res.json({
        success: true,
        data: {
          roles,
          totalUsers: await User.countDocuments(),
          timestamp: new Date().toISOString()
        }
      });
    }

    // ================================================
    // OPERATION 2: Get specific role details
    // ================================================
    if (operation === 'get_role') {
      if (!role) {
        return res.status(400).json({
          success: false,
          message: 'Role is required for get_role operation',
          code: 'ROLE_REQUIRED'
        });
      }

      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Admin access required to view role details',
          code: 'ADMIN_ACCESS_DENIED'
        });
      }

      const roleDef = ROLE_DEFINITIONS[role];
      if (!roleDef) {
        return res.status(404).json({
          success: false,
          message: `Role '${role}' not found`,
          code: 'ROLE_NOT_FOUND'
        });
      }

      const users = await User.find({
        $or: [
          { role: role },
          { isAdmin: role === 'admin' || role === 'super_admin' }
        ]
      }).select('_id fullName email phone createdAt isActive');

      return res.json({
        success: true,
        data: {
          role,
          label: roleDef.label,
          description: roleDef.description,
          level: roleDef.level,
          permissions: roleDef.permissions,
          inherits: roleDef.inherits || [],
          users: users,
          userCount: users.length
        }
      });
    }

    // ================================================
    // OPERATION 3: Assign role to user
    // ================================================
    if (operation === 'assign_role') {
      if (!isSuperAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Only Super Admin can assign roles',
          code: 'SUPER_ADMIN_REQUIRED'
        });
      }

      if (!targetUserId) {
        return res.status(400).json({
          success: false,
          message: 'targetUserId is required',
          code: 'TARGET_USER_REQUIRED'
        });
      }

      if (!role) {
        return res.status(400).json({
          success: false,
          message: 'Role is required',
          code: 'ROLE_REQUIRED'
        });
      }

      if (!ROLE_DEFINITIONS[role]) {
        return res.status(400).json({
          success: false,
          message: `Invalid role: ${role}`,
          code: 'INVALID_ROLE'
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'Target user not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Cannot modify super admin
      if (targetUser.isSuperAdmin || targetUser.role === 'super_admin') {
        return res.status(403).json({
          success: false,
          message: 'Cannot modify Super Admin role',
          code: 'CANNOT_MODIFY_SUPER_ADMIN'
        });
      }

      // Update user role
      const roleDef = ROLE_DEFINITIONS[role];
      targetUser.role = role;
      targetUser.isAdmin = (role === 'admin' || role === 'super_admin');
      targetUser.isSuperAdmin = (role === 'super_admin');
      targetUser.roleLevel = roleDef.level;
      targetUser.assignedBy = currentUser._id;
      targetUser.roleChangedAt = new Date();
      targetUser.permissions = roleDef.permissions || [];
      
      await targetUser.save();

      console.log(`✅ Role assigned: ${targetUser.email} → ${role} (by ${currentUser.email})`);

      return res.json({
        success: true,
        message: `User assigned to ${role} successfully`,
        data: {
          userId: targetUser._id,
          email: targetUser.email,
          fullName: targetUser.fullName,
          role: targetUser.role,
          isAdmin: targetUser.isAdmin,
          isSuperAdmin: targetUser.isSuperAdmin,
          permissions: targetUser.permissions,
          assignedBy: currentUser._id,
          assignedAt: targetUser.roleChangedAt
        }
      });
    }

    // ================================================
    // OPERATION 4: Remove role from user
    // ================================================
    if (operation === 'remove_role') {
      if (!isSuperAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Only Super Admin can remove roles',
          code: 'SUPER_ADMIN_REQUIRED'
        });
      }

      if (!targetUserId) {
        return res.status(400).json({
          success: false,
          message: 'targetUserId is required',
          code: 'TARGET_USER_REQUIRED'
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'Target user not found',
          code: 'USER_NOT_FOUND'
        });
      }

      // Cannot modify super admin
      if (targetUser.isSuperAdmin || targetUser.role === 'super_admin') {
        return res.status(403).json({
          success: false,
          message: 'Cannot modify Super Admin role',
          code: 'CANNOT_MODIFY_SUPER_ADMIN'
        });
      }

      // Cannot remove own role
      if (targetUser._id.toString() === currentUser._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'Cannot remove your own role',
          code: 'CANNOT_REMOVE_OWN_ROLE'
        });
      }

      // Reset to user
      const userRoleDef = ROLE_DEFINITIONS.user;
      targetUser.role = 'user';
      targetUser.isAdmin = false;
      targetUser.isSuperAdmin = false;
      targetUser.roleLevel = 0;
      targetUser.permissions = userRoleDef.permissions || [];
      targetUser.assignedBy = currentUser._id;
      targetUser.roleChangedAt = new Date();
      
      await targetUser.save();

      console.log(`✅ Role removed: ${targetUser.email} → user (by ${currentUser.email})`);

      return res.json({
        success: true,
        message: `Role removed from user successfully`,
        data: {
          userId: targetUser._id,
          email: targetUser.email,
          fullName: targetUser.fullName,
          role: targetUser.role,
          isAdmin: targetUser.isAdmin,
          isSuperAdmin: targetUser.isSuperAdmin
        }
      });
    }

    // ================================================
    // OPERATION 5: Get user's role and permissions
    // ================================================
    if (operation === 'get_user_role') {
      const userId = targetUserId || currentUser._id;
      
      // Users can only view their own role unless admin
      if (userId.toString() !== currentUser._id.toString() && !isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. You can only view your own role.',
          code: 'ACCESS_DENIED'
        });
      }

      const user = await User.findById(userId).select('-password -transactionPin');
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      const roleDef = ROLE_DEFINITIONS[user.role] || ROLE_DEFINITIONS.user;

      return res.json({
        success: true,
        data: {
          userId: user._id,
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          roleLevel: user.roleLevel || 0,
          isAdmin: user.isAdmin,
          isSuperAdmin: user.isSuperAdmin,
          roleLabel: roleDef.label,
          roleDescription: roleDef.description,
          permissions: user.permissions || [],
          allPermissions: roleDef.permissions || [],
          inheritedPermissions: roleDef.inherits || [],
          department: user.department || 'none',
          roleChangedAt: user.roleChangedAt
        }
      });
    }

    // ================================================
    // OPERATION 6: Check if user has permission
    // ================================================
    if (operation === 'check_permission') {
      if (!checkPermission) {
        return res.status(400).json({
          success: false,
          message: 'Permission to check is required',
          code: 'PERMISSION_REQUIRED'
        });
      }

      const userId = targetUserId || currentUser._id;
      
      if (userId.toString() !== currentUser._id.toString() && !isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. You can only check your own permissions.',
          code: 'ACCESS_DENIED'
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      const hasPerm = hasPermission(user, checkPermission);

      return res.json({
        success: true,
        data: {
          userId: user._id,
          email: user.email,
          permission: checkPermission,
          hasPermission: hasPerm,
          role: user.role,
          isAdmin: user.isAdmin,
          isSuperAdmin: user.isSuperAdmin
        }
      });
    }

    // ================================================
    // OPERATION 7: Get users by role
    // ================================================
    if (operation === 'get_users_by_role') {
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Admin access required',
          code: 'ADMIN_ACCESS_DENIED'
        });
      }

      let query = {};
      if (role) {
        query = {
          $or: [
            { role: role },
            { isAdmin: role === 'admin' || role === 'super_admin' }
          ]
        };
      }

      const users = await User.find(query)
        .select('_id fullName email phone role isAdmin isSuperAdmin isActive createdAt')
        .sort({ createdAt: -1 });

      return res.json({
        success: true,
        data: {
          users,
          count: users.length,
          role: role || 'all'
        }
      });
    }

    // ================================================
    // OPERATION 8: Update user permissions
    // ================================================
    if (operation === 'update_permissions') {
      if (!isSuperAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Only Super Admin can update permissions',
          code: 'SUPER_ADMIN_REQUIRED'
        });
      }

      if (!targetUserId) {
        return res.status(400).json({
          success: false,
          message: 'targetUserId is required',
          code: 'TARGET_USER_REQUIRED'
        });
      }

      if (!permissions || !Array.isArray(permissions)) {
        return res.status(400).json({
          success: false,
          message: 'Permissions array is required',
          code: 'PERMISSIONS_REQUIRED'
        });
      }

      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({
          success: false,
          message: 'Target user not found',
          code: 'USER_NOT_FOUND'
        });
      }

      if (targetUser.isSuperAdmin || targetUser.role === 'super_admin') {
        return res.status(403).json({
          success: false,
          message: 'Cannot modify Super Admin permissions',
          code: 'CANNOT_MODIFY_SUPER_ADMIN'
        });
      }

      targetUser.permissions = permissions;
      targetUser.assignedBy = currentUser._id;
      await targetUser.save();

      return res.json({
        success: true,
        message: 'Permissions updated successfully',
        data: {
          userId: targetUser._id,
          email: targetUser.email,
          permissions: targetUser.permissions
        }
      });
    }

    // ================================================
    // OPERATION 9: Get all available permissions
    // ================================================
    if (operation === 'get_available_permissions') {
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Admin access required',
          code: 'ADMIN_ACCESS_DENIED'
        });
      }

      const allPermissions = new Set();
      const rolePermissions = {};

      for (const [roleKey, roleDef] of Object.entries(ROLE_DEFINITIONS)) {
        rolePermissions[roleKey] = {
          permissions: roleDef.permissions || [],
          inherits: roleDef.inherits || []
        };
        (roleDef.permissions || []).forEach(p => allPermissions.add(p));
      }

      return res.json({
        success: true,
        data: {
          allPermissions: Array.from(allPermissions).sort(),
          rolePermissions,
          totalPermissions: allPermissions.size,
          roles: Object.keys(ROLE_DEFINITIONS)
        }
      });
    }

    // ================================================
    // OPERATION 10: Get role statistics
    // ================================================
    if (operation === 'get_role_stats') {
      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Admin access required',
          code: 'ADMIN_ACCESS_DENIED'
        });
      }

      const stats = {
        totalUsers: await User.countDocuments(),
        activeUsers: await User.countDocuments({ isActive: true }),
        byRole: {},
        byDepartment: {},
        recentAssignments: []
      };

      for (const [roleKey] of Object.entries(ROLE_DEFINITIONS)) {
        const count = await User.countDocuments({
          $or: [
            { role: roleKey },
            { isAdmin: roleKey === 'admin' || roleKey === 'super_admin' }
          ]
        });
        stats.byRole[roleKey] = count;
      }

      const departments = ['management', 'support', 'finance', 'operations', 'development', 'none'];
      for (const dept of departments) {
        const count = await User.countDocuments({ department: dept });
        stats.byDepartment[dept] = count;
      }

      stats.recentAssignments = await User.find({
        roleChangedAt: { $exists: true }
      })
        .select('_id fullName email role roleChangedAt assignedBy')
        .sort({ roleChangedAt: -1 })
        .limit(10);

      return res.json({
        success: true,
        data: stats
      });
    }

    // ================================================
    // OPERATION 11: Check resource access
    // ================================================
    if (operation === 'can_access') {
      if (!resource || !action) {
        return res.status(400).json({
          success: false,
          message: 'resource and action are required',
          code: 'RESOURCE_ACTION_REQUIRED'
        });
      }

      const userId = targetUserId || currentUser._id;
      
      if (userId.toString() !== currentUser._id.toString() && !isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. You can only check your own access.',
          code: 'ACCESS_DENIED'
        });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      const permissionMap = {
        'transactions:view': 'view_transactions',
        'transactions:view_all': 'view_all_transactions',
        'transactions:update': 'update_transaction_status',
        'users:view': 'view_users',
        'users:manage': 'manage_users',
        'users:update_status': 'update_user_status',
        'refunds:process': 'process_refunds',
        'disputes:view': 'view_disputes',
        'disputes:resolve': 'resolve_disputes',
        'notifications:send': 'send_notifications',
        'settings:manage': 'manage_settings',
        'reports:view': 'view_reports',
        'wallet:manage': 'manage_wallet'
      };

      const permission = permissionMap[`${resource}:${action}`];
      if (!permission) {
        return res.status(400).json({
          success: false,
          message: `Unknown resource:action mapping: ${resource}:${action}`,
          code: 'UNKNOWN_PERMISSION_MAPPING'
        });
      }

      const hasPerm = hasPermission(user, permission);

      return res.json({
        success: true,
        data: {
          userId: user._id,
          email: user.email,
          resource,
          action,
          permission,
          hasAccess: hasPerm,
          role: user.role,
          isAdmin: user.isAdmin
        }
      });
    }

    // ================================================
    // Unknown operation
    // ================================================
    return res.status(400).json({
      success: false,
      message: `Unknown operation: ${operation}`,
      code: 'UNKNOWN_OPERATION',
      availableOperations: [
        'get_roles',
        'get_role',
        'assign_role',
        'remove_role',
        'get_user_role',
        'check_permission',
        'get_users_by_role',
        'update_permissions',
        'get_available_permissions',
        'get_role_stats',
        'can_access'
      ]
    });

  } catch (error) {
    console.error('❌ RBAC API Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
      code: 'INTERNAL_ERROR',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;
