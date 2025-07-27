// routes/userRoutes.js
const express = require('express');
const router = express.Router();

// Import all controller functions from the centralized userController
// This is where the actual logic for register, login, etc., resides.
const {
    registerUser,
    loginUser,
    getUserById,
    provisionExistingUserVirtualAccount,
    updateUserProfile,
    toggleUserStatus,
    changePassword,
    getAllUsers,
    getUserBalance,
} = require('../controllers/userController'); // <<< CORRECT: Import functions from controller

// Import middleware
const { protect, authorizeAdmin } = require('../middleware/authMiddleware');

console.log("📥 /api/users route file loaded");

// Public Auth Routes - These now call functions from userController
router.post('/register', registerUser);
router.post('/login', loginUser);

// User Profile & Virtual Account Routes (Require Authentication)
router.get('/:id', protect, getUserById);
router.post('/provision-virtual-account', protect, provisionExistingUserVirtualAccount);
router.post('/change-password', protect, changePassword);
router.post('/get-balance', protect, getUserBalance);

// Admin Routes (Require Authentication and Admin Authorization)
// Uncomment 'authorizeAdmin' once you have it implemented and tested.
router.put('/:id', protect, /* authorizeAdmin, */ updateUserProfile);
router.put('/toggle-status/:id', protect, /* authorizeAdmin, */ toggleUserStatus);
router.get('/', protect, /* authorizeAdmin, */ getAllUsers);


module.exports = router;
