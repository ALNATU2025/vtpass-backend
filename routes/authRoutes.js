// routes/authRoutes.js
// This file defines API endpoints for user authentication and links them to controller functions.

const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware'); // Import your authentication middleware

// Import authentication controller functions
const { registerUser, loginUser, getMe } = require('../controllers/authController');

// --- Define Authentication Routes ---

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', registerUser);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user & get token (Login)
 * @access  Public
 */
router.post('/login', loginUser);

/**
 * @route   GET /api/auth/me
 * @desc    Get user profile data
 * @access  Private (requires valid JWT token)
 */
router.get('/me', protect, getMe); // 'protect' middleware runs first, then 'getMe' controller

// Optional: A base route for /api/auth (can be removed if not needed)
router.get('/', (req, res) => {
    res.status(200).json({ message: 'Auth routes base endpoint reached. Available routes: /register, /login, /me' });
});

module.exports = router;
