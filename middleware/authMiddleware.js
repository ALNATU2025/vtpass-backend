// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // <<< CORRECTED: Import from '../models/User'
// const User = require('../models/userModel'); // <<< REMOVE OR COMMENT OUT THIS LINE IF IT EXISTS

/**
 * @desc    Protect routes - Authenticate user with JWT
 * @param   {object} req - Express request object
 * @param   {object} res - Express response object
 * @param   {function} next - Express next middleware function
 */
const protect = async (req, res, next) => {
    let token;

    // Check for token in headers (Bearer token)
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Get token from header
            token = req.headers.authorization.split(' ')[1];

            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // Attach user to the request (excluding password)
            req.user = await User.findById(decoded.id).select('-password');

            if (!req.user) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }

            next(); // Proceed to the next middleware/route handler
        } catch (error) {
            console.error('❌ Auth middleware error:', error.message);
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Not authorized, token expired' });
            }
            return res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        return res.status(401).json({ message: 'Not authorized, no token' });
    }
};

/**
 * @desc    Authorize user roles (e.g., admin only)
 * @param   {string[]} roles - Array of allowed roles (e.g., ['admin'])
 * @returns {function} Express middleware function
 */
const authorizeAdmin = (req, res, next) => {
    // Assuming req.user is populated by the 'protect' middleware
    if (req.user && req.user.isAdmin) {
        next(); // User is admin, proceed
    } else {
        res.status(403).json({ message: 'Not authorized as an admin' });
    }
};

module.exports = {
    protect,
    authorizeAdmin,
};
