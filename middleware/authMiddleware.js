// middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // <<< CORRECTED: Import from '../models/User'

/**
 * @desc    Protect routes - Authenticate user with JWT
 * @param   {object} req - Express request object
 * @param   {object} res - Express response object
 * @param   {function} next - Express next middleware function
 */
// middleware/authMiddleware.js - OPTIONAL ENHANCEMENT

const protect = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            
            // ✅ Try to verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // ✅ Check if token is about to expire (within 1 day)
            const tokenExp = decoded.exp * 1000;
            const now = Date.now();
            const timeToExpiry = tokenExp - now;
            const oneDayMs = 24 * 60 * 60 * 1000;

            const user = await User.findById(decoded.id).select('-password');
            
            if (!user) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }

            // ✅ Auto-extend token if close to expiry
            if (timeToExpiry < oneDayMs && timeToExpiry > 0) {
                const newToken = jwt.sign(
                    { id: user._id },
                    process.env.JWT_SECRET,
                    { expiresIn: '7d' }
                );
                res.set('x-new-token', newToken);
            }

            req.user = user;
            next();
            
        } catch (error) {
            console.error('❌ Auth middleware error:', error.message);
            
            // ✅ Handle expired token
            if (error.name === 'TokenExpiredError') {
                // Try to refresh using refresh token header
                const refreshToken = req.headers['x-refresh-token'];
                if (refreshToken) {
                    try {
                        const decodedRefresh = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
                        const user = await User.findById(decodedRefresh.id);
                        
                        if (user && user.refreshToken === refreshToken) {
                            const newToken = jwt.sign(
                                { id: user._id },
                                process.env.JWT_SECRET,
                                { expiresIn: '7d' }
                            );
                            const newRefreshToken = jwt.sign(
                                { id: user._id },
                                process.env.REFRESH_TOKEN_SECRET,
                                { expiresIn: '90d' }
                            );
                            
                            user.refreshToken = newRefreshToken;
                            await user.save();
                            
                            res.set('x-new-token', newToken);
                            res.set('x-new-refresh-token', newRefreshToken);
                            
                            req.user = user;
                            return next();
                        }
                    } catch (refreshError) {
                        console.error('❌ Refresh failed:', refreshError.message);
                    }
                }
                return res.status(401).json({ 
                    message: 'Not authorized, token expired',
                    code: 'TOKEN_EXPIRED'
                });
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
