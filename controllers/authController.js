// controllers/authController.js
// This file contains the core logic for user authentication.

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // For password hashing
const User = require('../models/userModel'); // Assuming your User model is here

// Helper function to generate a JWT token
const generateToken = (id) => {
    // JWT_SECRET must be set in your environment variables (.env locally, Render dashboard for deployment)
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        console.error('ERROR: JWT_SECRET environment variable is not set!');
        // In a real app, you might want to throw a more critical error or handle this differently.
        throw new Error('JWT secret is not configured.');
    }
    return jwt.sign({ id }, jwtSecret, {
        expiresIn: '30d', // Token expires in 30 days
    });
};

/**
 * @desc    Register a new user
 * @route   POST /api/auth/register
 * @access  Public
 */
const registerUser = async (req, res) => {
    // Destructure fullName and phone instead of username
    const { fullName, phone, email, password } = req.body;

    // Basic validation: Check for all required fields
    if (!fullName || !phone || !email || !password) {
        return res.status(400).json({ message: 'Please enter all required fields: Full Name, Phone, Email, and Password' });
    }

    try {
        // Check if user with this email already exists
        const userExistsByEmail = await User.findOne({ email });
        if (userExistsByEmail) {
            return res.status(400).json({ message: 'User with this email already exists' });
        }

        // Check if user with this phone number already exists
        const userExistsByPhone = await User.findOne({ phone });
        if (userExistsByPhone) {
            return res.status(400).json({ message: 'User with this phone number already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10); // Generate a salt with 10 rounds
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user with fullName and phone
        const user = await User.create({
            fullName, // Using fullName
            phone,    // Using phone
            email,
            password: hashedPassword,
            // walletBalance defaults to 0 as per your userModel
        });

        if (user) {
            res.status(201).json({
                _id: user.id,
                fullName: user.fullName, // Return fullName
                phone: user.phone,       // Return phone
                email: user.email,
                token: generateToken(user._id),
                message: 'User registered successfully'
            });
        } else {
            res.status(400).json({ message: 'Invalid user data provided' });
        }
    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).json({ message: 'Server error during registration', error: error.message });
    }
};

/**
 * @desc    Authenticate user & get token (Login)
 * @route   POST /api/auth/login
 * @access  Public
 */
const loginUser = async (req, res) => {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
        return res.status(400).json({ message: 'Please enter email and password' });
    }

    try {
        // Check for user email
        const user = await User.findOne({ email });

        // Check password using the matchPassword method from the User model instance
        if (user && (await user.matchPassword(password))) { // THIS IS THE LINE THAT NEEDS THE METHOD IN USERMODEL
            res.json({
                _id: user.id,
                fullName: user.fullName, // Return fullName
                phone: user.phone,       // Return phone
                email: user.email,
                token: generateToken(user._id),
                message: 'Logged in successfully'
            });
        } else {
            res.status(400).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
};

/**
 * @desc    Get user profile data
 * @route   GET /api/auth/me
 * @access  Private (requires authentication)
 */
const getMe = async (req, res) => {
    // The 'protect' middleware adds the user object to the request (req.user)
    // We select '-password' in the middleware, so password is not exposed.
    if (req.user) {
        res.status(200).json({
            _id: req.user.id,
            fullName: req.user.fullName, // Return fullName
            phone: req.user.phone,       // Return phone
            email: req.user.email,
            walletBalance: req.user.walletBalance, // Assuming walletBalance is on the user object
        });
    } else {
        // This case should ideally not be hit if 'protect' middleware is working correctly
        res.status(401).json({ message: 'Not authorized, user data not found' });
    }
};

module.exports = {
    registerUser,
    loginUser,
    getMe,
};
