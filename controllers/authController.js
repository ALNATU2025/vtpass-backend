// controllers/authController.js
// This file contains the core logic for user authentication.

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // For password hashing
const User = require('../models/userModel'); // Assuming your User model is here
const { sendEmail } = require('../utils/emailService'); // Import the email sending utility

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
            fullName,
            phone,
            email,
            password: hashedPassword,
            // walletBalance defaults to 0 as per your userModel
        });

        if (user) {
            // --- NEW: Send Welcome Email Automatically ---
            try {
                const subject = 'Welcome to DalabaPay!';
                const text = `Hello ${user.fullName},\n\nWelcome to DalaPay! We're excited to have you on board. You can now easily pay bills, buy airtime, and more.\n\nBest regards,\nThe DalaPay Team`;
                const html = `
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                            .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9; }
                            .header { background-color: #007bff; color: white; padding: 10px 20px; border-radius: 8px 8px 0 0; text-align: center; }
                            .content { padding: 20px; }
                            .footer { text-align: center; font-size: 0.9em; color: #777; margin-top: 20px; }
                            .button { display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
                            .highlight { font-weight: bold; color: #007bff; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h2>Welcome to DalabaPay!</h2>
                            </div>
                            <div class="content">
                                <p>Hello ${user.fullName},</p>
                                <p>We're thrilled to welcome you to the DalabaPay family! 🎉</p>
                                <p>With DalabaPay, you can conveniently manage all your digital payments in one place:</p>
                                <ul>
                                    <li>Effortless bill payments</li>
                                    <li>Instant airtime and data top-ups</li>
                                    <li>Seamless utility payments</li>
                                    <li>And much more!</li>
                                </ul>
                                <p>Start exploring our services today and experience the ease of DalabaPay.</p>
                                <p>If you have any questions or need assistance, our support team is always here to help.</p>
                                <p>Best regards,<br>The DalaPay Team</p>
                            </div>
                            <div class="footer">
                                <p>&copy; ${new Date().getFullYear()} DalaPay. All rights reserved.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                `;
                await sendEmail(user.email, subject, text, html);
                console.log(`Welcome email sent to ${user.email} after registration.`);
            } catch (emailError) {
                console.error(`Failed to send welcome email to ${user.email}:`, emailError.message);
                // Important: Do NOT return an error here, as user registration was successful.
                // Just log the email sending failure.
            }
            // --- End New Email Logic ---

            res.status(201).json({
                _id: user.id,
                fullName: user.fullName,
                phone: user.phone,
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
        if (user && (await user.matchPassword(password))) {
            res.json({
                _id: user.id,
                fullName: user.fullName,
                phone: user.phone,
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
            fullName: req.user.fullName,
            phone: req.user.phone,
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
