// controllers/userController.js
const User = require('../models/User'); // Ensure correct path to your User model
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Needed for password hashing if not handled by pre-save hook
const { sendEmail } = require('../utils/emailService'); // Assuming this utility exists
const { provisionDedicatedAccount } = require('./paystackController'); // Import Paystack provisioning

// Helper function to generate a JWT token
const generateToken = (id) => {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        console.error('ERROR: JWT_SECRET environment variable is not set!');
        throw new Error('JWT secret is not configured.');
    }
    return jwt.sign({ id }, jwtSecret, {
        expiresIn: '30d', // Token expires in 30 days
    });
};

/**
 * @desc    Register a new user
 * @route   POST /api/users/register
 * @access  Public
 */
const registerUser = async (req, res) => {
    const { fullName, email, password, phone } = req.body;

    // Basic validation: Check for all required fields
    if (!fullName || !phone || !email || !password) {
        return res.status(400).json({ message: 'Please enter all required fields: Full Name, Phone, Email, and Password' });
    }

    try {
        // Check if user with given email or phone already exists
        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(400).json({ message: 'User with this email already exists' });
            } else {
                return res.status(400).json({ message: 'User with this phone number already exists' });
            }
        }

        // Hash password (if not already handled by a pre-save hook in your User model)
        // If your User model has a pre-save hook for hashing, you can remove this block.
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create new user
        const user = await User.create({
            fullName,
            phone,
            email,
            password: hashedPassword, // Use the hashed password
            // walletBalance, isAdmin, isActive will use their default values from schema
        });

        if (user) {
            // --- NEW: Provision dedicated account after user is saved ---
            try {
                const accountDetails = await provisionDedicatedAccount(user._id, user.email, user.fullName);
                console.log(`Dedicated account assigned to new user ${user.email}: ${accountDetails.accountNumber}`);
                // Update the user object in memory for the response, though it's already in DB
                user.virtualAccount = accountDetails;
            } catch (accountError) {
                console.error(`Failed to provision dedicated account for new user ${user.email}:`, accountError.message);
                // Log the error but do NOT prevent user registration from completing.
            }

            // --- Send Welcome Email Automatically ---
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
            }
            // --- End New Email Logic ---

            res.status(201).json({
                token: generateToken(user._id),
                user: {
                    _id: user._id,
                    fullName: user.fullName,
                    email: user.email,
                    phone: user.phone, // Include phone
                    walletBalance: user.walletBalance,
                    isAdmin: user.isAdmin, // Include isAdmin
                    isActive: user.isActive, // Include isActive
                    virtualAccount: user.virtualAccount, // Include virtual account details
                },
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
 * @route   POST /api/users/login
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
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Compare the provided password with the hashed password using the schema method
        const isMatch = await user.matchPassword(password); // Assumes matchPassword method exists on User model
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token for the logged-in user
        const token = generateToken(user._id);

        // Respond with the token and full user details
        res.status(200).json({
            token,
            user: {
                _id: user._id,
                fullName: user.fullName,
                email: user.email,
                phone: user.phone, // Include phone
                walletBalance: user.walletBalance,
                isAdmin: user.isAdmin, // Include isAdmin
                isActive: user.isActive, // Include isActive
                virtualAccount: user.virtualAccount, // Include virtual account details on login
            },
            message: 'Logged in successfully'
        });
    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
};

/**
 * @desc    Get user profile by ID (used by frontend to fetch full user data)
 * @route   GET /api/users/:id
 * @access  Private (requires authentication)
 */
const getUserById = async (req, res) => {
    try {
        // Fetch the user, explicitly selecting the virtualAccount field
        const user = await User.findById(req.params.id).select('-password');

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({
            success: true,
            user: {
                _id: user._id,
                fullName: user.fullName,
                email: user.email,
                phone: user.phone,
                walletBalance: user.walletBalance,
                isAdmin: user.isAdmin,
                isActive: user.isActive,
                virtualAccount: user.virtualAccount, // Ensure this is explicitly returned
            },
        });
    } catch (error) {
        console.error('❌ Error fetching user by ID:', error);
        res.status(500).json({ success: false, message: 'Server error fetching user data.', error: error.message });
    }
};

/**
 * @desc    Provision a dedicated virtual account for an existing user
 * @route   POST /api/users/provision-virtual-account
 * @access  Private (requires authentication)
 */
const provisionExistingUserVirtualAccount = async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Check if user already has a virtual account assigned
        if (user.virtualAccount && user.virtualAccount.assigned) {
            return res.status(200).json({
                success: true,
                message: 'Virtual account already assigned to this user.',
                virtualAccount: user.virtualAccount,
            });
        }

        // Call the Paystack provisioning function
        const accountDetails = await provisionDedicatedAccount(user._id, user.email, user.fullName);

        // The provisionDedicatedAccount function already updates the user in the DB.
        // We just need to send the response.

        res.status(200).json({
            success: true,
            message: 'Virtual account successfully provisioned for existing user.',
            virtualAccount: accountDetails,
        });

    } catch (error) {
        console.error('❌ Error provisioning virtual account for existing user:', error);
        res.status(500).json({ success: false, message: `Failed to provision virtual account: ${error.message}` });
    }
};

module.exports = {
    registerUser,
    loginUser,
    getUserById,
    provisionExistingUserVirtualAccount,
};
