// controllers/userController.js
const User = require('../models/User'); // <<< ENSURE THIS IS '../models/User'
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { sendEmail } = require('../utils/emailService');
const { provisionDedicatedAccount } = require('./paystackController');

// Helper function to generate a JWT token
const generateToken = (id) => {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
        console.error('ERROR: JWT_SECRET environment variable is not set!');
        throw new Error('JWT secret is not configured.');
    }
    return jwt.sign({ id }, jwtSecret, {
        expiresIn: '30d',
    });
};

/**
 * @desc    Register a new user
 * @route   POST /api/users/register
 * @access  Public
 */
const registerUser = async (req, res) => {
    const { fullName, email, password, phone } = req.body;
    if (!fullName || !phone || !email || !password) {
        return res.status(400).json({ message: 'Please enter all required fields: Full Name, Phone, Email, and Password' });
    }
    try {
        const userExists = await User.findOne({ $or: [{ email }, { phone }] });
        if (userExists) {
            if (userExists.email === email) {
                return res.status(400).json({ message: 'User with this email already exists' });
            } else {
                return res.status(400).json({ message: 'User with this phone number already exists' });
            }
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({
            fullName,
            phone,
            email,
            password: hashedPassword,
            isActive: true, // <--- EXPLICITLY SET isActive to true
        });
        await newUser.save();

        let virtualAccountDetails = null;
        try {
            virtualAccountDetails = await provisionDedicatedAccount(newUser._id, newUser.email, newUser.fullName);
            console.log(`Dedicated account assigned to new user ${newUser.email}: ${virtualAccountDetails.accountNumber}`);
            newUser.virtualAccount = virtualAccountDetails;
        } catch (accountError) {
            console.error(`Failed to provision dedicated account for new user ${newUser.email}:`, accountError.message);
        }

        const token = generateToken(newUser._id);
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                _id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                phone: newUser.phone,
                walletBalance: newUser.walletBalance,
                isActive: newUser.isActive,
                isAdmin: newUser.isAdmin,
                virtualAccount: newUser.virtualAccount,
            }
        });
    } catch (err) {
        console.error("❌ Error in /register:", err.message);
        res.status(500).json({ error: err.message || 'Server error during registration' });
    }
};

/**
 * @desc    Authenticate user & get token (Login)
 * @route   POST /api/users/login
 * @access  Public
 */
const loginUser = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Please enter email and password' });
    }
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        if (!user.isActive) {
            return res.status(403).json({ message: 'Your account has been deactivated. Please contact support.' });
        }
        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = generateToken(user._id);
        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                _id: user._id,
                fullName: user.fullName,
                email: user.email,
                phone: user.phone,
                walletBalance: user.walletBalance,
                isActive: user.isActive,
                isAdmin: user.isAdmin,
                virtualAccount: user.virtualAccount,
            },
        });
    } catch (error) {
        console.error('Error during user login:', error);
        res.status(500).json({ message: 'Server error during login', error: error.message });
    }
};

/**
 * @desc    Get user profile by ID
 * @route   GET /api/users/:id
 * @access  Private (requires authentication)
 */
const getUserById = async (req, res) => {
    try {
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
                virtualAccount: user.virtualAccount,
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
        if (user.virtualAccount && user.virtualAccount.assigned) {
            return res.status(200).json({
                success: true,
                message: 'Virtual account already assigned to this user.',
                virtualAccount: user.virtualAccount,
            });
        }
        const accountDetails = await provisionDedicatedAccount(user._id, user.email, user.fullName);
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

/**
 * @desc    Admin updates user profile and balance
 * @route   PUT /api/users/:id
 * @access  Private (Admin only)
 */
const updateUserProfile = async (req, res) => {
    const userId = req.params.id;
    const { fullName, email, phone, walletBalance, isActive, isAdmin } = req.body;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (fullName !== undefined) user.fullName = fullName;
        if (email !== undefined) {
            const emailExists = await User.findOne({ email: email, _id: { $ne: userId } });
            if (emailExists) {
                return res.status(400).json({ success: false, message: 'Email already in use by another user.' });
            }
            user.email = email;
        }
        if (phone !== undefined) {
            const phoneExists = await User.findOne({ phone: phone, _id: { $ne: userId } });
            if (phoneExists) {
                return res.status(400).json({ success: false, message: 'Phone number already in use by another user.' });
            }
            user.phone = phone;
        }
        if (walletBalance !== undefined) user.walletBalance = walletBalance;
        if (isActive !== undefined) user.isActive = isActive;
        if (isAdmin !== undefined) user.isAdmin = isAdmin;
        await user.save();
        res.status(200).json({
            success: true,
            message: 'User profile updated successfully.',
            user: {
                _id: user._id,
                fullName: user.fullName,
                email: user.email,
                phone: user.phone,
                walletBalance: user.walletBalance,
                isActive: user.isActive,
                isAdmin: user.isAdmin,
                virtualAccount: user.virtualAccount,
            },
        });
    } catch (error) {
        console.error('❌ Error updating user profile:', error);
        res.status(500).json({ success: false, message: 'Server error updating user profile.' });
    }
};

/**
 * @desc    Admin toggles user active status
 * @route   PUT /api/users/toggle-status/:id
 * @access  Private (Admin only)
 */
const toggleUserStatus = async (req, res) => {
    const userId = req.params.id;
    const { isActive } = req.body;
    if (typeof isActive !== 'boolean') {
        return res.status(400).json({ success: false, message: 'Invalid status provided. Must be true or false.' });
    }
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        user.isActive = isActive;
        await user.save();
        res.status(200).json({ success: true, message: `User account ${isActive ? 'activated' : 'deactivated'} successfully.`, user: { _id: user._id, fullName: user.fullName, email: user.email, isActive: user.isActive } });
    } catch (error) {
        console.error('❌ Error toggling user status:', error);
        res.status(500).json({ success: false, message: 'Server error toggling user status.' });
    }
};

/**
 * @desc    Change user's password
 * @route   POST /api/users/change-password
 * @access  Private
 */
const changePassword = async (req, res) => {
    const { userId, currentPassword, newPassword } = req.body;
    if (!userId || !currentPassword || !newPassword) {
        return res.status(400).json({ success: false, message: 'All fields (userId, currentPassword, newPassword) are required.' });
    }
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        const isMatch = await user.matchPassword(currentPassword);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect current password.' });
        }
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        res.status(200).json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        console.error('❌ Error changing password for user:', error);
        res.status(500).json({ success: false, message: 'Server error changing password.' });
    }
};

/**
 * @desc    Admin: Fetch all users
 * @route   GET /api/users
 * @access  Private (Admin only)
 */
const getAllUsers = async (req, res) => {
    try {
        const users = await User.find().select('_id fullName email walletBalance isActive isAdmin phone virtualAccount');
        res.status(200).json({ users });
    } catch (err) {
        console.error("❌ Error in /api/users (GET all):", err.message);
        res.status(500).json({ message: 'Failed to fetch users' });
    }
};

/**
 * @desc    Get user balance by POST
 * @route   POST /api/users/get-balance
 * @access  Private
 */
const getUserBalance = async (req, res) => {
    try {
        const { userId } = req.body;
        console.log("🔄 Balance check for userId:", userId);
        if (!userId) return res.status(400).json({ message: 'User ID is required' });
        const user = await User.findById(userId).select('walletBalance');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ walletBalance: user.walletBalance });
    } catch (err) {
        console.error("❌ Error in /get-balance:", err.message);
        res.status(500).json({ message: 'Server error', error: err.message });
    }
};

module.exports = {
    registerUser,
    loginUser,
    getUserById,
    provisionExistingUserVirtualAccount,
    updateUserProfile,
    toggleUserStatus,
    changePassword,
    getAllUsers,
    getUserBalance,
};
