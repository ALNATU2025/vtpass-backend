// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User'); // Ensure correct path to your User model
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../utils/emailService'); // Assuming this utility exists
const { provisionDedicatedAccount } = require('../controllers/paystackController'); // Import Paystack provisioning
const { protect } = require('../middleware/authMiddleware'); // <<< FIXED: Destructure 'protect' from the export

// Helper function to generate a JWT token
const generateToken = (id) => {
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

console.log("📥 /api/users route file loaded");

// ✅ Register new customer
router.post('/register', async (req, res) => {
    try {
        const { fullName, email, phone, password } = req.body;

        // Check if user with email or phone already exists
        const userExists = await User.findOne({ $or: [{ email }, { phone }] });
        if (userExists) {
            return res.status(400).json({ message: 'User with this email or phone already exists' });
        }

        // Password hashing is handled by the pre-save hook in the User model
        const newUser = new User({ fullName, email, phone, password });
        await newUser.save(); // Save user first to get an _id

        // --- NEW: Provision dedicated account after user is saved ---
        let virtualAccountDetails = null;
        try {
            virtualAccountDetails = await provisionDedicatedAccount(newUser._id, newUser.email, newUser.fullName);
            console.log(`Dedicated account assigned to new user ${newUser.email}: ${virtualAccountDetails.accountNumber}`);
            // Update the newUser object in memory for the response
            newUser.virtualAccount = virtualAccountDetails;
        } catch (accountError) {
            console.error(`Failed to provision dedicated account for new user ${newUser.email}:`, accountError.message);
            // Log the error but do NOT prevent user registration from completing.
            // The user will see the "Generate My Account" button in the app.
        }

        const token = generateToken(newUser._id); // Generate token on registration

        res.status(201).json({
            message: 'User registered successfully',
            token, // Include token in response
            user: {
                _id: newUser._id,
                fullName: newUser.fullName,
                email: newUser.email,
                phone: newUser.phone, // Ensure phone is included
                walletBalance: newUser.walletBalance,
                isActive: newUser.isActive, // Include isActive in response
                isAdmin: newUser.isAdmin, // Include isAdmin in response
                virtualAccount: newUser.virtualAccount, // Include virtualAccount in response
            }
        });
    } catch (err) {
        console.error("❌ Error in /register:", err.message);
        res.status(500).json({ error: err.message || 'Server error during registration' });
    }
});

// ✅ Login user
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        // Check if user is active
        if (!user.isActive) {
            return res.status(403).json({ message: 'Your account has been deactivated. Please contact support.' });
        }

        const isMatch = await user.matchPassword(password); // Using the schema method
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = generateToken(user._id); // Generate token on login

        res.json({
            message: 'Login successful',
            token, // Include token in response
            user: {
                _id: user._id,
                fullName: user.fullName,
                email: user.email,
                phone: user.phone, // Ensure phone is included
                walletBalance: user.walletBalance,
                isActive: user.isActive, // Include isActive in response
                isAdmin: user.isAdmin, // Include isAdmin in response
                virtualAccount: user.virtualAccount, // Include virtualAccount in response
            }
        });
    } catch (err) {
        console.error("❌ Error in /login:", err.message);
        res.status(500).json({ error: err.message || 'Server error during login' });
    }
});

// ✅ NEW ROUTE: POST /api/users/provision-virtual-account - For existing users to get a virtual account
router.post('/provision-virtual-account', protect, async (req, res) => {
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
});


// ✅ PUT /api/users/:id - Admin updates user profile and balance
// This endpoint MUST be protected by admin authorization.
router.put('/:id', /* auth, authorizeAdmin, */ async (req, res) => { // Assuming 'auth' and 'authorizeAdmin' are your middleware
    try {
        const userId = req.params.id;
        const { fullName, email, phone, walletBalance, isActive, isAdmin } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Update fields if they are provided in the request body
        if (fullName !== undefined) user.fullName = fullName;
        if (email !== undefined) {
            // Check if new email already exists for another user
            const emailExists = await User.findOne({ email: email, _id: { $ne: userId } });
            if (emailExists) {
                return res.status(400).json({ success: false, message: 'Email already in use by another user.' });
            }
            user.email = email;
        }
        if (phone !== undefined) {
            // Check if new phone already exists for another user
            const phoneExists = await User.findOne({ phone: phone, _id: { $ne: userId } });
            if (phoneExists) {
                return res.status(400).json({ success: false, message: 'Phone number already in use by another user.' });
            }
            user.phone = phone;
        }
        if (walletBalance !== undefined) user.walletBalance = walletBalance;
        if (isActive !== undefined) user.isActive = isActive;
        if (isAdmin !== undefined) user.isAdmin = isAdmin; // Be cautious allowing this via UI

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
                virtualAccount: user.virtualAccount, // Include virtualAccount
            }
        });

    } catch (error) {
        console.error('❌ Error updating user profile:', error);
        res.status(500).json({ success: false, message: 'Server error updating user profile.' });
    }
});


// ✅ PUT /api/users/toggle-status/:id - Admin toggles user active status (existing route)
router.put('/toggle-status/:id', /* auth, authorizeAdmin, */ async (req, res) => {
    try {
        const userId = req.params.id;
        const { isActive } = req.body;

        if (typeof isActive !== 'boolean') {
            return res.status(400).json({ success: false, message: 'Invalid status provided. Must be true or false.' });
        }

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
});

// ✅ POST /api/users/change-password - Change user's password (existing route)
router.post('/change-password', /* auth, */ async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'All fields (userId, currentPassword, newPassword) are required.' });
        }

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
});

// ✅ Admin: Fetch all users for manual funding (GET /api/users) (existing route)
router.get('/', async (req, res) => {
    try {
        // Include virtualAccount in the select statement if you want it for admin view
        const users = await User.find().select('_id fullName email walletBalance isActive isAdmin phone virtualAccount');
        res.status(200).json({ users });
    } catch (err) {
        console.error("❌ Error in /api/users (GET all):", err.message);
        res.status(500).json({ message: 'Failed to fetch users' });
    }
});

// ✅ Get user balance by POST (POST /api/users/get-balance) (existing route)
router.post('/get-balance', async (req, res) => {
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
});

// ✅ Fetch user by ID (for balance refresh and virtual account) (GET /api/users/:id) (existing route)
router.get('/:id', protect, async (req, res) => { // Added 'protect' middleware
    try {
        // Changed to select all fields except password to include virtualAccount
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });

        res.status(200).json({ user });
    } catch (err) {
        console.error("❌ Error in /api/users/:id (GET by ID):", err.message);
        res.status(500).json({ message: 'Error fetching user details' });
    }
});

module.exports = router;
