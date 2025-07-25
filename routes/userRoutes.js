// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Helper function to generate a JWT token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET || 'your_jwt_secret', {
    expiresIn: '7d',
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
    await newUser.save();

    const token = generateToken(newUser._id); // Generate token on registration

    res.status(201).json({
      message: 'User registered successfully',
      token, // Include token in response
      user: {
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        walletBalance: newUser.walletBalance,
        isActive: newUser.isActive, // Include isActive in response
        isAdmin: newUser.isAdmin // Include isAdmin in response
      }
    });
  } catch (err) {
    console.error("❌ Error in /register:", err.message);
    res.status(500).json({ error: err.message });
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
        walletBalance: user.walletBalance,
        isActive: user.isActive, // Include isActive in response
        isAdmin: user.isAdmin // Include isAdmin in response
      }
    });
  } catch (err) {
    console.error("❌ Error in /login:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ✅ NEW ROUTE: PUT /api/users/:id - Admin updates user profile and balance
// This endpoint MUST be protected by admin authorization.
router.put('/:id', /* auth, authorizeAdmin, */ async (req, res) => {
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
        isAdmin: user.isAdmin
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
    const users = await User.find().select('_id fullName email walletBalance isActive isAdmin phone');
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

// ✅ Fetch user by ID (for balance refresh) (GET /api/users/:id) (existing route)
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('_id fullName email walletBalance isActive isAdmin phone');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.status(200).json({ user });
  } catch (err) {
    console.error("❌ Error in /api/users/:id (GET by ID):", err.message);
    res.status(500).json({ message: 'Error fetching user details' });
  }
});

module.exports = router;
