// routes/userRoutes.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/userModel'); // Ensure this imports the consolidated User model

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

    const newUser = new User({ fullName, email, phone, password });
    await newUser.save();

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        walletBalance: newUser.walletBalance
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

    const isMatch = await user.matchPassword(password); // Using the schema method
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    res.json({
      message: 'Login successful',
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        walletBalance: user.walletBalance
      }
    });
  } catch (err) {
    console.error("❌ Error in /login:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Admin: Fetch all users for manual funding (GET /api/users)
router.get('/', async (req, res) => {
  try {
    const users = await User.find().select('_id fullName email walletBalance');
    res.status(200).json({ users });
  } catch (err) {
    console.error("❌ Error in /api/users (GET all):", err.message);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

// ✅ Get user balance by POST (POST /api/users/get-balance)
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

// ✅ Fetch user by ID (for balance refresh) (GET /api/users/:id)
router.get('/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('_id fullName email walletBalance');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.status(200).json({ user });
  } catch (err) {
    console.error("❌ Error in /api/users/:id (GET by ID):", err.message);
    res.status(500).json({ message: 'Error fetching user details' });
  }
});

module.exports = router;
