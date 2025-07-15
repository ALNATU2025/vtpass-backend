const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');

// ✅ Register new customer
router.post('/register', async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

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
    res.status(500).json({ error: err.message });
  }
});

// ✅ Login user
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
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
    res.status(500).json({ error: err.message });
  }
});

// ✅ Admin: Fetch all users for manual funding
router.get('/', async (req, res) => {
     console.log("📥 /api/users route file loaded");
  try {
    const users = await User.find().select('_id fullName email walletBalance');
    res.status(200).json({ users });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

module.exports = router;
