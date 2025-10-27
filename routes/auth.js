// File: backend/routes/auth.js
const express = require('express');
const User = require('../models/User');
const router = express.Router();

router.post('/api/register', async (req, res) => {
  const { fullName, email, phone, password, referralCode } = req.body;

  try {
    // Check for duplicate email or phone
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: existingUser.email === email ? 'Email already exists' : 'Phone number already exists',
        errorCode: existingUser.email === email ? 'DUPLICATE_EMAIL' : 'DUPLICATE_PHONE',
      });
    }

    // Create new user (password hashing omitted for brevity)
    const user = new User({
      fullName,
      email,
      phone,
      password: hashedPassword, // Assume password is hashed
      referralCode,
      isAdmin: false,
      walletBalance: 0,
      commissionBalance: 0,
      transactionPinSet: false,
      biometricEnabled: false,
    });

    await user.save();

    // Generate tokens (JWT or similar, implement as needed)
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    res.status(201).json({
      success: true,
      message: 'Registration successful!',
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        isAdmin: user.isAdmin,
        walletBalance: user.walletBalance,
        commissionBalance: user.commissionBalance,
        transactionPinSet: user.transactionPinSet,
        biometricEnabled: user.biometricEnabled,
      },
      token,
      refreshToken,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
      errorCode: 'SERVER_ERROR',
    });
  }
});

module.exports = router;
