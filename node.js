// routes/transferRoutes.js (Assuming this is the file name)

const express = require('express');
const router = express.Router();
// ✅ CHANGE THIS LINE:
const User = require('../models/User'); // Changed from '../models/userModel' to '../models/User'
const Transaction = require('../models/Transaction'); // Assuming this path is correct
const authMiddleware = require('../middleware/authMiddleware'); // Assuming this path is correct

// POST /api/transfer
router.post('/', authMiddleware, async (req, res) => {
  try {
    const userId = req.user._id; // Assuming authMiddleware correctly sets req.user
    const { accountNumber, bank, amount } = req.body;

    if (!accountNumber || !bank || !amount) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.walletBalance < amount) {
      return res.status(400).json({ error: 'Insufficient wallet balance.' });
    }

    // Deduct from wallet
    user.walletBalance -= amount;
    await user.save();

    // Log transaction
    await Transaction.create({
      userId,
      type: 'transfer',
      amount,
      recipient: accountNumber,
      bank,
    });

    return res.json({
      message: 'Transfer successful',
      walletBalance: user.walletBalance,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
