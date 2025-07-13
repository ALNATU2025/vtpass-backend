const express = require('express');
const router = express.Router();
const Transaction = require('../models/Transaction');
const User = require('../models/User');

// Create a transaction (credit or debit)
router.post('/', async (req, res) => {
  try {
    const { userId, type, amount, description } = req.body;

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Update user wallet balance
    if (type === 'credit') {
      user.walletBalance += amount;
    } else if (type === 'debit') {
      if (user.walletBalance < amount) {
        return res.status(400).json({ message: 'Insufficient balance' });
      }
      user.walletBalance -= amount;
    }

    await user.save();

    // Save transaction
    const newTx = new Transaction({
      userId,
      type,
      amount,
      description,
      status: 'verified',
    });

    await newTx.save();

    res.status(201).json({ message: 'Transaction recorded', transaction: newTx });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// List all transactions
router.get('/', async (req, res) => {
  try {
    const txs = await Transaction.find().populate('userId', 'name email').sort({ createdAt: -1 });
    res.json(txs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
