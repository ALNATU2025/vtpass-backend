const express = require('express');
const router = express.Router();
const User = require('../models/userModel');
const Transaction = require('../models/transactionModel');

router.post('/', async (req, res) => {
  const { userId, amount } = req.body;

  const user = await User.findById(userId);
  if (!user) return res.status(404).json({ message: 'User not found' });

  user.walletBalance += amount;
  await user.save();

  await Transaction.create({
    userId,
    type: 'Manual Funding',
    amount,
    status: 'success',
    description: 'Admin funded wallet',
  });

  res.json({ success: true, newBalance: user.walletBalance });
});

module.exports = router;
