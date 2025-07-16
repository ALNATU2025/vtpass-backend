const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');

router.post('/pay', async (req, res) => {
  try {
    const { email, serviceType, smartCardNumber, selectedPackage, amount, selectedCable } = req.body;

    // Validate fields
    if (!email || !smartCardNumber || !amount || !selectedPackage || !serviceType || !selectedCable) {
      return res.status(400).json({
        message: 'All fields (email, smartCardNumber, amount, selectedPackage, serviceType, selectedCable) are required'
      });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount)) {
      return res.status(400).json({ message: 'Invalid amount format' });
    }

    if (user.walletBalance < numericAmount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Deduct amount
    user.walletBalance -= numericAmount;
    await user.save();

    // Save transaction
    const newTransaction = new Transaction({
      userId: user._id,
      type: 'Cable TV',
      provider: selectedCable,
      service: serviceType,
      smartCardNumber,
      package: selectedPackage,
      amount: numericAmount,
    });

    await newTransaction.save();

    res.status(200).json({
      message: 'Payment successful',
      walletBalance: user.walletBalance,
      transaction: newTransaction,
    });
  } catch (err) {
    console.error('CableTV Error:', err.message);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

module.exports = router;
