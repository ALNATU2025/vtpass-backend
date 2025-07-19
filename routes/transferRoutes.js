// routes/transferRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/userModel'); // Ensure this imports the consolidated User model
const Transaction = require('../models/transactionModel'); // Assuming you have a general Transaction model

// Middleware to protect routes (assuming it populates req.user._id)
// const authMiddleware = require('../middleware/authMiddleware'); // Uncomment if you use this middleware

// POST /api/transfer
// This route now expects receiverEmail for transfers, aligning with Flutter's ApiService.transfer
router.post('/', /* authMiddleware, */ async (req, res) => { // Uncomment authMiddleware if needed
  try {
    // Assuming senderId is passed in the body or retrieved from authMiddleware
    // If using authMiddleware, use const senderId = req.user._id;
    const { senderId, receiverEmail, amount } = req.body;

    if (!senderId || !receiverEmail || !amount) {
      return res.status(400).json({ error: 'Sender ID, Receiver Email, and Amount are required.' });
    }

    const sender = await User.findById(senderId);
    if (!sender) return res.status(404).json({ error: 'Sender user not found.' });

    const receiver = await User.findOne({ email: receiverEmail });
    if (!receiver) return res.status(404).json({ error: 'Receiver user not found with this email.' });

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount.' });
    }

    if (sender.walletBalance < numericAmount) {
      return res.status(400).json({ error: 'Insufficient wallet balance.' });
    }

    // Perform the transfer
    sender.walletBalance -= numericAmount;
    receiver.walletBalance += numericAmount;

    await sender.save();
    await receiver.save();

    // Log transaction for sender (debit)
    await Transaction.create({
      userId: sender._id,
      type: 'Transfer (Debit)',
      amount: -numericAmount, // Store as negative for debit
      recipient: receiver.email, // Store receiver's email
      status: 'success',
    });

    // Log transaction for receiver (credit)
    await Transaction.create({
      userId: receiver._id,
      type: 'Transfer (Credit)',
      amount: numericAmount,
      sender: sender.email, // Store sender's email
      status: 'success',
    });

    return res.json({
      message: 'Transfer successful',
      senderWalletBalance: sender.walletBalance,
      receiverWalletBalance: receiver.walletBalance, // Optionally return receiver's balance
    });
  } catch (err) {
    console.error('❌ Transfer Error:', err.message);
    res.status(500).json({ error: 'Server error during transfer.' });
  }
});

module.exports = router;
