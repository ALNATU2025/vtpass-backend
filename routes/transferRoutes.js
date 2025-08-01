// routes/transferRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User'); // Ensure correct path to your User model
const Transaction = require('../models/Transaction');
const { v4: uuidv4 } = require('uuid'); // Import uuid for unique transaction IDs

// Middleware to protect routes (if you have one, uncomment and use)
// const auth = require('../middleware/auth');

// POST /api/transfer - Internal transfer from one user to another
router.post('/', /* auth, */ async (req, res) => {
  const { senderId, receiverEmail, amount } = req.body;

  if (!senderId || !receiverEmail || typeof amount !== 'number' || amount <= 0) {
    return res.status(400).json({ success: false, message: 'Invalid input: senderId, receiverEmail, and a positive amount are required.' });
  }

  try {
    // Find sender
    const sender = await User.findById(senderId);
    if (!sender) {
      return res.status(404).json({ success: false, message: 'Sender not found.' });
    }

    // Find receiver by email
    const receiver = await User.findOne({ email: receiverEmail });
    if (!receiver) {
      return res.status(404).json({ success: false, message: 'Receiver with this email not found.' });
    }

    // Prevent transfer to self
    if (sender._id.toString() === receiver._id.toString()) {
      return res.status(400).json({ success: false, message: 'Cannot transfer money to yourself.' });
    }

    // Check sender's balance
    if (sender.walletBalance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });
    }

    // --- Perform the transfer ---
    // Debit sender
    sender.walletBalance -= amount;
    await sender.save();

    // Credit receiver
    receiver.walletBalance += amount;
    await receiver.save();

    // --- Create transaction records for both parties ---
    const transactionId = uuidv4(); // Generate a unique ID for the transaction pair

    // Sender's transaction
    const senderTransaction = new Transaction({
      userId: sender._id,
      type: 'Transfer-Sent', // Use 'Transfer-Sent' for clarity in transaction history
      amount: amount,
      status: 'Successful', // Changed from 'completed' to 'Successful' to match schema enum
      transactionId: transactionId, // Assign the unique transaction ID
      details: {
        description: `Transfer to ${receiver.fullName} (${receiver.email})`,
        receiverId: receiver._id,
        receiverEmail: receiver.email,
        senderPreviousBalance: sender.walletBalance + amount, // Before debit
        senderNewBalance: sender.walletBalance, // After debit
      },
    });
    await senderTransaction.save();

    // Receiver's transaction
    const receiverTransaction = new Transaction({
      userId: receiver._id,
      type: 'Transfer-Received', // Use 'Transfer-Received' for clarity in transaction history
      amount: amount,
      status: 'Successful', // Changed from 'completed' to 'Successful' to match schema enum
      transactionId: transactionId, // Assign the same unique transaction ID
      details: {
        description: `Received from ${sender.fullName} (${sender.email})`,
        senderId: sender._id,
        senderEmail: sender.email,
        receiverPreviousBalance: receiver.walletBalance - amount, // Before credit
        receiverNewBalance: receiver.walletBalance, // After credit
      },
    });
    await receiverTransaction.save();

    res.status(200).json({
      success: true,
      message: 'Transfer successful.',
      newSenderBalance: sender.walletBalance,
      senderTransactionId: senderTransaction._id,
      receiverTransactionId: receiverTransaction._id,
    });

  } catch (error) {
    console.error('❌ Error during internal transfer:', error);
    // Send a more informative message if possible, but keep 500 for unhandled errors
    res.status(500).json({ success: false, message: 'Server error during transfer. Please check server logs for details.', error: error.message });
  }
});

module.exports = router;
