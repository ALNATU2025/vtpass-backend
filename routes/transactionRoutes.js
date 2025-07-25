// routes/transactionRoutes.js

const express = require('express');
const router = express.Router();
const Transaction = require('../models/transactionModel'); // Ensure this path is correct: '../models/transactionModel'

// ✅ NEW ROUTE: GET /api/transactions
// This route fetches ALL transactions.
router.get('/', async (req, res) => {
  try {
    // Fetch all transactions, sorted by creation date (newest first)
    // You might want to add authentication middleware here to ensure only admins can access this.
    const transactions = await Transaction.find().sort({ createdAt: -1 });

    res.status(200).json(transactions);
  } catch (error) {
    console.error('❌ Error fetching all transactions:', error);
    res.status(500).json({ success: false, message: 'Server error fetching all transactions.' });
  }
});

// ✅ EXISTING ROUTE: GET /api/transactions/:userId
// This route fetches transactions for a SPECIFIC user.
router.get('/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    // Fetch all transactions for the given user, sorted by creation date (newest first)
    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });

    res.status(200).json(transactions);
  } catch (error) {
    console.error('❌ Error fetching transactions for user:', error); // Changed log message for clarity
    res.status(500).json({ success: false, message: 'Server error fetching user transactions.' }); // Changed message for clarity
  }
});

module.exports = router;