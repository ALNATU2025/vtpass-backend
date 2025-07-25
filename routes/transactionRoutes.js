const express = require('express');
const router = express.Router();
const Transaction = require('../models/transactionModels'); 
 // Ensure this path is correct relative to this file

// GET /api/transactions/:userId
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
    console.error('❌ Error fetching transactions:', error);
    res.status(500).json({ success: false, message: 'Server error fetching transactions.' });
  }
});

module.exports = router;