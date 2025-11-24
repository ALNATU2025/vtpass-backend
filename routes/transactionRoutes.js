const express = require('express');
const router = express.Router();
const Transaction = require('../models/Transaction');
const protect = require('../middleware/protect'); // <-- ADD THIS

// 🔐 GET /api/transactions - user’s own transactions
router.get('/', protect, async (req, res) => {
  try {
    const userId = req.user._id;  // <-- ALWAYS available now

    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions
    });

  } catch (error) {
    console.error('❌ Error fetching user transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching transactions.'
    });
  }
});

// 🔐 GET /api/transactions/all - Admin only
router.get('/all', protect, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const transactions = await Transaction.find().sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions
    });

  } catch (error) {
    console.error('❌ Error fetching all transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching all transactions.'
    });
  }
});

// 🔐 GET /api/transactions/user/:userId - Admin only
router.get('/user/:userId', protect, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const { userId } = req.params;

    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions
    });

  } catch (error) {
    console.error('❌ Error fetching user transactions:', error);
    res.status(500).json({
      success: false,
      message: 'Server error fetching user transactions.'
    });
  }
});

module.exports = router;
