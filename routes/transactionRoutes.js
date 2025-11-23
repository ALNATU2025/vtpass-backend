// routes/transactionRoutes.js

const express = require('express');
const router = express.Router();
const Transaction = require('../models/Transaction');

// ✅ GET /api/transactions - Get transactions for current user (requires authentication)
router.get('/', async (req, res) => {
  try {
    // Extract user ID from authenticated request (you'll need to add auth middleware)
    const userId = req.user?._id;
    
    if (!userId) {
      return res.status(401).json({ 
        success: false, 
        message: 'Authentication required' 
      });
    }

    // Fetch transactions for the authenticated user
    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions: transactions
    });
  } catch (error) {
    console.error('❌ Error fetching user transactions:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error fetching transactions.' 
    });
  }
});

// ✅ GET /api/transactions/all - Get ALL transactions (Admin only)
router.get('/all', async (req, res) => {
  try {
    // Add admin check here
    const isAdmin = req.user?.isAdmin;
    if (!isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }

    const transactions = await Transaction.find().sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions: transactions
    });
  } catch (error) {
    console.error('❌ Error fetching all transactions:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error fetching all transactions.' 
    });
  }
});

// ✅ GET /api/transactions/user/:userId - Get transactions for specific user (Admin only)
router.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required.' 
      });
    }

    // Add admin check here
    const isAdmin = req.user?.isAdmin;
    if (!isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }

    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions: transactions
    });
  } catch (error) {
    console.error('❌ Error fetching transactions for user:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error fetching user transactions.' 
    });
  }
});

module.exports = router;
