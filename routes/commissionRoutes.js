// routes/commissionRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { protect } = require('../middleware/authMiddleware');







// ADD THIS RATE LIMITER (adjust as needed)
const withdrawLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // max 5 withdrawals per window
  message: {
    success: false,
    message: 'Too many withdrawal attempts. Please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});




// @desc    Get commission balance
// @route   GET /api/commission/balance
// @access  Private
router.get('/balance', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('commissionBalance walletBalance fullName email phone');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      data: {
        commissionBalance: user.commissionBalance,
        walletBalance: user.walletBalance,
        formattedCommissionBalance: user.formattedCommissionBalance,
        formattedWalletBalance: user.formattedWalletBalance,
        user: {
          fullName: user.fullName,
          email: user.email,
          phone: user.phone
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Get commission balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get commission balance'
    });
  }
});

// @desc    Withdraw commission to main wallet
// @route   POST /api/commission/withdraw
// @access  Private
router.post('/withdraw', protect, async (req, res) => {
  try {
    const { amount, transactionPin, useBiometric } = req.body;
    const userId = req.user._id;
    
    // Validate amount
    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid amount'
      });
    }
    
    // Check minimum withdrawal
    if (amount < 500) {
      return res.status(400).json({
        success: false,
        message: 'Minimum withdrawal amount is ₦500'
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Verify authentication
    const authReq = {
      ...req,
      body: { transactionPin, useBiometric }
    };
    
    // Use verifyTransactionAuth middleware manually
    verifyTransactionAuth(authReq, res, async () => {
      try {
        // Process withdrawal
        const result = await user.withdrawCommissionToWallet(amount, transactionPin);
        
        res.json({
          success: true,
          message: result.message,
          data: {
            newCommissionBalance: result.newCommissionBalance,
            newWalletBalance: result.newWalletBalance,
            commissionTransactionId: result.commissionTransactionId,
            walletTransactionId: result.walletTransactionId
          }
        });
        
      } catch (error) {
        console.error('❌ Commission withdrawal processing error:', error);
        res.status(400).json({
          success: false,
          message: error.message || 'Failed to process withdrawal'
        });
      }
    });
    
  } catch (error) {
    console.error('❌ Commission withdrawal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// @desc    Get commission transactions
// @route   GET /api/commission/transactions
// @access  Private
router.get('/transactions', protect, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status, startDate, endDate } = req.query;
    const userId = req.user._id;
    
    const query = { userId, isCommission: true };
    
    // Apply filters
    if (type) query.type = type;
    if (status) query.status = status;
    
    // Date filter
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('-__v');
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      success: true,
      data: {
        transactions,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Get commission transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get commission transactions'
    });
  }
});

// @desc    Use commission for service purchase
// @route   POST /api/commission/use-for-service
// @access  Private
router.post('/use-for-service', protect, async (req, res) => {
  try {
    const {
      serviceType,
      amount,
      serviceDetails,
      transactionPin,
      useBiometric
    } = req.body;
    
    const userId = req.user._id;
    
    // Validate input
    if (!serviceType || !amount || !serviceDetails) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }
    
    if (amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Verify authentication
    const authReq = {
      ...req,
      body: { transactionPin, useBiometric }
    };
    
    verifyTransactionAuth(authReq, res, async () => {
      try {
        // Deduct commission
        const commissionResult = await user.deductCommissionForService(
          amount,
          serviceType,
          serviceDetails
        );
        
        res.json({
          success: true,
          message: `₦${amount.toFixed(2)} commission allocated for ${serviceType} purchase`,
          data: {
            newCommissionBalance: commissionResult.newCommissionBalance,
            transactionId: commissionResult.transactionId,
            commissionTransaction: commissionResult.commissionTransaction,
            commissionOnly: true
          }
        });
        
      } catch (error) {
        console.error('❌ Commission deduction error:', error);
        res.status(400).json({
          success: false,
          message: error.message || 'Failed to use commission'
        });
      }
    });
    
  } catch (error) {
    console.error('❌ Use commission for service error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// @desc    Complete commission-based service purchase (called after VTPass success)
// @route   POST /api/commission/complete-service-purchase
// @access  Private
router.post('/complete-service-purchase', protect, async (req, res) => {
  try {
    const { transactionId, vtpassResponse, status = 'Successful' } = req.body;
    
    if (!transactionId) {
      return res.status(400).json({
        success: false,
        message: 'Transaction ID is required'
      });
    }
    
    // Update commission transaction with VTPass response
    const updatedTransaction = await Transaction.findByIdAndUpdate(
      transactionId,
      {
        status: status,
        'metadata.vtpassResponse': vtpassResponse,
        'metadata.completedAt': new Date()
      },
      { new: true }
    );
    
    if (!updatedTransaction) {
      return res.status(404).json({
        success: false,
        message: 'Commission transaction not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Service purchase completed successfully',
      data: {
        transaction: updatedTransaction
      }
    });
    
  } catch (error) {
    console.error('❌ Complete service purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete service purchase'
    });
  }
});

// @desc    Refund commission (if service purchase fails)
// @route   POST /api/commission/refund
// @access  Private
router.post('/refund', protect, async (req, res) => {
  try {
    const { transactionId } = req.body;
    
    if (!transactionId) {
      return res.status(400).json({
        success: false,
        message: 'Transaction ID is required'
      });
    }
    
    const transaction = await Transaction.findById(transactionId);
    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found'
      });
    }
    
    // Verify transaction belongs to user
    if (transaction.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized'
      });
    }
    
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Process refund
    const refundResult = await user.refundCommission(transaction.amount, transactionId);
    
    res.json({
      success: true,
      message: `₦${transaction.amount.toFixed(2)} commission refunded successfully`,
      data: {
        newCommissionBalance: refundResult.newCommissionBalance,
        refundTransactionId: refundResult.refundTransactionId
      }
    });
    
  } catch (error) {
    console.error('❌ Commission refund error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process refund'
    });
  }
});

module.exports = router;
