// routes/commissionRoutes.js
const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { protect } = require('../middleware/authMiddleware');
const { verifyTransactionAuth } = require('../middleware/transactionAuthMiddleware');

// Helper function to format currency
const formatCurrency = (amount) => {
  return new Intl.NumberFormat('en-NG', {
    style: 'currency',
    currency: 'NGN',
    minimumFractionDigits: 2
  }).format(amount);
};

// Rate limiter for withdrawals
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
        formattedCommissionBalance: formatCurrency(user.commissionBalance),
        formattedWalletBalance: formatCurrency(user.walletBalance),
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
router.post('/withdraw', protect, withdrawLimiter, verifyTransactionAuth, async (req, res) => {
  try {
    const { amount } = req.body;
    const userId = req.user._id;
    
    // Validate amount
    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Please enter a valid amount'
      });
    }
    
    // Convert to number
    const withdrawalAmount = parseFloat(amount);
    
    // Check minimum withdrawal
    if (withdrawalAmount < 500) {
      return res.status(400).json({
        success: false,
        message: 'Minimum withdrawal amount is ₦500'
      });
    }
    
    // Check maximum withdrawal (optional)
    if (withdrawalAmount > 50000) {
      return res.status(400).json({
        success: false,
        message: 'Maximum withdrawal amount is ₦50,000'
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if user has enough commission balance
    if (user.commissionBalance < withdrawalAmount) {
      return res.status(400).json({
        success: false,
        message: `Insufficient commission balance. Available: ${formatCurrency(user.commissionBalance)}`
      });
    }
    
    // Process withdrawal
    const result = await user.withdrawCommissionToWallet(withdrawalAmount);
    
    res.json({
      success: true,
      message: result.message,
      data: {
        newCommissionBalance: result.newCommissionBalance,
        newWalletBalance: result.newWalletBalance,
        formattedNewCommissionBalance: formatCurrency(result.newCommissionBalance),
        formattedNewWalletBalance: formatCurrency(result.newWalletBalance),
        commissionTransactionId: result.commissionTransactionId,
        walletTransactionId: result.walletTransactionId,
        amountWithdrawn: withdrawalAmount,
        formattedAmountWithdrawn: formatCurrency(withdrawalAmount)
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
    
    // Format amounts for display
    const formattedTransactions = transactions.map(transaction => ({
      ...transaction.toObject(),
      formattedAmount: formatCurrency(transaction.amount),
      formattedBalance: transaction.balanceAfter ? formatCurrency(transaction.balanceAfter) : null
    }));
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      success: true,
      data: {
        transactions: formattedTransactions,
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
router.post('/use-for-service', protect, verifyTransactionAuth, async (req, res) => {
  try {
    const {
      serviceType,
      amount,
      serviceDetails
    } = req.body;
    
    const userId = req.user._id;
    
    // Validate input
    if (!serviceType || !amount || !serviceDetails) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }
    
    const serviceAmount = parseFloat(amount);
    
    if (serviceAmount <= 0) {
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
    
    // Check if user has enough commission balance
    if (user.commissionBalance < serviceAmount) {
      return res.status(400).json({
        success: false,
        message: `Insufficient commission balance. Available: ${formatCurrency(user.commissionBalance)}`
      });
    }
    
    // Deduct commission
    const commissionResult = await user.deductCommissionForService(
      serviceAmount,
      serviceType,
      serviceDetails
    );
    
    res.json({
      success: true,
      message: `${formatCurrency(serviceAmount)} commission allocated for ${serviceType} purchase`,
      data: {
        newCommissionBalance: commissionResult.newCommissionBalance,
        formattedNewCommissionBalance: formatCurrency(commissionResult.newCommissionBalance),
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
    
    // Verify it's a commission transaction
    if (!transaction.isCommission) {
      return res.status(400).json({
        success: false,
        message: 'Not a commission transaction'
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
      message: `${formatCurrency(transaction.amount)} commission refunded successfully`,
      data: {
        newCommissionBalance: refundResult.newCommissionBalance,
        formattedNewCommissionBalance: formatCurrency(refundResult.newCommissionBalance),
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
