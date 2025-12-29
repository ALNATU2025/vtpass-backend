// routes/commissionRoutes.js
const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
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





// Add this at the TOP of commissionRoutes.js, after imports
router.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Commission API is working!',
    timestamp: new Date().toISOString(),
    endpoints: [
      '/balance',
      '/withdraw',
      '/transactions',
      '/use-for-service',
      '/complete-service-purchase',
      '/refund'
    ]
  });
});

// Also add a simple stats endpoint for your Flutter app:
router.get('/stats', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get total commission earned
    const totalCommission = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          type: 'Commission Credit'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    // Get today's commission
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todayCommission = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          type: 'Commission Credit',
          createdAt: { $gte: today }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    // Get this month's commission
    const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    
    const monthCommission = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          type: 'Commission Credit',
          createdAt: { $gte: firstDayOfMonth }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    // Get commission by source
    const bySource = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          type: 'Commission Credit'
        }
      },
      {
        $group: {
          _id: '$metadata.commissionSource',
          count: { $sum: 1 },
          total: { $sum: '$amount' }
        }
      },
      {
        $sort: { total: -1 }
      }
    ]);
    
    // Get recent commission transactions
    const recentCommissions = await Transaction.find({
      userId: userId,
      isCommission: true
    })
    .sort({ createdAt: -1 })
    .limit(5)
    .lean();
    
    res.json({
      success: true,
      data: {
        currentBalance: user.commissionBalance,
        totalEarned: totalCommission[0]?.total || 0,
        todayEarned: todayCommission[0]?.total || 0,
        monthEarned: monthCommission[0]?.total || 0,
        bySource: bySource,
        recentCommissions: recentCommissions,
        formatted: {
          currentBalance: formatCurrency(user.commissionBalance),
          totalEarned: formatCurrency(totalCommission[0]?.total || 0),
          todayEarned: formatCurrency(todayCommission[0]?.total || 0),
          monthEarned: formatCurrency(monthCommission[0]?.total || 0)
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Commission stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get commission statistics'
    });
  }
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

// @desc    Use commission for service purchase - FIXED VERSION (NO DUPLICATE COMMISSION)
// @route   POST /api/commission/use-for-service
// @access  Private
router.post('/use-for-service', protect, verifyTransactionAuth, async (req, res) => {
  const session = await mongoose.startSession();
  
  try {
    await session.startTransaction();
    
    const {
      serviceType,
      amount,
      serviceDetails
    } = req.body;
    
    const userId = req.user._id;
    
    // Validate input
    if (!serviceType || !amount || !serviceDetails) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }
    
    const serviceAmount = parseFloat(amount);
    
    if (serviceAmount <= 0) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Amount must be greater than 0'
      });
    }
    
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if user has enough commission balance
    if (user.commissionBalance < serviceAmount) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: `Insufficient commission balance. Available: ${formatCurrency(user.commissionBalance)}`
      });
    }
    
    // ================================================
    // 🔥 CRITICAL FIX: DON'T CREATE COMMISSION CREDIT
    // When using commission to pay, we only DEDUCT commission
    // NO commission should be earned for this transaction
    // ================================================
    
    // 1. Deduct commission from user's balance
    const balanceBefore = user.commissionBalance;
    user.commissionBalance -= serviceAmount;
    
    // 2. Save user
    await user.save({ session });
    
    // 3. Create ONLY the commission debit transaction
    // This is NOT a commission earning, it's commission spending
    const commissionTransaction = new Transaction({
      userId: userId,
      amount: serviceAmount,
      type: 'Commission Debit', // NOT 'Commission Credit'
      status: 'Successful',
      description: `Commission used for ${serviceType} purchase`,
      balanceBefore: balanceBefore,
      balanceAfter: user.commissionBalance,
      metadata: {
        serviceType: serviceType,
        serviceDetails: serviceDetails,
        paymentMethod: 'commission',
        commissionUsed: true,
        walletUsed: false,
        isCommissionPayment: true // NEW FLAG to identify commission payments
      },
      isCommission: true, // This IS a commission transaction
      commissionAction: 'debit', // NEW: specify it's a debit
      gateway: 'DalaBaPay App',
      reference: `COMM_DEBIT_${Date.now()}_${Math.floor(Math.random() * 1000)}`
    });
    
    await commissionTransaction.save({ session });
    
    // 4. Commit transaction
    await session.commitTransaction();
    
    console.log(`✅ Commission used for ${serviceType}: ₦${serviceAmount.toFixed(2)}`);
    console.log(`   New commission balance: ₦${user.commissionBalance.toFixed(2)}`);
    console.log(`   Commission transaction ID: ${commissionTransaction._id}`);
    
    res.json({
      success: true,
      message: `${formatCurrency(serviceAmount)} commission allocated for ${serviceType} purchase`,
      data: {
        newCommissionBalance: user.commissionBalance,
        formattedNewCommissionBalance: formatCurrency(user.commissionBalance),
        transactionId: commissionTransaction._id,
        commissionTransaction: commissionTransaction,
        commissionOnly: true,
        noCommissionEarned: true // NEW: Tell frontend NOT to expect commission
      }
    });
    
  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Commission deduction error:', error);
    res.status(400).json({
      success: false,
      message: error.message || 'Failed to use commission'
    });
  } finally {
    session.endSession();
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
