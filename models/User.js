// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');const userSchema = mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    phone: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    transactionPin: { 
      type: String 
    },
     transactionPinSet: {  // ← ADD THIS FIELD
      type: Boolean,
      default: false
    },
    password: {
      type: String,
      required: true,
    },
    walletBalance: {
      type: Number,
      default: 0.0,
    },
    commissionBalance: {
      type: Number,
      default: 0.0,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isActive: {
      type: Boolean,
      default: true,
    },// === NEW FIELDS TO ADD ===

// Referral system fields
referralCode: {
  type: String,
  unique: true,
  sparse: true,
  trim: true,
},
referrerId: {
  type: mongoose.Schema.Types.ObjectId,
  ref: 'User',
  default: null,
},
referralCount: {
  type: Number,
  default: 0,
},
totalReferralEarnings: {
  type: Number,
  default: 0.0,
},

// Authentication fields
refreshToken: {
  type: String,
  default: null,
},
resetPasswordToken: {
  type: String,
  default: null,
},
resetPasswordExpire: {
  type: Date,
  default: null,
},

// Security fields
failedPinAttempts: {
  type: Number,
  default: 0,
},
pinLockedUntil: {
  type: Date,
  default: null,
},
biometricEnabled: {
  type: Boolean,
  default: false,
},
biometricKey: {
  type: String,
  default: null,
},
biometricCredentialId: {
  type: String,
  default: null,
},

// Profile fields
profileImage: {
  type: String,
  default: null,
},
lastLoginAt: {
  type: Date,
  default: null,
},

// First transaction tracking
isFirstTransaction: {
  type: Boolean,
  default: true,
},
hasReceivedFirstTransactionBonus: {
  type: Boolean,
  default: false,
},

// Virtual Account fields
virtualAccount: {
  assigned: { 
    type: Boolean, 
    default: false 
  },
  bankName: { 
    type: String, 
    default: '' 
  },
  accountNumber: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  accountName: { 
    type: String, 
    default: '' 
  },
  reference: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
},  },
  {
    timestamps: true,
  }
);// Hash transaction PIN before saving if modified
userSchema.pre('save', async function (next) {
  if (this.isModified('transactionPin') && this.transactionPin) {
    console.log(DEBUG (User Model Pre-Save): Hashing transaction PIN for user ${this.email});
    const salt = await bcrypt.genSalt(10);
    this.transactionPin = await bcrypt.hash(this.transactionPin, salt);
  }
  next();
});// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};// Method to compare transaction PIN
userSchema.methods.matchTransactionPin = async function (enteredPin) {
  if (!this.transactionPin) {
    return false;
  }
  return await bcrypt.compare(enteredPin, this.transactionPin);
};// Method to check if PIN is locked
userSchema.methods.isPinLocked = function () {
  return this.pinLockedUntil && this.pinLockedUntil > new Date();
};// Method to get remaining lock time in minutes
userSchema.methods.getRemainingLockTime = function () {
  if (!this.pinLockedUntil) return 0;
  const now = new Date();
  const diff = this.pinLockedUntil - now;
  return Math.ceil(diff / (1000 * 60)); // Convert to minutes
};// Method to increment failed PIN attempts
userSchema.methods.incrementFailedPinAttempts = function () {
  this.failedPinAttempts += 1;  // Lock account after 3 failed attempts for 15 minutes
  if (this.failedPinAttempts >= 3) {
    this.pinLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  }  return this.save();
};// Method to reset failed PIN attempts (on successful PIN entry)
userSchema.methods.resetFailedPinAttempts = function () {
  this.failedPinAttempts = 0;
  this.pinLockedUntil = null;
  return this.save();
};// Static method to find user by referral code
userSchema.statics.findByReferralCode = function (referralCode) {
  return this.findOne({ referralCode: referralCode.toUpperCase() });
};// Virtual for formatted wallet balance
userSchema.virtual('formattedWalletBalance').get(function () {
  return ₦${this.walletBalance.toFixed(2)};
});// Virtual for formatted commission balance
userSchema.virtual('formattedCommissionBalance').get(function () {
  return ₦${this.commissionBalance.toFixed(2)};
});// Add to models/User.js after existing methods// Method to verify transaction PIN with lock checking
userSchema.methods.verifyTransactionPin = async function (enteredPin) {
  try {
    // Check if PIN is locked
    if (this.isPinLocked()) {
      const remainingTime = this.getRemainingLockTime();
      throw new Error(Account locked. Try again in ${remainingTime} minutes.);
    }if (!this.transactionPin) {
  return { success: false, message: 'Transaction PIN not set' };
}

const isMatch = await bcrypt.compare(enteredPin, this.transactionPin);

if (isMatch) {
  // Reset failed attempts on success
  await this.resetFailedPinAttempts();
  return { success: true, message: 'PIN verified successfully' };
} else {
  // Increment failed attempts
  await this.incrementFailedPinAttempts();
  
  if (this.failedPinAttempts >= 3) {
    return { 
      success: false, 
      message: 'Account locked for 15 minutes due to multiple failed attempts' 
    };
  }
  
  const remainingAttempts = 3 - this.failedPinAttempts;
  return { 
    success: false, 
    message: `Invalid PIN. ${remainingAttempts} attempts remaining` 
  };
}  } catch (error) {
    console.error('Error verifying PIN:', error);
    return { success: false, message: error.message };
  }
};// Method to check commission balance
userSchema.methods.checkCommissionBalance = function (amount) {
  if (this.commissionBalance < amount) {
    return {
      success: false,
      available: this.commissionBalance,
      required: amount,
      message: Insufficient commission balance. Available: ₦${this.commissionBalance.toFixed(2)}
    };
  }
  return {
    success: true,
    available: this.commissionBalance,
    required: amount,
    message: 'Sufficient commission balance'
  };
};// Method to deduct commission for service purchase
userSchema.methods.deductCommissionForService = async function (amount, serviceType, serviceDetails) {
  const session = await mongoose.startSession();
  session.startTransaction();  try {
    const balanceCheck = this.checkCommissionBalance(amount);
    if (!balanceCheck.success) {
      throw new Error(balanceCheck.message);
    }const oldCommissionBalance = this.commissionBalance;
this.commissionBalance -= amount;

// Create commission transaction
const commissionTransaction = new Transaction({
  userId: this._id,
  type: 'Commission Debit', // Using your Transaction model enum
  amount: amount,
  status: 'Pending', // Will update after VTPass success
  description: `Commission used for ${serviceType} purchase`,
  balanceBefore: oldCommissionBalance,
  balanceAfter: this.commissionBalance,
  isCommission: true,
  service: serviceType,
  metadata: {
    ...serviceDetails,
    commissionUsed: true,
    serviceType: serviceType,
    timestamp: new Date()
  }
});

await this.save({ session });
await commissionTransaction.save({ session });

await session.commitTransaction();

return {
  success: true,
  newCommissionBalance: this.commissionBalance,
  deductedAmount: amount,
  transactionId: commissionTransaction._id,
  commissionTransaction: commissionTransaction
};  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};// Method to withdraw commission to main wallet
userSchema.methods.withdrawCommissionToWallet = async function (amount, transactionPin = null) {
  const session = await mongoose.startSession();
  session.startTransaction();  try {
    // Verify PIN if provided
    if (transactionPin) {
      const pinVerification = await this.verifyTransactionPin(transactionPin);
      if (!pinVerification.success) {
        throw new Error(pinVerification.message);
      }
    }// Check balance
const balanceCheck = this.checkCommissionBalance(amount);
if (!balanceCheck.success) {
  throw new Error(balanceCheck.message);
}

// Check minimum withdrawal
if (amount < 500) {
  throw new Error('Minimum withdrawal amount is ₦500');
}

const oldCommissionBalance = this.commissionBalance;
const oldWalletBalance = this.walletBalance || 0;

// Deduct from commission
this.commissionBalance -= amount;

// Add to main wallet
this.walletBalance = (this.walletBalance || 0) + amount;

// Create commission withdrawal transaction
const commissionTransaction = new Transaction({
  userId: this._id,
  type: 'Commission Withdrawal',
  amount: amount,
  status: 'Successful',
  description: 'Commission withdrawn to main wallet',
  balanceBefore: oldCommissionBalance,
  balanceAfter: this.commissionBalance,
  isCommission: true,
  service: 'commission_withdrawal',
  metadata: {
    withdrawal: true,
    destination: 'main_wallet',
    oldWalletBalance: oldWalletBalance,
    newWalletBalance: this.walletBalance,
    withdrawalType: 'commission_to_wallet'
  }
});

// Create wallet credit transaction
const walletTransaction = new Transaction({
  userId: this._id,
  type: 'Commission Credit',
  amount: amount,
  status: 'Successful',
  description: 'Commission transferred to main wallet',
  balanceBefore: oldWalletBalance,
  balanceAfter: this.walletBalance,
  isCommission: false,
  service: 'wallet_credit',
  metadata: {
    source: 'commission_wallet',
    commissionTransactionId: commissionTransaction._id,
    commissionAmount: amount
  }
});

await this.save({ session });
await commissionTransaction.save({ session });
await walletTransaction.save({ session });

await session.commitTransaction();

return {
  success: true,
  newCommissionBalance: this.commissionBalance,
  newWalletBalance: this.walletBalance,
  commissionTransactionId: commissionTransaction._id,
  walletTransactionId: walletTransaction._id,
  message: `₦${amount.toFixed(2)} successfully withdrawn to main wallet`
};  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};// Method to refund commission (if VTPass transaction fails)
userSchema.methods.refundCommission = async function (amount, originalTransactionId) {
  const session = await mongoose.startSession();
  session.startTransaction();  try {
    const oldCommissionBalance = this.commissionBalance;
    this.commissionBalance += amount;// Create refund transaction
const refundTransaction = new Transaction({
  userId: this._id,
  type: 'Commission Credit', // This is correct for refund
  amount: amount,
  status: 'Successful',
  description: 'Commission refunded - Service purchase failed',
  balanceBefore: oldCommissionBalance,
  balanceAfter: this.commissionBalance,
  isCommission: true,
  service: 'commission_refund',
  metadata: {
    refund: true,
    originalTransactionId: originalTransactionId,
    refundReason: 'service_purchase_failed',
    timestamp: new Date()
  }
});

// Update original transaction status
await Transaction.findByIdAndUpdate(
  originalTransactionId,
  {
    status: 'Failed',
    'metadata.refunded': true,
    'metadata.refundTransactionId': refundTransaction._id
  },
  { session }
);

await this.save({ session });
await refundTransaction.save({ session });

await session.commitTransaction();

return {
  success: true,
  newCommissionBalance: this.commissionBalance,
  refundTransactionId: refundTransaction._id
};  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};// Index for better performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ referralCode: 1 });
userSchema.index({ referrerId: 1 });
userSchema.index({ 'virtualAccount.accountNumber': 1 });module.exports = mongoose.models.User || mongoose.model('User', userSchema);vtpass-backend/routes/commissionRoutes.js
// routes/commissionRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { protect } = require('../middleware/auth');
const { verifyTransactionAuth } = require('../middleware/transactionAuth');// @desc    Get commission balance
// @route   GET /api/commission/balance
// @access  Private
router.get('/balance', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('commissionBalance walletBalance fullName email phone');if (!user) {
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
});  } catch (error) {
    console.error(' Get commission balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get commission balance'
    });
  }
});// @desc    Withdraw commission to main wallet
// @route   POST /api/commission/withdraw
// @access  Private
router.post('/withdraw', protect, async (req, res) => {
  try {
    const { amount, transactionPin, useBiometric } = req.body;
    const userId = req.user._id;// Validate amount
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
    console.error(' Commission withdrawal processing error:', error);
    res.status(400).json({
      success: false,
      message: error.message || 'Failed to process withdrawal'
    });
  }
});  } catch (error) {
    console.error(' Commission withdrawal error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});// @desc    Get commission transactions
// @route   GET /api/commission/transactions
// @access  Private
router.get('/transactions', protect, async (req, res) => {
  try {
    const { page = 1, limit = 20, type, status, startDate, endDate } = req.query;
    const userId = req.user._id;const query = { userId, isCommission: true };

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
});  } catch (error) {
    console.error(' Get commission transactions error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get commission transactions'
    });
  }
});// @desc    Use commission for service purchase
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
    } = req.body;const userId = req.user._id;

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
    console.error(' Commission deduction error:', error);
    res.status(400).json({
      success: false,
      message: error.message || 'Failed to use commission'
    });
  }
});  } catch (error) {
    console.error(' Use commission for service error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});// @desc    Complete commission-based service purchase (called after VTPass success)
// @route   POST /api/commission/complete-service-purchase
// @access  Private
router.post('/complete-service-purchase', protect, async (req, res) => {
  try {
    const { transactionId, vtpassResponse, status = 'Successful' } = req.body;if (!transactionId) {
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
});  } catch (error) {
    console.error(' Complete service purchase error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete service purchase'
    });
  }
});// @desc    Refund commission (if service purchase fails)
// @route   POST /api/commission/refund
// @access  Private
router.post('/refund', protect, async (req, res) => {
  try {
    const { transactionId } = req.body;if (!transactionId) {
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
});  } catch (error) {
    console.error(' Commission refund error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process refund'
    });
  }
});module.exports = router;

