// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Transaction = require('./Transaction');

const userSchema = mongoose.Schema(
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
    transactionPinSet: {  
      type: Boolean,
      default: false
    },
    password: {
      type: String,
      required: true,
    },
    
    // ========== PASSWORD RESET OTP FIELDS ==========
    resetPasswordOTP: {
      type: String,
      default: null,
    },
    resetPasswordOTPExpire: {
      type: Date,
      default: null,
    },
    resetPasswordOTPAttempts: {
      type: Number,
      default: 0,
    },
    resetPasswordOTPLockedUntil: {
      type: Date,
      default: null,
    },
    // =============================================
    
    // ========== PIN RESET OTP FIELDS ==========
    pinResetToken: {
      type: String,
      default: null,
    },
    pinResetTokenExpires: {
      type: Date,
      default: null,
    },
    pinResetTokenAttempts: {
      type: Number,
      default: 0,
    },
    pinResetTokenVerified: {
      type: Boolean,
      default: false,
    },
    // ==========================================
    
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
    },
    
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

    pendingCommission: {
  type: Number,
  default: 0.0,
},
lastCommissionAwarded: {
  type: Date,
  default: null,
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
    },
  },
  {
    timestamps: true,
  }
);

// ========== FIXED OTP METHODS (Renamed to avoid conflicts) ==========

// Method to check if password reset OTP is locked
userSchema.methods.isOTPLocked = function () {
  return this.resetPasswordOTPLockedUntil && this.resetPasswordOTPLockedUntil > new Date();
};

// Method to get remaining OTP lock time
userSchema.methods.getOTPLockRemaining = function () {
  if (!this.resetPasswordOTPLockedUntil) return 0;
  const now = new Date();
  const diff = this.resetPasswordOTPLockedUntil - now;
  return Math.ceil(diff / (1000 * 60)); // Convert to minutes
};

// Method to increment failed OTP attempts
userSchema.methods.incrementOTPAttempts = async function () {
  this.resetPasswordOTPAttempts += 1;
  
  // Lock OTP verification after 3 failed attempts for 30 minutes
  if (this.resetPasswordOTPAttempts >= 3) {
    this.resetPasswordOTPLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  }
  
  return this.save();
};

// Method to reset OTP attempts (on successful verification)
userSchema.methods.resetOTPAttempts = async function () {
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  return this.save();
};

// Method to verify password reset OTP
userSchema.methods.verifyOTP = async function (otp) {
  try {
    // Check if OTP verification is locked
    if (this.isOTPLocked()) {
      const remainingTime = this.getOTPLockRemaining();
      return {
        success: false,
        locked: true,
        message: `OTP verification locked. Try again in ${remainingTime} minutes.`
      };
    }

    // Check if OTP exists
    if (!this.resetPasswordOTP) {
      return {
        success: false,
        message: 'No OTP requested. Please request a new OTP.'
      };
    }

    // Check if OTP has expired
    if (!this.resetPasswordOTPExpire || this.resetPasswordOTPExpire < new Date()) {
      // Clear expired OTP
      this.resetPasswordOTP = null;
      this.resetPasswordOTPExpire = null;
      await this.save();
      
      return {
        success: false,
        expired: true,
        message: 'OTP has expired. Please request a new one.'
      };
    }

    // Verify OTP matches (string comparison)
    const isMatch = this.resetPasswordOTP === otp;
    
    if (isMatch) {
      // Reset failed attempts on success
      await this.resetOTPAttempts();
      return {
        success: true,
        message: 'OTP verified successfully'
      };
    } else {
      // Increment failed attempts
      await this.incrementOTPAttempts();
      
      if (this.resetPasswordOTPAttempts >= 3) {
        return {
          success: false,
          locked: true,
          message: 'OTP verification locked for 30 minutes due to multiple failed attempts'
        };
      }
      
      const remainingAttempts = 3 - this.resetPasswordOTPAttempts;
      return {
        success: false,
        message: `Invalid OTP. ${remainingAttempts} attempts remaining`
      };
    }
  } catch (error) {
    console.error('Error verifying password reset OTP:', error);
    return {
      success: false,
      message: 'Error verifying OTP. Please try again.'
    };
  }
};

// Method to set password reset OTP
userSchema.methods.setOTP = async function (otp) {
  this.resetPasswordOTP = otp;
  this.resetPasswordOTPExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  this.resetPasswordToken = null;
  this.resetPasswordExpire = null;
  
  return this.save();
};

// Method to clear password reset OTP
userSchema.methods.clearOTP = async function () {
  this.resetPasswordOTP = null;
  this.resetPasswordOTPExpire = null;
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  
  return this.save();
};

// Method to generate and set password reset token (after OTP verification)
userSchema.methods.generateResetToken = async function () {
  const crypto = require('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.resetPasswordToken = resetToken;
  this.resetPasswordExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  
  // Clear OTP
  this.resetPasswordOTP = null;
  this.resetPasswordOTPExpire = null;
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  
  await this.save();
  
  return resetToken;
};

// Method to verify password reset token
userSchema.methods.isResetTokenValid = function (token) {
  if (!this.resetPasswordToken || !this.resetPasswordExpire) {
    return false;
  }
  
  const isValid = this.resetPasswordToken === token && this.resetPasswordExpire > new Date();
  return isValid;
};

// Method to clear password reset token (after successful reset)
userSchema.methods.clearResetToken = async function () {
  this.resetPasswordToken = null;
  this.resetPasswordExpire = null;
  
  return this.save();
};

// ========== END OF FIXED OTP METHODS ==========

// Hash transaction PIN before saving if modified
userSchema.pre('save', async function (next) {
  // Only hash transactionPin if it's a 6-digit number
  if (this.isModified('transactionPin') && this.transactionPin) {
    // Check if it's already hashed (starts with $2a$ or $2b$)
    if (!this.transactionPin.startsWith('$2a$') && !this.transactionPin.startsWith('$2b$')) {
      // Only hash if it's 6 digits (raw PIN)
      if (/^\d{6}$/.test(this.transactionPin)) {
        console.log(`DEBUG (User Model Pre-Save): Hashing transaction PIN for user ${this.email}`);
        const salt = await bcrypt.genSalt(10);
        this.transactionPin = await bcrypt.hash(this.transactionPin, salt);
      }
    }
  }
  next();
});

// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to compare transaction PIN
userSchema.methods.matchTransactionPin = async function (enteredPin) {
  if (!this.transactionPin) {
    return false;
  }
  return await bcrypt.compare(enteredPin, this.transactionPin);
};

// Method to check if PIN is locked
userSchema.methods.isPinLocked = function () {
  return this.pinLockedUntil && this.pinLockedUntil > new Date();
};

// Method to get remaining lock time in minutes
userSchema.methods.getRemainingLockTime = function () {
  if (!this.pinLockedUntil) return 0;
  const now = new Date();
  const diff = this.pinLockedUntil - now;
  return Math.ceil(diff / (1000 * 60)); // Convert to minutes
};

// Method to increment failed PIN attempts
userSchema.methods.incrementFailedPinAttempts = function () {
  this.failedPinAttempts += 1;
  
  // Lock account after 3 failed attempts for 15 minutes
  if (this.failedPinAttempts >= 3) {
    this.pinLockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
  }
  
  return this.save();
};

// Method to reset failed PIN attempts (on successful PIN entry)
userSchema.methods.resetFailedPinAttempts = function () {
  this.failedPinAttempts = 0;
  this.pinLockedUntil = null;
  return this.save();
};

// Static method to find user by referral code
userSchema.statics.findByReferralCode = function (referralCode) {
  return this.findOne({ referralCode: referralCode.toUpperCase() });
};

// Virtual for formatted wallet balance
userSchema.virtual('formattedWalletBalance').get(function () {
  return `₦${this.walletBalance.toFixed(2)}`;
});

// Virtual for formatted commission balance
userSchema.virtual('formattedCommissionBalance').get(function () {
  return `₦${this.commissionBalance.toFixed(2)}`;
});

// Method to verify transaction PIN with lock checking
userSchema.methods.verifyTransactionPin = async function (enteredPin) {
  try {
    // Check if PIN is locked
    if (this.isPinLocked()) {
      const remainingTime = this.getRemainingLockTime();
      throw new Error(`Account locked. Try again in ${remainingTime} minutes.`);
    }

    if (!this.transactionPin) {
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
    }
  } catch (error) {
    console.error('Error verifying PIN:', error);
    return { success: false, message: error.message };
  }
};

// Method to check commission balance
userSchema.methods.checkCommissionBalance = function (amount) {
  if (this.commissionBalance < amount) {
    return {
      success: false,
      available: this.commissionBalance,
      required: amount,
      message: `Insufficient commission balance. Available: ₦${this.commissionBalance.toFixed(2)}`
    };
  }
  return {
    success: true,
    available: this.commissionBalance,
    required: amount,
    message: 'Sufficient commission balance'
  };
};

// Method to deduct commission for service purchase
userSchema.methods.deductCommissionForService = async function (amount, serviceType, serviceDetails) {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const balanceCheck = this.checkCommissionBalance(amount);
    if (!balanceCheck.success) {
      throw new Error(balanceCheck.message);
    }
    
    const oldCommissionBalance = this.commissionBalance;
    this.commissionBalance -= amount;
    
    // Create commission transaction
    const commissionTransaction = new Transaction({
      userId: this._id,
      type: 'Commission Debit',
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
    };
    
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};

// Method to withdraw commission to main wallet
userSchema.methods.withdrawCommissionToWallet = async function (amount, transactionPin = null) {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    // Verify PIN if provided
    if (transactionPin) {
      const pinVerification = await this.verifyTransactionPin(transactionPin);
      if (!pinVerification.success) {
        throw new Error(pinVerification.message);
      }
    }
    
    // Check balance
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
    };
    
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};

// Method to refund commission (if VTPass transaction fails)
userSchema.methods.refundCommission = async function (amount, originalTransactionId) {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const oldCommissionBalance = this.commissionBalance;
    this.commissionBalance += amount;
    
    // Create refund transaction
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
    };
    
  } catch (error) {
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};

// Index for better performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ referralCode: 1 });
userSchema.index({ referrerId: 1 });
userSchema.index({ 'virtualAccount.accountNumber': 1 });
userSchema.index({ resetPasswordOTP: 1 });
userSchema.index({ resetPasswordOTPExpire: 1 });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
