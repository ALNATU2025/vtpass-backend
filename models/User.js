// models/User.js - COMPLETE REPLACEMENT
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

    // Add this inside your User schema definition
fcmToken: {
  type: String,
  default: null,
  index: true
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
    
    // ========== ROLE BASED ACCESS CONTROL ==========
    role: {
      type: String,
      enum: ['user', 'admin', 'super_admin', 'support', 'finance'],
      default: 'user'
    },
    roleLevel: {
      type: Number,
      default: 0
    },
    permissions: {
      type: [String],
      default: ['view_profile', 'make_transactions']
    },
    department: {
      type: String,
      enum: ['management', 'support', 'finance', 'operations', 'development', 'none'],
      default: 'none'
    },
    assignedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    roleChangedAt: {
      type: Date,
      default: Date.now
    },
    // BACKWARD COMPATIBILITY - Keep these
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isSuperAdmin: {
      type: Boolean,
      default: false,
    },
    // =============================================
    
    isActive: {
      type: Boolean,
      default: true,
    },

    welcomeBonusReceived: {
      type: Boolean,
      default: false
    },
    firstDepositBonusReceived: {
      type: Boolean,
      default: false
    },
    firstDepositMade: {
      type: Boolean,
      default: false
    },
    welcomeBonusAmount: {
      type: Number,
      default: 0
    },
    referralBonusAwarded: {
      type: Boolean,
      default: false
    },
    indirectBonusAwardedLevel2: {
      type: Boolean,
      default: false
    },
    indirectBonusAwardedLevel3: {
      type: Boolean,
      default: false
    },
    referralTier: {
      type: String,
      enum: ['Bronze', 'Silver', 'Gold', 'Platinum'],
      default: 'Bronze'
    },
    referrerCode: String,
    referrerName: String,
    referralCount: {
      type: Number,
      default: 0
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
        default: null 
      },
      accountNumber: { 
        type: String, 
        default: null,
        index: false
      },
      accountName: { 
        type: String, 
        default: null 
      },
      reference: { 
        type: String, 
        default: null,
        index: false
      },
    },
  },
  {
    timestamps: true,
  }
);

// ========== USER SCHEMA METHODS ==========

// Method to check if user has specific permission
userSchema.methods.hasPermission = function(permission) {
  // Super admin has all permissions
  if (this.isSuperAdmin || this.role === 'super_admin') {
    return true;
  }
  
  // Check user's permissions
  if (this.permissions && this.permissions.includes(permission)) {
    return true;
  }
  
  // Check role-based permissions (using the ROLE_DEFINITIONS from middleware)
  const ROLE_DEFINITIONS = {
    admin: {
      permissions: ['view_dashboard', 'view_users', 'manage_users', 'view_transactions', 
                    'view_all_transactions', 'update_transaction_status', 'manage_admins',
                    'manage_settings', 'view_reports', 'export_data', 'manage_notifications'],
      inherits: ['finance', 'support']
    },
    finance: {
      permissions: ['view_transactions', 'view_all_transactions', 'process_refunds', 
                    'view_disputes', 'resolve_disputes', 'view_reports', 'view_financial_reports',
                    'manage_wallet'],
      inherits: ['support']
    },
    support: {
      permissions: ['view_users', 'view_transactions', 'view_disputes', 'create_disputes',
                    'resolve_disputes', 'send_notifications', 'update_user_status'],
      inherits: ['user']
    },
    user: {
      permissions: ['view_profile', 'update_profile', 'view_own_transactions', 'make_transactions',
                    'create_own_disputes', 'view_own_disputes', 'view_commission']
    }
  };
  
  // Check role permissions
  const roleDef = ROLE_DEFINITIONS[this.role];
  if (roleDef) {
    if (roleDef.permissions && roleDef.permissions.includes(permission)) {
      return true;
    }
    // Check inherited permissions
    if (roleDef.inherits) {
      for (const inheritedRole of roleDef.inherits) {
        const inheritedDef = ROLE_DEFINITIONS[inheritedRole];
        if (inheritedDef && inheritedDef.permissions && inheritedDef.permissions.includes(permission)) {
          return true;
        }
      }
    }
  }
  
  // Backward compatibility
  if (this.isAdmin) {
    return true;
  }
  
  return false;
};

// Method to check if user has any of the specified roles
userSchema.methods.hasRole = function(roles) {
  if (this.isSuperAdmin || this.role === 'super_admin') {
    return true;
  }
  if (typeof roles === 'string') {
    return this.role === roles;
  }
  if (Array.isArray(roles)) {
    return roles.includes(this.role);
  }
  return false;
};

// Method to get user's role level
userSchema.methods.getRoleLevel = function() {
  const roleLevels = {
    'user': 0,
    'support': 2,
    'finance': 3,
    'admin': 4,
    'super_admin': 5
  };
  return this.roleLevel || roleLevels[this.role] || 0;
};

// Method to check if user can access a resource
userSchema.methods.canAccess = function(resource, action) {
  const permissionMap = {
    'transactions:view': 'view_transactions',
    'transactions:view_all': 'view_all_transactions',
    'transactions:update': 'update_transaction_status',
    'users:view': 'view_users',
    'users:manage': 'manage_users',
    'users:update_status': 'update_user_status',
    'refunds:process': 'process_refunds',
    'disputes:view': 'view_disputes',
    'disputes:resolve': 'resolve_disputes',
    'notifications:send': 'send_notifications',
    'settings:manage': 'manage_settings',
    'reports:view': 'view_reports',
    'wallet:manage': 'manage_wallet'
  };
  
  const permission = permissionMap[`${resource}:${action}`];
  if (!permission) return false;
  
  return this.hasPermission(permission);
};

// ========== EXISTING METHODS (Keep all your existing methods) ==========

// Hash transaction PIN before saving if modified
userSchema.pre('save', async function (next) {
  if (this.isModified('transactionPin') && this.transactionPin) {
    if (!this.transactionPin.startsWith('$2a$') && !this.transactionPin.startsWith('$2b$')) {
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
  return Math.ceil(diff / (1000 * 60));
};

// Method to increment failed PIN attempts
userSchema.methods.incrementFailedPinAttempts = function () {
  this.failedPinAttempts += 1;
  if (this.failedPinAttempts >= 3) {
    this.pinLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
  }
  return this.save();
};

// Method to reset failed PIN attempts
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
    if (this.isPinLocked()) {
      const remainingTime = this.getRemainingLockTime();
      throw new Error(`Account locked. Try again in ${remainingTime} minutes.`);
    }

    if (!this.transactionPin) {
      return { success: false, message: 'Transaction PIN not set' };
    }

    const isMatch = await bcrypt.compare(enteredPin, this.transactionPin);
    
    if (isMatch) {
      await this.resetFailedPinAttempts();
      return { success: true, message: 'PIN verified successfully' };
    } else {
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
  
  try {
    await session.startTransaction();
    
    console.log(`💰 DEDUCTING COMMISSION FOR SERVICE: ${serviceType}, Amount: ₦${amount}`);
    console.log(`📊 User: ${this.email}, Current commission: ₦${this.commissionBalance}`);
    
    if (this.commissionBalance < amount) {
      await session.abortTransaction();
      throw new Error(`Insufficient commission balance. Available: ₦${this.commissionBalance.toFixed(2)}, Required: ₦${amount.toFixed(2)}`);
    }
    
    const balanceBefore = this.commissionBalance;
    this.commissionBalance -= amount;
    
    const reference = `COMM_DEBIT_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
    
    const commissionTransaction = new Transaction({
      userId: this._id,
      type: 'Commission Debit',
      amount: amount,
      status: 'Pending',
      description: `Commission used for ${serviceType} purchase`,
      balanceBefore: balanceBefore,
      balanceAfter: this.commissionBalance,
      isCommission: true,
      service: serviceType,
      authenticationMethod: 'pin',
      gateway: 'DalaBaPay App',
      reference: reference,
      metadata: {
        ...serviceDetails,
        commissionUsed: true,
        walletUsed: false,
        serviceType: serviceType,
        originalService: serviceType,
        paymentMethod: 'commission',
        isCommissionPayment: true,
        commissionAction: 'debit',
        timestamp: new Date(),
        skipCommissionCalculation: true,
        noCommissionEarned: true,
        phone: serviceDetails.phone || '',
        network: serviceDetails.network || '',
        meterNumber: serviceDetails.meterNumber || serviceDetails.billersCode || '',
        smartcardNumber: serviceDetails.smartcardNumber || serviceDetails.billersCode || '',
        billersCode: serviceDetails.billersCode || '',
        variation_code: serviceDetails.variation_code || ''
      }
    });
    
    await this.save({ session });
    await commissionTransaction.save({ session });
    
    await session.commitTransaction();
    
    console.log(`✅ Commission deducted: ₦${amount.toFixed(2)}`);
    console.log(`   New commission balance: ₦${this.commissionBalance.toFixed(2)}`);
    console.log(`   Commission transaction ID: ${commissionTransaction._id}`);
    console.log(`   Reference: ${reference}`);
    
    return {
      success: true,
      newCommissionBalance: this.commissionBalance,
      deductedAmount: amount,
      transactionId: commissionTransaction._id,
      commissionTransaction: commissionTransaction,
      reference: reference,
      message: `Commission deducted for ${serviceType} purchase`
    };
    
  } catch (error) {
    console.error('❌ Commission deduction error:', error);
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
    if (transactionPin) {
      const pinVerification = await this.verifyTransactionPin(transactionPin);
      if (!pinVerification.success) {
        throw new Error(pinVerification.message);
      }
    }
    
    const balanceCheck = this.checkCommissionBalance(amount);
    if (!balanceCheck.success) {
      throw new Error(balanceCheck.message);
    }
    
    if (amount < 500) {
      throw new Error('Minimum withdrawal amount is ₦500');
    }
    
    const oldCommissionBalance = this.commissionBalance;
    const oldWalletBalance = this.walletBalance || 0;
    
    this.commissionBalance -= amount;
    this.walletBalance = (this.walletBalance || 0) + amount;
    
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

// Method to refund commission
userSchema.methods.refundCommission = async function (amount, originalTransactionId) {
  const session = await mongoose.startSession();
  
  try {
    await session.startTransaction();
    
    console.log(`🔄 REFUNDING COMMISSION: ₦${amount}, Original TXN: ${originalTransactionId}`);
    
    const oldCommissionBalance = this.commissionBalance;
    this.commissionBalance += amount;
    
    const refundTransaction = new Transaction({
      userId: this._id,
      type: 'Commission Refund',
      amount: amount,
      status: 'Successful',
      description: 'Commission refunded - Service purchase failed',
      balanceBefore: oldCommissionBalance,
      balanceAfter: this.commissionBalance,
      isCommission: true,
      service: 'commission_refund',
      authenticationMethod: 'system',
      gateway: 'DalaBaPay App',
      reference: `COMM_REFUND_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
      metadata: {
        refund: true,
        originalTransactionId: originalTransactionId,
        refundReason: 'service_purchase_failed',
        refundSource: 'commission_payment',
        timestamp: new Date(),
        isRefund: true,
        originalAmount: amount
      }
    });
    
    const originalTransaction = await Transaction.findById(originalTransactionId).session(session);
    if (originalTransaction) {
      originalTransaction.status = 'Failed';
      originalTransaction.metadata = {
        ...originalTransaction.metadata,
        refunded: true,
        refundTransactionId: refundTransaction._id,
        refundedAt: new Date()
      };
      await originalTransaction.save({ session });
    }
    
    await this.save({ session });
    await refundTransaction.save({ session });
    
    await session.commitTransaction();
    
    console.log(`✅ Commission refunded: ₦${amount.toFixed(2)}`);
    console.log(`   New commission balance: ₦${this.commissionBalance.toFixed(2)}`);
    console.log(`   Refund transaction ID: ${refundTransaction._id}`);
    
    return {
      success: true,
      newCommissionBalance: this.commissionBalance,
      refundTransactionId: refundTransaction._id,
      message: `Commission refunded successfully`
    };
    
  } catch (error) {
    console.error('❌ Commission refund error:', error);
    await session.abortTransaction();
    throw error;
  } finally {
    session.endSession();
  }
};

// ========== OTP METHODS (Keep your existing ones) ==========

userSchema.methods.isOTPLocked = function () {
  return this.resetPasswordOTPLockedUntil && this.resetPasswordOTPLockedUntil > new Date();
};

userSchema.methods.getOTPLockRemaining = function () {
  if (!this.resetPasswordOTPLockedUntil) return 0;
  const now = new Date();
  const diff = this.resetPasswordOTPLockedUntil - now;
  return Math.ceil(diff / (1000 * 60));
};

userSchema.methods.incrementOTPAttempts = async function () {
  this.resetPasswordOTPAttempts += 1;
  if (this.resetPasswordOTPAttempts >= 3) {
    this.resetPasswordOTPLockedUntil = new Date(Date.now() + 30 * 60 * 1000);
  }
  return this.save();
};

userSchema.methods.resetOTPAttempts = async function () {
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  return this.save();
};

userSchema.methods.verifyOTP = async function (otp) {
  try {
    if (this.isOTPLocked()) {
      const remainingTime = this.getOTPLockRemaining();
      return {
        success: false,
        locked: true,
        message: `OTP verification locked. Try again in ${remainingTime} minutes.`
      };
    }

    if (!this.resetPasswordOTP) {
      return {
        success: false,
        message: 'No OTP requested. Please request a new OTP.'
      };
    }

    if (!this.resetPasswordOTPExpire || this.resetPasswordOTPExpire < new Date()) {
      this.resetPasswordOTP = null;
      this.resetPasswordOTPExpire = null;
      await this.save();
      
      return {
        success: false,
        expired: true,
        message: 'OTP has expired. Please request a new one.'
      };
    }

    const isMatch = this.resetPasswordOTP === otp;
    
    if (isMatch) {
      await this.resetOTPAttempts();
      return {
        success: true,
        message: 'OTP verified successfully'
      };
    } else {
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

userSchema.methods.setOTP = async function (otp) {
  this.resetPasswordOTP = otp;
  this.resetPasswordOTPExpire = new Date(Date.now() + 10 * 60 * 1000);
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  this.resetPasswordToken = null;
  this.resetPasswordExpire = null;
  return this.save();
};

userSchema.methods.clearOTP = async function () {
  this.resetPasswordOTP = null;
  this.resetPasswordOTPExpire = null;
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  return this.save();
};

userSchema.methods.generateResetToken = async function () {
  const crypto = require('crypto');
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.resetPasswordToken = resetToken;
  this.resetPasswordExpire = new Date(Date.now() + 10 * 60 * 1000);
  
  this.resetPasswordOTP = null;
  this.resetPasswordOTPExpire = null;
  this.resetPasswordOTPAttempts = 0;
  this.resetPasswordOTPLockedUntil = null;
  
  await this.save();
  return resetToken;
};

userSchema.methods.isResetTokenValid = function (token) {
  if (!this.resetPasswordToken || !this.resetPasswordExpire) {
    return false;
  }
  return this.resetPasswordToken === token && this.resetPasswordExpire > new Date();
};

userSchema.methods.clearResetToken = async function () {
  this.resetPasswordToken = null;
  this.resetPasswordExpire = null;
  return this.save();
};

// Indexes
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ referralCode: 1 });
userSchema.index({ referrerId: 1 });
userSchema.index({ 'virtualAccount.accountNumber': 1 });
userSchema.index({ resetPasswordOTP: 1 });
userSchema.index({ resetPasswordOTPExpire: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isAdmin: 1 });
userSchema.index({ isSuperAdmin: 1 });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
