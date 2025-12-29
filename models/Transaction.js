//models/transaction.js
const mongoose = require('mongoose');

const metadataSchema = new mongoose.Schema({
    phone: { type: String },
    smartcardNumber: { type: String },
    billersCode: { type: String },
    variation_code: { type: String },
    packageName: { type: String },
    serviceID: { type: String },
    selectedPackage: { type: String },
    meterNumber: { type: String },
    provider: { type: String },
    type: { type: String },
    token: { type: String },
    customerName: { type: String },
    customerAddress: { type: String },
    exchangeReference: { type: String },
    vtpassResponse: { type: mongoose.Schema.Types.Mixed },
    paystackData: { type: mongoose.Schema.Types.Mixed },
    verificationHistory: [{
        method: { type: String, enum: ['polling', 'webhook', 'callback', 'manual'] },
        timestamp: { type: Date, default: Date.now },
        status: { type: String },
        response: { type: mongoose.Schema.Types.Mixed }
    }]
}, { _id: false });

const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: false,
        index: true,
        sparse: true
    },
    type: {
        type: String,
        enum: [
            // Service transactions
            'Airtime Purchase',
            'Data Purchase',
            'Cable TV Subscription',
            'Cable TV Purchase',
            'Electricity Payment',
            'Electricity Purchase',
            'Insurance Purchase',
            'Education Purchase',
            'Wallet Funding',
            'Transfer Sent',
            'Transfer Received',
            
            // Commission transactions
            'Commission Credit',                  // Generic commission
            'Transfer Commission Credit',
            'Airtime Commission Credit',
            'Data Commission Credit',
            'Cable TV Commission Credit',
            'Electricity Commission Credit',
            'Education Commission Credit',
            'Insurance Commission Credit',
            'Wallet Funding Commission Credit',
            'Commission Withdrawal',
            'Commission Debit',
            'Commission used for service purchase',
            
            // Other types
            'debit',
            'credit',
            'wallet_funding',
            'virtual_account_topup'
        ],
        required: true
    },



      isFailed: { 
        type: Boolean, 
        default: false, 
        index: true 
    },
    shouldShowAsFailed: { 
        type: Boolean, 
        default: false 
    },
    amountBelowMinimum: {
        type: Boolean,
        default: false
    },
    minimumAmountViolation: {
        amount: Number,
        requiredMinimum: Number,
        message: String
    },




    
    amount: { type: Number, required: true, min: 0 },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed', 'Processing', 'Refunded'],
        default: 'Pending'
    },
    transactionId: { 
        type: String, 
        unique: true, 
        sparse: true,
        default: function() {
            return `TXN_${Date.now()}_${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
        }
    },

    userEmailSnapshot: { type: String, index: true },
    userNameSnapshot: { type: String },

    isSystemTransaction: {
    type: Boolean,
    default: false,
    index: true
},
    
    reference: { 
        type: String, 
        unique: true, 
        index: true,
        default: function() {
            // Generate unique reference
            const timestamp = Date.now();
            const random = Math.floor(Math.random() * 1000000);
            return `REF_${timestamp}_${random}`;
        }
    },
    description: { type: String, required: true },
    balanceBefore: { type: Number, default: 0 },
    balanceAfter: { type: Number, default: 0 },
    metadata: metadataSchema,
    isCommission: { type: Boolean, default: false, index: true },
    service: { type: String, default: '', index: true },
    authenticationMethod: {
        type: String,
        enum: ['pin', 'biometric', 'none', 'paystack', 'manual'],
        default: 'none'
    },
    gateway: { type: String, default: 'paystack' },
    gatewayResponse: { type: mongoose.Schema.Types.Mixed },
    gatewayReference: { type: String, index: true },
    retryCount: { type: Number, default: 0, max: 3 },
    lastVerifiedAt: Date,
    verificationAttempts: { type: Number, default: 0 },
    failureReason: String,
    canRetry: { type: Boolean, default: false },
    nextRetryAt: Date
}, {
    timestamps: true,
    versionKey: false
});

// Pre-save hooks
transactionSchema.pre('save', function(next) {
    // Ensure transactionId is set
    if (!this.transactionId) {
        this.transactionId = `TXN_${Date.now()}_${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
    }
    
    // Ensure reference is set
    if (!this.reference) {
        const timestamp = Date.now();
        const random = Math.floor(Math.random() * 1000000);
        this.reference = `REF_${timestamp}_${random}`;
    }
    
    next();
});

// Virtuals
transactionSchema.virtual('phoneNumber').get(function() {
    return this.metadata?.phone || this.metadata?.billersCode || null;
});

transactionSchema.virtual('formattedAmount').get(function() {
    return `₦${this.amount.toFixed(2)}`;
});

transactionSchema.virtual('formattedBalanceBefore').get(function() {
    return `₦${(this.balanceBefore || 0).toFixed(2)}`;
});

transactionSchema.virtual('formattedBalanceAfter').get(function() {
    return `₦${(this.balanceAfter || 0).toFixed(2)}`;
});

// Nigeria timezone (UTC+1)
transactionSchema.virtual('nigeriaTime').get(function() {
    if (!this.createdAt) return null;
    return new Date(this.createdAt.getTime() + 60 * 60 * 1000);
});

transactionSchema.virtual('formattedNigeriaTime').get(function() {
    return this.nigeriaTime 
      ? this.nigeriaTime.toLocaleString('en-NG', {
          year: 'numeric',
          month: 'short',
          day: '2-digit',
          hour: '2-digit',
          minute: '2-digit',
          hour12: true
        })
      : '';
});

// Transform for JSON
transactionSchema.set('toJSON', {
    virtuals: true,
    transform: (doc, ret) => {
        if (ret.createdAt) {
            ret.createdAt = new Date(ret.createdAt.getTime() + 60 * 60 * 1000);
        }
        if (ret.updatedAt) {
            ret.updatedAt = new Date(ret.updatedAt.getTime() + 60 * 60 * 1000);
        }
        return ret;
    }
});

transactionSchema.set('toObject', { virtuals: true });

// Indexes
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ userId: 1, isCommission: 1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ status: 1, createdAt: -1 });
transactionSchema.index({ gatewayReference: 1 });
transactionSchema.index({ type: 1, createdAt: -1 });
transactionSchema.index({ service: 1, createdAt: -1 });

transactionSchema.index({ createdAt: -1 }); // For global sorting




module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
