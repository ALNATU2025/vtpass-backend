// models/Transaction.js — ULTIMATE FINAL VERSION (DEC 2025 - FIXED & PERFECT)
const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    type: {
        type: String,
        enum: [
            // === MAIN USER TRANSACTIONS (Visible in tabs) ===
            'Airtime Purchase',
            'Data Purchase',
            'Cable TV Subscription',
            'Electricity Payment',
            'Education Payment',
            'Insurance Purchase',
            'Wallet Funding',
            'Transfer Sent',
            'Transfer Received',

            // === COMMISSION SYSTEM ===
            'Commission Credit',        // ← This is the ONLY correct value!
            'Commission Withdrawal',

            // === LEGACY / FALLBACK (Keep for backward compatibility) ===
            'debit',
            'credit'
        ],
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: [0, 'Amount cannot be negative']
    },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed'],
        default: 'Pending'
    },
    transactionId: {
        type: String,
        unique: true,
        sparse: true,
        index: true
    },
    reference: {
        type: String,
        unique: true,
        sparse: true,
        index: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    balanceBefore: {
        type: Number,
        default: 0,
        min: 0
    },
    balanceAfter: {
        type: Number,
        default: 0,
        min: 0
    },
    metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: () => ({})
    },
    isCommission: {
        type: Boolean,
        default: false,
        index: true
    },
    service: {
        type: String,
        default: '',
        index: true,
        trim: true
    },
    authenticationMethod: {
        type: String,
        enum: ['pin', 'biometric', 'none', 'paystack', 'manual'],
        default: 'none'
    }
}, {
    timestamps: true,
    versionKey: false
});

// === AUTO-GENERATE transactionId ONLY IF NOT PROVIDED ===
transactionSchema.pre('save', function(next) {
    if (!this.transactionId) {
        // Format: TXN20251209123456_ABCD
        const timestamp = Date.now();
        const random = Math.random().toString(36).substr(2, 4).toUpperCase();
        this.transactionId = `TXN${timestamp}${random}`;
    }
    next();
});

// === INDEXES FOR PERFORMANCE ===
transactionSchema.index({ userId: 1, createdAt: -1 });           // Main transaction list
transactionSchema.index({ userId: 1, isCommission: 1 });         // Commission tab
transactionSchema.index({ reference: 1 });                       // VTPass/PayStack lookup
transactionSchema.index({ status: 1, createdAt: -1 });           // Pending verifications
transactionSchema.index({ service: 1 });                         // Filter by service
transactionSchema.index({ type: 1 });                            // Filter by type

// === VIRTUAL: Easy access to phone number from metadata ===
transactionSchema.virtual('phoneNumber').get(function() {
    return this.metadata?.phone || this.metadata?.billersCode || null;
});

// === ENSURE JSON OUTPUT INCLUDES VIRTUALS ===
transactionSchema.set('toJSON', { virtuals: true });
transactionSchema.set('toObject', { virtuals: true });

module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
