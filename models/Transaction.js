// models/Transaction.js — FINAL PRODUCTION VERSION
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
      'Transfer-Sent', 'Transfer-Received',
      'Airtime', 'Data', 'CableTV', 'Electricity',
      'airtime_purchase', 'data_purchase', 'cable_purchase', 'electricity_purchase',
      'CashWithdraw', 'FundWallet', 'wallet_funding',
      'virtual_account_topup', 'virtual_account_deposit',
      'credit', 'debit'
    ],
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 0
    },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed', 'Completed'],
        default: 'Pending',
        set: (v) => {
            if (!v) return 'Pending';
            const map = {
                success: 'Successful',
                successful: 'Successful',
                complete: 'Completed',
                completed: 'Completed'
            };
            const normalized = v.toString().trim().toLowerCase();
            return map[normalized] || normalized.charAt(0).toUpperCase() + normalized.slice(1);
        }
    },
    transactionId: {
        type: String,
        unique: true,
        sparse: true,
        default: null
    },
    reference: {
        type: String,
        unique: true,
        sparse: true,
        index: true
    },
    description: {
        type: String,
        default: ''
    },
    balanceBefore: { type: Number, default: 0 },
    balanceAfter: { type: Number, default: 0 },
    details: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    gateway: { type: String, default: 'paystack' },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
    timestamps: true 
});

// Auto-generate transactionId
transactionSchema.pre('save', function(next) {
    if (!this.transactionId && this.reference) {
        this.transactionId = this.reference;
    }
    if (!this.transactionId) {
        this.transactionId = `TXN_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`.toUpperCase();
    }
    next();
});

// Compound index for fast reference + user lookups
transactionSchema.index({ reference: 1, userId: 1 });

module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
