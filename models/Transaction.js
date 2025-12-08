// models/Transaction.js — FINAL CLEAN & PROFESSIONAL VERSION
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
            'Airtime Purchase',
            'Data Purchase',
            'Cable TV Subscription',
            'Electricity Payment',
            'Education Payment',
            'Insurance Purchase',
            'Wallet Funding',
            'Transfer Sent',
            'Transfer Received',
            'Commission Credit',
            'Commission Withdrawal',
            'debit',
            'credit'
        ],
        required: true
    },
    amount: { type: Number, required: true, min: 0 },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed'],
        default: 'Pending'
    },
    transactionId: { type: String, unique: true, sparse: true },
    reference: { type: String, unique: true, sparse: true, index: true },
    description: { type: String, required: true },
    balanceBefore: { type: Number, default: 0 },
    balanceAfter: { type: Number, default: 0 },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },

    // These fields make commission work perfectly
    isCommission: { type: Boolean, default: false, index: true },
    service: { type: String, default: '', index: true } // e.g. "Airtime", "Data", "Electricity"
}, { timestamps: true });

// Auto-generate transactionId
transactionSchema.pre('save', function(next) {
    if (!this.transactionId) {
        this.transactionId = `TXN${Date.now()}${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
    }
    next();
});

transactionSchema.index({ userId: 1, isCommission: 1 });
transactionSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
