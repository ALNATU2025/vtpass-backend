// models/Transaction.js

const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    type: {
        type: String,
        enum: ['Transfer-Sent', 'Transfer-Received', 'Airtime', 'Data', 'CableTV', 'CashWithdraw', 'FundWallet', 'wallet_funding'],
        required: true,
    },
    amount: {
        type: Number,
        required: true,
    },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed', 'completed'],
        default: 'Pending',
    },
    transactionId: {
        type: String,
        unique: true,
        required: true,
    },
    details: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
}, { timestamps: true });

module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
