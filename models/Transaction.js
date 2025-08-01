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
        enum: ['Transfer-Sent', 'Transfer-Received', 'Airtime', 'Data', 'CableTV', 'CashWithdraw', 'FundWallet'],
        required: true,
    },
    amount: {
        type: Number,
        required: true,
    },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed'],
        default: 'Pending', // It's safer to default to 'Pending'
    },
    transactionId: {
        type: String,
        unique: true,
        required: true,
    },
    details: {
        // Use a flexible object to store service-specific details
        // e.g., { network: 'MTN', phoneNumber: '080...', plan: '500MB' }
        // e.g., { smartCardNumber: '123...', packageName: 'dstv-padi', serviceID: 'dstv' }
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
}, { timestamps: true });

// Prevent Mongoose from overwriting the model if it's already defined
module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);