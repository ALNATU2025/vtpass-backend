// models/Transaction.js
const mongoose = require('mongoose');

const transactionSchema = mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    enum: [
      'Commission Debit', 
      'Commission Credit', 
      'Commission Withdrawal',
      'Wallet Credit', 
      'Wallet Debit',
      'Referral Credit',
      'Service Purchase',
      'Bonus Credit'
    ],
    required: true,
  },
  amount: {
    type: Number,
    required: true,
    min: 0,
  },
  status: {
    type: String,
    enum: ['Pending', 'Successful', 'Failed', 'Processing'],
    default: 'Pending',
  },
  description: {
    type: String,
    required: true,
  },
  balanceBefore: {
    type: Number,
    default: 0,
  },
  balanceAfter: {
    type: Number,
    default: 0,
  },
  isCommission: {
    type: Boolean,
    default: false,
  },
  service: {
    type: String,
    default: '',
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  reference: {
    type: String,
    unique: true,
    sparse: true,
  },
}, {
  timestamps: true,
});

// Indexes
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ isCommission: 1, status: 1 });
transactionSchema.index({ type: 1, createdAt: -1 });
transactionSchema.index({ reference: 1 });

module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
