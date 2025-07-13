const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['credit', 'debit', 'payment'] },
  amount: Number,
  status: { type: String, default: 'pending' },
  description: String
}, { timestamps: true });

module.exports = mongoose.model('Transaction', TransactionSchema);
