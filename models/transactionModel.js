const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    enum: ['Transfer', 'Airtime', 'Data', 'CableTV', 'CashWithdraw'],
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    default: 'Successful',
  },
  details: {
    type: String,
  },
}, { timestamps: true });

// ✅ Avoid OverwriteModelError
module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
