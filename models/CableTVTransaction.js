const mongoose = require('mongoose');

const cableTVTransactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  serviceType: { type: String, required: true },
  smartCardNumber: { type: String, required: true },
  packageName: { type: String, required: true },
  amount: { type: Number, required: true },
  status: { type: String, default: 'success' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('CableTVTransaction', cableTVTransactionSchema);
