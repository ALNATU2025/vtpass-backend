const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    enum: ['Transfer', 'Airtime', 'Data', 'CableTV', 'CashWithdraw', 'FundWallet'], // Added 'CableTV' and 'FundWallet'
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    enum: ['Successful', 'Pending', 'Failed'], // Added enum for clarity
    default: 'Successful',
  },
  // Specific fields for CableTV transactions (required only if type is 'CableTV')
  smartCardNumber: {
    type: String,
    required: function() { return this.type === 'CableTV'; }
  },
  packageName: { // This will store the VTpass variation_code (e.g., 'dstv-padi')
    type: String,
    required: function() { return this.type === 'CableTV'; }
  },
  // You might also want to store the display name of the package or cable provider
  // selectedPackageName: { type: String },
  // selectedCableDisplayName: { type: String },

  transactionId: { // VTpass transaction ID or custom request_id
    type: String,
    unique: true, // Ensures transaction IDs are unique
    required: true,
  },
  details: { // General purpose field for additional, unstructured details (e.g., full VTpass response)
    type: mongoose.Schema.Types.Mixed, // Allows any type, including nested objects
    default: {}
  },
}, { timestamps: true });

// ✅ Avoid OverwriteModelError
module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
