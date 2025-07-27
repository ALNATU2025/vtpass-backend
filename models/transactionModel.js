const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    // Updated enum to include specific transfer types for clarity
    enum: ['Transfer-Sent', 'Transfer-Received', 'Airtime', 'Data', 'CableTV', 'CashWithdraw', 'FundWallet'],
    required: true,
  },
  amount: {
    type: Number,
    required: true,
  },
  status: {
    type: String,
    enum: ['Successful', 'Pending', 'Failed'], // This enum is fine and matches 'Successful' used in route
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
    required: true, // <<< CRITICAL: This was the missing piece causing the 500 error
  },
  details: { // General purpose field for additional, unstructured details (e.g., full VTpass response)
    type: mongoose.Schema.Types.Mixed, // Allows any type, including nested objects
    default: {}
  },
}, { timestamps: true });

// ✅ Avoid OverwriteModelError: Use the existing model if it's already defined
module.exports = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);
