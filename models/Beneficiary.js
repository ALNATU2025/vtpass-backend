// models/Beneficiary.js
const mongoose = require('mongoose');

const beneficiarySchema = new mongoose.Schema({
  userId: { // The user who owns this beneficiary
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Reference to the User model
    required: true,
  },
  name: { // A friendly name for the beneficiary (e.g., "Mom's Phone", "John's Email")
    type: String,
    required: true,
    trim: true,
  },
  type: { // Type of beneficiary: 'phone' or 'email'
    type: String,
    enum: ['phone', 'email'],
    required: true,
  },
  value: { // The actual phone number or email address
    type: String,
    required: true,
    trim: true,
    lowercase: true, // For emails, ensure consistency
  },
  // Optional: Additional details like network for phone, or bank for transfers
  network: {
    type: String,
    trim: true,
    required: function() { return this.type === 'phone'; } // Required only if type is 'phone'
  },
  // You can add more fields here if needed, e.g., 'bankName' for transfer beneficiaries
}, { timestamps: true });

// Ensure a user cannot save the same type and value beneficiary multiple times
beneficiarySchema.index({ userId: 1, type: 1, value: 1 }, { unique: true });

module.exports = mongoose.models.Beneficiary || mongoose.model('Beneficiary', beneficiarySchema);
