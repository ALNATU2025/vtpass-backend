// models/CableTVTransaction.js
const mongoose = require('mongoose');

// Define the schema for Cable TV specific transactions
const cableTVTransactionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // References the User model
    required: true
  },
  serviceType: { // e.g., 'cabletv'
    type: String,
    required: true
  },
  smartCardNumber: {
    type: String,
    required: true
  },
  packageName: { // The specific package name, e.g., 'DSTV Padi'
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true
  },
  status: { // Status of the transaction, default to 'success'
    type: String,
    default: 'success'
  },
  transactionId: { // To store the unique ID from VTpass or your own system
    type: String,
    required: true,
    unique: true
  }
}, {
  timestamps: true // Adds createdAt and updatedAt timestamps
});

// Export the CableTVTransaction model
module.exports = mongoose.model('CableTVTransaction', cableTVTransactionSchema);
