// models/AdminNotification.js
const mongoose = require('mongoose');

const AdminNotificationSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: [
      'new_user_registration',
      'transaction_made',
      'wallet_funded',
      'wallet_funding_success',
      'wallet_funding_failed',
      'transaction_status_change',
      'suspicious_activity',
      'duplicate_transaction_attempt'
    ],
    required: true,
    index: true
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  severity: {
    type: String,
    enum: ['info', 'success', 'warning', 'critical'],
    default: 'info',
    index: true
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  userName: String,
  userEmail: String,
  userPhone: String,
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', index: true },
  transactionReference: String,
  transactionType: String,
  amount: Number,
  status: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  isRead: { type: Boolean, default: false, index: true },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now, index: true }
});

AdminNotificationSchema.index({ createdAt: -1 });
AdminNotificationSchema.index({ isRead: 1, createdAt: -1 });

module.exports = mongoose.model('AdminNotification', AdminNotificationSchema);
