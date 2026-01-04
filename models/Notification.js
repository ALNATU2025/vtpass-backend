// models/Notification.js
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
    index: true,
  },
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
  },
  message: {
    type: String,
    required: true,
    trim: true,
    maxlength: 500,
  },
  readBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }],
  isGeneral: {
    type: Boolean,
    default: function() { return this.recipient === null; }
  },
  isRead: {
    type: Boolean,
    default: false
  },
  // UPDATED: Added transfer-related notification types
  type: {
    type: String,
    enum: [
      'account', 
      'transaction', 
      'security', 
      'promotion', 
      'system', 
      'alert', 
      'update', 
      'general', 
      'test',
      'transfer_sent',      // Added
      'transfer_received',  // Added
      'payment_success',
      'payment_failed',
      'commission_earned',
      'wallet_funded',
      'announcement' 
    ],
    default: 'general'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, { 
  timestamps: true 
});

// Indexes for better query performance
notificationSchema.index({ recipient: 1, isRead: 1, createdAt: -1 });
notificationSchema.index({ type: 1, createdAt: -1 });
notificationSchema.index({ isGeneral: 1, createdAt: -1 });
notificationSchema.index({ createdAt: -1 });

module.exports = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);
