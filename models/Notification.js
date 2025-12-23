// models/Notification.js
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  // If 'recipient' is null, it's a general notification for all users.
  // If 'recipient' is a user ID, it's a specific notification for that user.
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null, // Null means it's a broadcast/general notification
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
  // Optional: Add a read flag for personal notifications
  isRead: {
    type: Boolean,
    default: false
  },
  type: {
    type: String,
    enum: ['account', 'transaction', 'security', 'promotion', 'system'],
    default: 'account'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, { 
  timestamps: true 
});

module.exports = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);
