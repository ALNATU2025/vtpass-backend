// models/Notification.js
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  // If 'recipient' is null, it's a general notification for all users.
  // If 'recipient' is a user ID, it's a specific notification for that user.
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null, // Null means it's a broadcast/general notification
    index: true, // Index for faster lookup by recipient
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
  readBy: [{ // Array of user IDs who have read this notification
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }],
  isGeneral: { // Convenience flag: true if recipient is null
    type: Boolean,
    default: function() { return this.recipient === null; }
  },
  // You can add 'type' (e.g., 'announcement', 'transaction_alert', 'warning')
  // or 'link' (for deep linking within the app) here if needed.
}, { timestamps: true }); // createdAt and updatedAt

module.exports = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);
