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
  // UPDATE THIS: Add 'test' to the enum values
  type: {
    type: String,
    enum: ['account', 'transaction', 'security', 'promotion', 'system', 'alert', 'update', 'general', 'test'],
    default: 'general'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
}, { 
  timestamps: true 
});

module.exports = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);
