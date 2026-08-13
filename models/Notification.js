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
      'transfer_sent',
      'transfer_received',
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
  },
  // NEW: Track if notification was sent via socket
  sentViaSocket: {
    type: Boolean,
    default: false
  },
  // NEW: Socket delivery status
  deliveredAt: {
    type: Date,
    default: null
  }
}, { 
  timestamps: true 
});

// ==================== INDEXES ====================
notificationSchema.index({ recipient: 1, isRead: 1, createdAt: -1 });
notificationSchema.index({ type: 1, createdAt: -1 });
notificationSchema.index({ isGeneral: 1, createdAt: -1 });
notificationSchema.index({ createdAt: -1 });

// ==================== INSTANCE METHODS ====================

/**
 * Check if notification is read by a specific user
 */
notificationSchema.methods.isReadByUser = function(userId) {
  const userIdStr = userId.toString();
  
  // For personal notifications
  if (this.recipient && this.recipient.toString() === userIdStr) {
    return this.isRead === true;
  }
  
  // For general notifications (sent to all)
  if (!this.recipient) {
    return this.readBy && this.readBy.some(id => id.toString() === userIdStr);
  }
  
  return false;
};

/**
 * Mark notification as read by a specific user
 */
notificationSchema.methods.markAsReadByUser = async function(userId) {
  const userIdStr = userId.toString();
  
  // For personal notifications
  if (this.recipient && this.recipient.toString() === userIdStr) {
    this.isRead = true;
    return await this.save();
  }
  
  // For general notifications (sent to all)
  if (!this.recipient) {
    if (!this.readBy) this.readBy = [];
    if (!this.readBy.some(id => id.toString() === userIdStr)) {
      this.readBy.push(userId);
      await this.save();
    }
    return this;
  }
  
  return this;
};

/**
 * Check if notification is for a specific user
 */
notificationSchema.methods.isForUser = function(userId) {
  const userIdStr = userId.toString();
  
  // Personal notification for this user
  if (this.recipient && this.recipient.toString() === userIdStr) {
    return true;
  }
  
  // General notification (sent to all)
  if (!this.recipient) {
    return true;
  }
  
  return false;
};

/**
 * Get unread count for a user (static method)
 */
notificationSchema.statics.getUnreadCount = async function(userId) {
  return await this.countDocuments({
    $or: [
      { recipient: userId, isRead: false },
      { recipient: null, readBy: { $ne: userId } }
    ]
  });
};

/**
 * Get all unread notifications for a user
 */
notificationSchema.statics.getUnreadForUser = async function(userId, limit = 50) {
  return await this.find({
    $or: [
      { recipient: userId, isRead: false },
      { recipient: null, readBy: { $ne: userId } }
    ]
  })
  .sort({ createdAt: -1 })
  .limit(limit)
  .lean();
};

// ==================== VIRTUAL PROPERTIES ====================

// Helper to convert to JSON with extra info
notificationSchema.set('toJSON', {
  transform: function(doc, ret) {
    ret.id = ret._id;
    delete ret.__v;
    
    // Add isGeneral if not already set
    if (ret.isGeneral === undefined) {
      ret.isGeneral = ret.recipient === null;
    }
    
    return ret;
  }
});

// ==================== EXPORT ====================

module.exports = mongoose.models.Notification || mongoose.model('Notification', notificationSchema);
