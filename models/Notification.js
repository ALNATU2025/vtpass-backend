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
    // ✅ COMPLETE ENUM — includes every type used anywhere in the codebase
        enum: [
      // ---- General / account ----
      'general',
      'account',
      'announcement',
      'security',
      'promotion',
      'system',
      'alert',
      'update',
      'test',

      // ---- Transaction lifecycle ----
      'transaction',
      'transaction_success',
      'transaction_pending',
      'transaction_failed',
      'transaction_issue',
      'transaction_status_update',

      // ---- Payments ----
      'payment_success',
      'payment_failed',

      // ---- Money movement ----
      'wallet_funded',
      'wallet_funding',
      'wallet_debited',
      'refund',
      'refund_credited',
      'transfer_sent',
      'transfer_received',

      // ---- Commission / referral ----
      'commission_earned',
      'referral_bonus',
      'referral_commission',

      // ---- Admin ----
      'admin_transaction',
      'admin_activity',
      'admin_alert',
      'admin_refund',
      'admin_dispute',
    ],
    default: 'general'
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  // Track if notification was sent via socket
  sentViaSocket: {
    type: Boolean,
    default: false
  },
  // Socket delivery status
  deliveredAt: {
    type: Date,
    default: null
  },
  // Track if push notification was sent
  pushSent: {
    type: Boolean,
    default: false
  },
  pushError: {
    type: String,
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
