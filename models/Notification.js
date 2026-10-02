// models/Notification.js
// FIXES APPLIED:
//   1. Added 'transaction_refunded' to the type enum
//   2. Added pre-save hook to sync top-level pushSent/pushError with metadata
//   3. Simplified getUnreadCount static to match helper + socket-server

const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema(
  {
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
    readBy: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    ],
    isGeneral: {
      type: Boolean,
      default: function () {
        return this.recipient === null;
      },
    },
    isRead: {
      type: Boolean,
      default: false,
    },
    type: {
      type: String,
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
        'transaction_refunded',      // ✅ ADDED
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
      default: 'general',
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    sentViaSocket: {
      type: Boolean,
      default: false,
    },
    deliveredAt: {
      type: Date,
      default: null,
    },
    pushSent: {
      type: Boolean,
      default: false,
    },
    pushError: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// ==================== INDEXES ====================
notificationSchema.index({ recipient: 1, isRead: 1, createdAt: -1 });
notificationSchema.index({ type: 1, createdAt: -1 });
notificationSchema.index({ isGeneral: 1, createdAt: -1 });
notificationSchema.index({ createdAt: -1 });

// ==================== PRE-SAVE SYNC HOOK ====================
// Keeps top-level pushSent/pushError synced with metadata.pushSent/pushError.
// The helper writes to metadata (Mixed field); this mirrors it upward so
// admin queries on the top-level field get accurate data.
notificationSchema.pre('save', function (next) {
  if (this.metadata && typeof this.metadata === 'object') {
    if (typeof this.metadata.pushSent === 'boolean') {
      this.pushSent = this.metadata.pushSent;
    }
    if (this.metadata.pushError !== undefined) {
      this.pushError = this.metadata.pushError;
    }
  }
  next();
});

// ==================== INSTANCE METHODS ====================
notificationSchema.methods.isReadByUser = function (userId) {
  const userIdStr = userId.toString();
  if (this.recipient && this.recipient.toString() === userIdStr) {
    return this.isRead === true;
  }
  if (!this.recipient) {
    return this.readBy && this.readBy.some((id) => id.toString() === userIdStr);
  }
  return false;
};

notificationSchema.methods.markAsReadByUser = async function (userId) {
  const userIdStr = userId.toString();
  if (this.recipient && this.recipient.toString() === userIdStr) {
    this.isRead = true;
    return await this.save();
  }
  if (!this.recipient) {
    if (!this.readBy) this.readBy = [];
    if (!this.readBy.some((id) => id.toString() === userIdStr)) {
      this.readBy.push(userId);
      await this.save();
    }
    return this;
  }
  return this;
};

notificationSchema.methods.isForUser = function (userId) {
  const userIdStr = userId.toString();
  if (this.recipient && this.recipient.toString() === userIdStr) return true;
  if (!this.recipient) return true;
  return false;
};

// ==================== STATIC METHODS ====================
// ✅ Matches notificationHelper.js and socket-server.js
notificationSchema.statics.getUnreadCount = async function (userId) {
  return await this.countDocuments({
    recipient: userId,
    isRead: false,
  });
};

notificationSchema.statics.getUnreadForUser = async function (
  userId,
  limit = 50
) {
  return await this.find({
    $or: [
      { recipient: userId, isRead: false },
      { recipient: null, readBy: { $ne: userId } },
    ],
  })
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
};

// ==================== toJSON ====================
notificationSchema.set('toJSON', {
  transform: function (doc, ret) {
    ret.id = ret._id;
    delete ret.__v;
    if (ret.isGeneral === undefined) {
      ret.isGeneral = ret.recipient === null;
    }
    return ret;
  },
});

module.exports =
  mongoose.models.Notification ||
  mongoose.model('Notification', notificationSchema);
