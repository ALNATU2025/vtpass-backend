// models/AdminAuditLog.js
const mongoose = require('mongoose');

const adminAuditLogSchema = new mongoose.Schema({
  // Who performed the action
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  adminName: { type: String, required: true },
  adminEmail: { type: String, required: true },

  // Who was affected
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  userName: { type: String, required: true },
  userEmail: { type: String, required: true },

  // What happened
  action: {
    type: String,
    required: true,
    enum: [
      'WALLET_CREDIT',
      'WALLET_DEBIT',
      'USER_ACTIVATED',
      'USER_DEACTIVATED',
      'USER_SUSPENDED',
      'USER_APPROVED',
      'USER_REJECTED',
      'USER_EDITED',
      'PIN_UNLOCKED',
      'PIN_RESET',
      'ROLE_CHANGED',
    ],
    index: true,
  },

  // Financial details
  amount: { type: Number, default: 0 },
  balanceBefore: { type: Number, default: 0 },
  balanceAfter: { type: Number, default: 0 },

  // Context
  reason: { type: String, default: '' },
  reference: { type: String, default: '' },
  note: { type: String, default: '' },

  // Extra data
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },

  createdAt: { type: Date, default: Date.now, index: true },
});

adminAuditLogSchema.index({ createdAt: -1 });
adminAuditLogSchema.index({ userId: 1, createdAt: -1 });
adminAuditLogSchema.index({ adminId: 1, createdAt: -1 });

module.exports = mongoose.model('AdminAuditLog', adminAuditLogSchema);
