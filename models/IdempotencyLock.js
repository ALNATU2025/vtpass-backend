// models/IdempotencyLock.js
// ============================================================
// ATOMIC DUPLICATE PREVENTION
//
// Creates a UNIQUE document per (userId + serviceKey + recipient + amount + variation).
// MongoDB's unique index makes it PHYSICALLY IMPOSSIBLE for two parallel
// requests to both create the same lock. The second insert fails with E11000.
//
// This replaces the racy "findOne-then-create" pattern.
//
// TTL index auto-deletes the lock after `expiresAt`, so users aren't
// permanently blocked — they just can't repeat within the window.
// ============================================================

const mongoose = require('mongoose');

const idempotencyLockSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      unique: true,          // ⬅️ THE ATOMIC LOCK
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    serviceKey: { type: String, required: true },
    recipient: { type: String, default: '' },
    amount: { type: Number, default: 0 },
    variation: { type: String, default: '' },
    requestId: { type: String, default: '' },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },  // ⬅️ TTL — MongoDB auto-deletes
    },
  },
  { timestamps: true }
);

module.exports =
  mongoose.models.IdempotencyLock ||
  mongoose.model('IdempotencyLock', idempotencyLockSchema);
