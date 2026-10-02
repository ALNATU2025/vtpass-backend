// models/IdempotencyLock.js
// ============================================================
// DALABAPAY — ATOMIC IDEMPOTENCY / TRANSACTION LOCK MODEL
// ============================================================
//
// MongoDB's UNIQUE index on "key" makes the lock atomic.
// Two parallel requests: Request A wins, Request B gets E11000.
//
// Two lock types:
//   ACTIVE_TRANSACTION  → prevents a user from running two txns at once
//   EXACT_TRANSACTION   → prevents the same txn being submitted twice
// ============================================================

const mongoose = require('mongoose');

const idempotencyLockSchema = new mongoose.Schema(
  {
    // Unique lock key. Examples:
    //   ACTIVE_USER:64abc123...
    //   64abc123:cable:1234567890:5000:dstv-padi
    key: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
    },

    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },

    lockType: {
      type: String,
      enum: ['ACTIVE_TRANSACTION', 'EXACT_TRANSACTION'],
      required: true,
      index: true,
    },

    serviceKey: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true,
    },

    recipient: {
      type: String,
      default: '',
      trim: true,
    },

    amount: {
      type: Number,
      default: 0,
      min: 0,
    },

    variation: {
      type: String,
      default: '',
      trim: true,
    },

    requestId: {
      type: String,
      default: '',
      trim: true,
      index: true,
    },

    // ⚠️ IMPORTANT: Do NOT add index:true here.
    // A dedicated TTL index is defined below.
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

// ============================================================
// TTL INDEX — MongoDB auto-deletes expired locks
// ============================================================
idempotencyLockSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

// ============================================================
// USER ACTIVE TRANSACTION INDEX
// ============================================================
idempotencyLockSchema.index({
  userId: 1,
  lockType: 1,
  expiresAt: 1,
});

// ============================================================
// USER + SERVICE INDEX
// ============================================================
idempotencyLockSchema.index({
  userId: 1,
  serviceKey: 1,
  createdAt: -1,
});

module.exports =
  mongoose.models.IdempotencyLock ||
  mongoose.model('IdempotencyLock', idempotencyLockSchema);
