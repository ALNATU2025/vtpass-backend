// middleware/rateLimiter.js
const mongoose = require('mongoose');
const Transaction = mongoose.model('Transaction');
const { sendBlockedNotification } = require('../helpers/blockedNotifier');

// ============================================================
// IN-MEMORY STORES
// ============================================================
const requestCache = new Map();       // Per-payload fingerprints (secondary)
const userGateCache = new Map();      // Per-user gate (PRIMARY — 60s)

// Cleanup every 5 seconds — tightens the exact-60s boundary
setInterval(() => {
  const now = Date.now();
  let deleted = 0;

  // Per-payload cache — 61s retention
  for (const [key, data] of requestCache.entries()) {
    if (now - data.timestamp > 61000) {
      requestCache.delete(key);
      deleted++;
    }
  }

  // Per-user gate — 61s retention
  for (const [key, data] of userGateCache.entries()) {
    if (now - data.timestamp > 61000) {
      userGateCache.delete(key);
      deleted++;
    }
  }

  if (deleted > 0) {
    console.log(`🧹 Rate limiter cache cleaned: ${deleted} entries. requestCache=${requestCache.size}, userGate=${userGateCache.size}`);
  }
}, 5000);

// ============================================================
// preventRaceCondition — 60-second ABSOLUTE user gate
// ============================================================
// After ANY transaction attempt by a user, they are blocked for
// exactly 60 seconds. No payload change, no service change, no
// recipient change can bypass this.
//
// Failed transactions are ALSO blocked for 60 seconds so nobody
// can spam attempts.
// ============================================================
const preventRaceCondition = (options = {}) => {
  const {
    windowMs = 60000,          // 60 seconds — hard block
    keyPrefix = 'txn',
    blockOnFailure = true      // Failed transactions also block
  } = options;

  return async (req, res, next) => {
    try {
      const userId = req.user?._id?.toString() || req.body.userId || req.query.userId;
      if (!userId) return next();

      const now = Date.now();
      const userGateKey = `usergate_${userId}`;

      // ============================================================
      // LAYER 1 — PER-USER GATE (60 seconds, all services)
      // ============================================================
          const gate = userGateCache.get(userGateKey);
      if (gate && (now - gate.timestamp) < windowMs) {
        const elapsedMs = now - gate.timestamp;
        const waitSec = Math.ceil((windowMs - elapsedMs) / 1000);
        console.log(`🚫 [60s GATE] User ${userId} blocked — wait ${waitSec}s (last attempt ${Math.round(elapsedMs / 1000)}s ago)`);

        // ✅ Notify the user that they were blocked
        sendBlockedNotification({
          userId,
          reason: 'rate_limit',
          service: serviceType || 'transaction',
          retryAfterSeconds: waitSec,
          metadata: {
            gateType: 'user-60s',
            elapsedSeconds: Math.round(elapsedMs / 1000),
            serviceType: serviceType || 'transaction'
          }
        }).catch(() => {});

        return res.status(429).json({
          success: false,
          code: 'TRANSACTION_IN_PROGRESS',
          message: `You must wait ${waitSec} seconds before starting another transaction. Only one transaction is allowed per minute.`,
          retryAfter: waitSec,
          retryAfterSeconds: waitSec,
          transactionInProgress: true
        });
      }

      // ============================================================
      // LAYER 2 — DB CHECK (60s, status-aware but still blocks)
      // ============================================================
      // Any transaction attempt (Successful, Pending, Processing,
      // or Failed) in the last 60 seconds blocks the user.
      // ============================================================
      const lookbackTime = new Date(now - windowMs);
      const recentTx = await Transaction.findOne({
        userId: userId,
        createdAt: { $gte: lookbackTime }
      }).sort({ createdAt: -1 }).lean();

      if (recentTx) {
        const ageMs = now - new Date(recentTx.createdAt).getTime();
        const waitSec = Math.ceil((windowMs - ageMs) / 1000);
        const status = (recentTx.status || '').toLowerCase();

        // ✅ FAILED transactions can be retried only if BOTH:
        //    (a) we're within the 60-second window AND
        //    (b) blockOnFailure is false
        // Default: blockOnFailure = true → everything blocks 60s.
        if (!blockOnFailure && (status === 'failed' || status === 'cancelled')) {
          console.log(`✅ [60s GATE] Previous txn FAILED — allowing immediate retry`);
          // fall through to next()
              } else {
          console.log(`🚫 [60s GATE-DB] User ${userId} has recent txn (${status}) ${Math.round(ageMs / 1000)}s ago — wait ${waitSec}s`);

          // ✅ Notify the user that they were blocked
          sendBlockedNotification({
            userId,
            reason: 'in_progress',
            service: serviceType || 'transaction',
            retryAfterSeconds: waitSec,
            metadata: {
              gateType: 'db-60s',
              previousStatus: recentTx.status,
              previousTransactionId: recentTx._id?.toString() || null,
              previousAgeSeconds: Math.round(ageMs / 1000)
            }
          }).catch(() => {});

          return res.status(429).json({
            success: false,
            code: 'TRANSACTION_IN_PROGRESS',
            message: `You must wait ${waitSec} seconds before starting another transaction. Only one transaction is allowed per minute.`,
            retryAfter: waitSec,
            retryAfterSeconds: waitSec,
            existingTransactionId: recentTx._id,
            existingStatus: recentTx.status,
            transactionInProgress: true
          });
        }
      }

      // ============================================================
      // LAYER 3 — EXACT PAYLOAD DEDUP (60s)
      // ============================================================
      // Same user + service + recipient + amount → still blocked.
      // This is a backstop in case Layer 1/2 fail.
      // ============================================================
      const serviceType = req.body.serviceType || req.body.serviceID || req.body.type || 'unknown';
      const phone = req.body.phone || req.body.billersCode || req.body.meterNumber || req.body.smartcardNumber || '';
      const amount = parseFloat(req.body.amount) || 0;
      const variationCode = req.body.variationCode || req.body.variation_code || '';

      const fingerprint = `${keyPrefix}_${userId}_${serviceType}_${phone}_${variationCode}_${amount}`;
          const cached = requestCache.get(fingerprint);
      if (cached && (now - cached.timestamp) < windowMs) {
        const waitSec = Math.ceil((windowMs - (now - cached.timestamp)) / 1000);
        console.log(`🚫 [60s GATE-PAYLOAD] Duplicate payload — wait ${waitSec}s`);

        // ✅ Notify the user that they were blocked
        sendBlockedNotification({
          userId,
          reason: 'duplicate',
          service: serviceType || 'transaction',
          retryAfterSeconds: waitSec,
          metadata: {
            gateType: 'exact-payload',
            serviceType: serviceType || 'transaction',
            recipient: phone || null,
            amount: amount || 0
          }
        }).catch(() => {});

        return res.status(429).json({
          success: false,
          code: 'DUPLICATE_TRANSACTION_CACHE',
          message: `This exact transaction was already submitted. Please wait ${waitSec} seconds.`,
          retryAfter: waitSec,
          retryAfterSeconds: waitSec,
          alreadyProcessed: true
        });
      }

      // ============================================================
      // LAYER 4 — DUPLICATE request_id
      // ============================================================
      const requestId = req.body.request_id || req.body.requestId;
      if (requestId) {
        const existing = await Transaction.findOne({
          $or: [
            { reference: requestId },
            { transactionId: requestId },
            { 'metadata.requestId': requestId }
          ]
        }).lean();

        if (existing) {
          const status = (existing.status || '').toLowerCase();
          if (status !== 'failed' && status !== 'cancelled') {
            console.log(`🚫 DUPLICATE request_id BLOCKED: ${requestId}`);
            return res.status(409).json({
              success: false,
              message: 'This transaction has already been processed.',
              code: 'DUPLICATE_REQUEST_ID',
              existingTransactionId: existing._id,
              alreadyProcessed: true
            });
          }
        }
      }

      // ============================================================
      // ALL CHECKS PASSED — SET THE 60s GATE
      // ============================================================
      userGateCache.set(userGateKey, { timestamp: now, userId });
      requestCache.set(fingerprint, { timestamp: now, userId });

      console.log(`✅ [60s GATE] User ${userId} allowed — gate set for 60s`);
      next();

    } catch (error) {
      console.error('❌ Rate limiter error:', error);
      // FAIL CLOSED — never process if we can't verify the gate
      return res.status(503).json({
        success: false,
        code: 'RATE_LIMITER_UNAVAILABLE',
        message: 'Transaction protection is temporarily unavailable. Please try again shortly.'
      });
    }
  };
};

// ============================================================
// preventDuplicateVtpassCall — backstop for request_id reuse
// ============================================================
const preventDuplicateVtpassCall = () => {
  const vtpassCache = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, data] of vtpassCache.entries()) {
      if (now - data.timestamp > 61000) vtpassCache.delete(key);
    }
  }, 10000);

  return async (req, res, next) => {
    try {
      const requestId = req.body.request_id || req.body.requestId;
      if (!requestId) return next();

      const key = `vtpass_${requestId}`;
      const now = Date.now();
      const cached = vtpassCache.get(key);

      if (cached && (now - cached.timestamp) < 60000) {
        const waitSec = Math.ceil((60000 - (now - cached.timestamp)) / 1000);
        return res.status(429).json({
          success: false,
          message: `This transaction is already being processed. Please wait ${waitSec} seconds.`,
          code: 'DUPLICATE_REQUEST',
          retryAfter: waitSec
        });
      }

      vtpassCache.set(key, { timestamp: now });
      next();
    } catch (error) {
      console.error('VTpass duplicate check error:', error);
      next();
    }
  };
};

// ============================================================
// userServiceRateLimiter — kept for backward compatibility
// ============================================================
const userServiceRateLimiter = (serviceType, maxPerMinute = 1, windowMs = 60000) => {
  const cache = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of cache.entries()) {
      const valid = timestamps.filter(t => now - t < windowMs);
      if (valid.length === 0) cache.delete(key);
      else cache.set(key, valid);
    }
  }, 10000);

  return async (req, res, next) => {
    try {
      const userId = req.user?._id?.toString();
      if (!userId) return next();

      const key = `user_${userId}_${serviceType}`;
      const now = Date.now();
      let arr = cache.get(key) || [];
      arr = arr.filter(t => now - t < windowMs);

      if (arr.length >= maxPerMinute) {
        const oldest = arr[0];
        const waitSec = Math.ceil((windowMs - (now - oldest)) / 1000);
        return res.status(429).json({
          success: false,
          message: `You can only make ${maxPerMinute} ${serviceType} purchase(s) per minute. Wait ${waitSec}s.`,
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: waitSec
        });
      }

      arr.push(now);
      cache.set(key, arr);
      next();
    } catch (error) {
      console.error('User rate limiter error:', error);
      next();
    }
  };
};

// ============================================================
// getCacheStats — debugging
// ============================================================
const getCacheStats = () => ({
  requestCacheSize: requestCache.size,
  userGateSize: userGateCache.size,
  requestCacheKeys: Array.from(requestCache.keys()),
  userGateKeys: Array.from(userGateCache.keys())
});

module.exports = {
  preventRaceCondition,
  preventDuplicateVtpassCall,
  userServiceRateLimiter,
  getCacheStats
};
