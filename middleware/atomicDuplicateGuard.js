// middleware/atomicDuplicateGuard.js
// ============================================================
// ABSOLUTE 60-SECOND GATE — atomic, DB-backed, per-user
// ============================================================
// No user can start a second transaction within 60 seconds of
// the previous attempt. Blocks across ALL services, ALL
// recipients, ALL amounts.
//
// Two layers:
//   1. ACTIVE_USER lock  → 60s block per user (all services)
//   2. EXACT lock        → 60s block for identical retries
// ============================================================

// middleware/atomicDuplicateGuard.js
const IdempotencyLock = require('../models/IdempotencyLock');
const { sendBlockedNotification } = require('../helpers/blockedNotifier');

const LOCK_MS = 60 * 1000;        // 60 seconds — ACTIVE user lock
const DUPLICATE_MS = 60 * 1000;   // 60 seconds — EXACT lock

// ============================================================
function buildKey(req, serviceKey) {
  const userId = req.user?._id?.toString() || 'anon';
  const body = req.body || {};

  const recipient = (
    body.phone || body.phoneNumber || body.billersCode ||
    body.smartcardNumber || body.meterNumber || body.plateNumber ||
    body.profileId || body.receiverEmail || ''
  ).toString().trim();

  const amount = Number(body.amount || body.Amount || 0);

  const variation = (
    body.variationCode || body.variation_code || body.variation ||
    body.planName || body.plan || body.serviceID || ''
  ).toString().trim();

  return `${userId}:${serviceKey}:${recipient}:${amount}:${variation}`;
}

function buildUserActiveKey(req) {
  const userId = req.user?._id?.toString();
  if (!userId) return null;
  return `ACTIVE_USER:${userId}`;
}

function getRetryAfterSeconds(expiresAt, fallbackMs) {
  if (!expiresAt) return Math.max(1, Math.ceil(fallbackMs / 1000));
  const remaining = new Date(expiresAt).getTime() - Date.now();
  return Math.max(1, Math.ceil(remaining / 1000));
}

// ============================================================
// MIDDLEWARE FACTORY
// ============================================================
function atomicDuplicateGuard(serviceKey, opts = {}) {
  const lockMs = Number(opts.lockMs) > 0 ? Number(opts.lockMs) : LOCK_MS;
  const duplicateMs = Number(opts.duplicateMs) > 0 ? Number(opts.duplicateMs) : DUPLICATE_MS;

  return async (req, res, next) => {
    // 1. AUTH
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({
        success: false,
        code: 'AUTHENTICATION_REQUIRED',
        message: 'You must be logged in to perform a transaction.'
      });
    }

    // 1B. FORCE-CLEAN EXPIRED LOCKS (eliminates TTL sweep delay)
    try {
      await IdempotencyLock.deleteMany({
        userId,
        expiresAt: { $lt: new Date() }
      });
    } catch (cleanupErr) {
      console.warn('⚠️ [GUARD-CLEANUP] Failed:', cleanupErr.message);
      // Fail closed
      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message: 'Transaction protection is temporarily unavailable. Please try again shortly.'
      });
    }

    // 2. BUILD KEYS
    const exactKey = buildKey(req, serviceKey);
    const activeUserKey = buildUserActiveKey(req);

    const requestId = req.body?.request_id || req.body?.requestId || req.id || '';
    const amount = Number(req.body?.amount || req.body?.Amount || 0);

    const recipient = (
      req.body?.phone || req.body?.phoneNumber || req.body?.billersCode ||
      req.body?.smartcardNumber || req.body?.meterNumber || ''
    ).toString().trim();

    const variation = (
      req.body?.variationCode || req.body?.variation_code || req.body?.variation ||
      req.body?.planName || req.body?.plan || ''
    ).toString().trim();

    // 3. CHECK EXISTING ACTIVE TRANSACTION
    try {
      const activeTransaction = await IdempotencyLock.findOne({
        key: activeUserKey,
        userId,
        lockType: 'ACTIVE_TRANSACTION',
        expiresAt: { $gt: new Date() }
      }).lean();

      if (activeTransaction) {
        const retryAfterSeconds = getRetryAfterSeconds(activeTransaction.expiresAt, lockMs);
        console.warn(`🚫 [ACTIVE-TXN] User ${userId} blocked — 60s window active, ${retryAfterSeconds}s remaining`);

                // ✅ Notify the user that they were blocked
        sendBlockedNotification({
          userId,
          reason: 'in_progress',
          service: serviceKey,
          retryAfterSeconds,
          metadata: {
            gateType: 'active-lock',
            totalWindowSeconds: 60,
            previousService: activeTransaction.serviceKey || null,
            previousLockId: activeTransaction._id?.toString() || null
          }
        }).catch(() => {});

        return res.status(409).json({
          success: false,
          code: 'TRANSACTION_IN_PROGRESS',
          message: `A transaction is already being processed. Please wait ${retryAfterSeconds} seconds.`,
          retryAfterSeconds,
          retryAfter: retryAfterSeconds,
          transactionInProgress: true
        });
      }
    } catch (err) {
      console.error('❌ [ACTIVE-CHECK] Failed:', err.message);
      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message: 'Transaction protection is temporarily unavailable. Please try again shortly.'
      });
    }

    // 4. ATOMIC ACTIVE-USER LOCK
    try {
      await IdempotencyLock.create({
        key: activeUserKey,
        userId,
        serviceKey,
        lockType: 'ACTIVE_TRANSACTION',
        recipient,
        amount,
        variation,
        requestId,
        expiresAt: new Date(Date.now() + lockMs)
      });
    } catch (err) {
           if (err && err.code === 11000) {
        // Parallel request won the race
        let retryAfterSeconds = Math.max(1, Math.ceil(lockMs / 1000));
        try {
          const existing = await IdempotencyLock.findOne({ key: activeUserKey }).lean();
          if (existing?.expiresAt) {
            retryAfterSeconds = getRetryAfterSeconds(existing.expiresAt, lockMs);
          }
        } catch (_) {}
        console.warn(`🚫 [ACTIVE-RACE] User ${userId} blocked — ${retryAfterSeconds}s remaining`);

        // ✅ Notify the user that they were blocked
        sendBlockedNotification({
          userId,
          reason: 'in_progress',
          service: serviceKey,
          retryAfterSeconds,
          metadata: {
            gateType: 'active-race'
          }
        }).catch(() => {});

        return res.status(409).json({
          success: false,
          code: 'TRANSACTION_IN_PROGRESS',
          message: `You already have a transaction being processed. Please wait ${retryAfterSeconds} seconds.`,
          retryAfterSeconds,
          retryAfter: retryAfterSeconds,
          transactionInProgress: true
        });
      }

      console.error('❌ [ACTIVE-LOCK] Failed:', err.message);
      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message: 'We could not securely start your transaction. Please try again shortly.'
      });
    }

    // 5. EXACT DUPLICATE LOCK
    try {
      await IdempotencyLock.create({
        key: exactKey,
        userId,
        serviceKey,
        lockType: 'EXACT_TRANSACTION',
        recipient,
        amount,
        variation,
        requestId,
        expiresAt: new Date(Date.now() + duplicateMs)
      });

      req.transactionGuard = {
        activeUserKey,
        exactKey,
        serviceKey,
        userId: userId.toString(),
        lockCreatedAt: new Date()
      };

      console.log(`🔐 [60s GATE] ${serviceKey} locked for user ${userId}`);
      return next();

    } catch (err) {
           if (err && err.code === 11000) {
        // Release ACTIVE lock we just took
        try {
          await IdempotencyLock.deleteOne({
            key: activeUserKey,
            userId,
            lockType: 'ACTIVE_TRANSACTION'
          });
        } catch (releaseErr) {
          console.error('⚠️ [ACTIVE-LOCK] Cleanup failed:', releaseErr.message);
        }

        let retryAfterSeconds = Math.max(1, Math.ceil(duplicateMs / 1000));
        try {
          const existing = await IdempotencyLock.findOne({ key: exactKey }).lean();
          if (existing?.expiresAt) {
            retryAfterSeconds = getRetryAfterSeconds(existing.expiresAt, duplicateMs);
          }
        } catch (_) {}

        console.warn(`🚫 [DUPLICATE] Blocked duplicate ${serviceKey} for user ${userId}`);

        // ✅ Notify the user that they were blocked
        sendBlockedNotification({
          userId,
          reason: 'duplicate',
          service: serviceKey,
          retryAfterSeconds,
          metadata: {
            gateType: 'exact-lock',
            recipient: recipient || null,
            amount: amount || 0,
            variation: variation || null
          }
        }).catch(() => {});

        return res.status(409).json({
          success: false,
          code: 'DUPLICATE_TRANSACTION_BLOCKED',
          message: `This transaction has already been submitted. Please wait ${retryAfterSeconds} seconds.`,
          retryAfterSeconds,
          retryAfter: retryAfterSeconds,
          isDuplicate: true
        });
      }

      console.error('❌ [EXACT-LOCK] Failed:', err.message);
      try {
        await IdempotencyLock.deleteOne({
          key: activeUserKey,
          userId,
          lockType: 'ACTIVE_TRANSACTION'
        });
      } catch (_) {}

      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message: 'We could not securely start your transaction. Please try again shortly.'
      });
    }
  };
}

// ============================================================
// RELEASE BOTH LOCKS — ONLY call this on PRE-PROVIDER failures
// ============================================================
async function releaseLock(req, serviceKey) {
  try {
    const activeUserKey = buildUserActiveKey(req);
    const exactKey = buildKey(req, serviceKey);

    if (activeUserKey) {
      await IdempotencyLock.deleteOne({
        key: activeUserKey,
        userId: req.user?._id,
        lockType: 'ACTIVE_TRANSACTION'
      });
    }

    await IdempotencyLock.deleteOne({
      key: exactKey,
      userId: req.user?._id,
      serviceKey,
      lockType: 'EXACT_TRANSACTION'
    });

    console.log(`🔓 [60s GATE] Released ${serviceKey} lock for user ${req.user?._id}`);
  } catch (err) {
    console.error('⚠️ [60s GATE] Release failed:', err.message);
  }
}

// ============================================================
// NO-OP — the 60-second block is enforced by natural TTL expiry.
// Do NOT delete the lock here. It must live its full 60 seconds.
// ============================================================
async function releaseActiveTransactionLock(req) {
  try {
    const userId = req.user?._id;
    if (!userId) return;
    console.log(`🔒 [60s GATE] Lock kept for user ${userId} — expires in ~60s`);
  } catch (err) {
    console.error('⚠️ [60s GATE] Log failed:', err.message);
  }
}

module.exports = {
  atomicDuplicateGuard,
  releaseLock,
  releaseActiveTransactionLock,
  buildKey,
  buildUserActiveKey
};
