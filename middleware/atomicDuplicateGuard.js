// middleware/atomicDuplicateGuard.js
// ============================================================
// DALABAPAY — ATOMIC TRANSACTION PROTECTION
// ============================================================
//
// Two layers of protection:
//
//   1. ACTIVE_USER lock   → ONE active transaction per user
//   2. EXACT transaction  → same (service+recipient+amount+variation)
//                           cannot be submitted twice within 60s
//
// MongoDB unique index on "key" makes both layers atomic.
// Fails CLOSED on DB error (never processes a financial txn
// when the safety lock cannot be verified).
// ============================================================

const IdempotencyLock = require('../models/IdempotencyLock');

// ACTIVE lock: how long a single in-flight transaction can hold the user.
// 90s = long enough for slow VTpass responses, short enough that a crash
// doesn't lock the user for long.
const DEFAULT_LOCK_MS = 90 * 1000;

// DUPLICATE lock: how long the EXACT SAME transaction is blocked.
// 60 seconds = 1 minute, per requirement.
const DEFAULT_DUPLICATE_MS = 60 * 1000;

// ============================================================
// BUILD EXACT TRANSACTION KEY
// ============================================================
function buildKey(req, serviceKey) {
  const userId = req.user?._id?.toString() || 'anon';
  const body = req.body || {};

  const recipient = (
    body.phone ||
    body.phoneNumber ||
    body.billersCode ||
    body.smartcardNumber ||
    body.meterNumber ||
    body.plateNumber ||
    body.profileId ||
    body.receiverEmail ||
    ''
  )
    .toString()
    .trim();

  const amount = Number(body.amount || body.Amount || 0);

  const variation = (
    body.variationCode ||
    body.variation_code ||
    body.variation ||
    body.planName ||
    body.plan ||
    body.serviceID ||
    ''
  )
    .toString()
    .trim();

  return `${userId}:${serviceKey}:${recipient}:${amount}:${variation}`;
}

// ============================================================
// BUILD USER ACTIVE-TRANSACTION KEY
// ============================================================
function buildUserActiveKey(req) {
  const userId = req.user?._id?.toString();
  if (!userId) return null;
  return `ACTIVE_USER:${userId}`;
}

// ============================================================
// GET RETRY TIME
// ============================================================
function getRetryAfterSeconds(expiresAt, fallbackMs) {
  if (!expiresAt) {
    return Math.max(1, Math.ceil(fallbackMs / 1000));
  }
  const remaining = new Date(expiresAt).getTime() - Date.now();
  return Math.max(1, Math.ceil(remaining / 1000));
}

// ============================================================
// MIDDLEWARE FACTORY
// ============================================================
function atomicDuplicateGuard(serviceKey, opts = {}) {
  const lockMs =
    Number(opts.lockMs) > 0 ? Number(opts.lockMs) : DEFAULT_LOCK_MS;

  const duplicateMs =
    Number(opts.duplicateMs) > 0
      ? Number(opts.duplicateMs)
      : DEFAULT_DUPLICATE_MS;

  return async (req, res, next) => {
    // 1. AUTH CHECK
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({
        success: false,
        code: 'AUTHENTICATION_REQUIRED',
        message: 'You must be logged in to perform a transaction.',
      });
    }

    // 2. BUILD KEYS
    const exactKey = buildKey(req, serviceKey);
    const activeUserKey = buildUserActiveKey(req);

    const requestId =
      req.body?.request_id || req.body?.requestId || req.id || '';

    const amount = Number(req.body?.amount || req.body?.Amount || 0);

    const recipient = (
      req.body?.phone ||
      req.body?.phoneNumber ||
      req.body?.billersCode ||
      req.body?.smartcardNumber ||
      req.body?.meterNumber ||
      ''
    )
      .toString()
      .trim();

    const variation = (
      req.body?.variationCode ||
      req.body?.variation_code ||
      req.body?.variation ||
      req.body?.planName ||
      req.body?.plan ||
      ''
    )
      .toString()
      .trim();

    // 3. CHECK EXISTING ACTIVE TRANSACTION
    try {
      const activeTransaction = await IdempotencyLock.findOne({
        key: activeUserKey,
        userId,
        lockType: 'ACTIVE_TRANSACTION',
        expiresAt: { $gt: new Date() },
      }).lean();

      if (activeTransaction) {
        const retryAfterSeconds = getRetryAfterSeconds(
          activeTransaction.expiresAt,
          lockMs
        );

        console.warn(
          `🚫 [ACTIVE-TXN] User ${userId} already has an active transaction`
        );

        return res.status(409).json({
          success: false,
          code: 'TRANSACTION_IN_PROGRESS',
          message:
            `A transaction is already being processed. ` +
            `Please wait ${retryAfterSeconds}s and try again.`,
          retryAfterSeconds,
          isDuplicate: false,
          transactionInProgress: true,
        });
      }
    } catch (err) {
      console.error('❌ [ACTIVE-CHECK] Failed:', err.message);
      // FAIL CLOSED — never process a financial txn without verification
      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message:
          'Transaction protection is temporarily unavailable. Please try again shortly.',
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
        expiresAt: new Date(Date.now() + lockMs),
      });
    } catch (err) {
      // 4a. DUPLICATE ACTIVE LOCK — parallel request won the race
      if (err && err.code === 11000) {
        let retryAfterSeconds = Math.max(1, Math.ceil(lockMs / 1000));

        try {
          const existing = await IdempotencyLock.findOne({
            key: activeUserKey,
          }).lean();

          if (existing?.expiresAt) {
            retryAfterSeconds = getRetryAfterSeconds(
              existing.expiresAt,
              lockMs
            );
          }
        } catch (_) {
          // keep fallback
        }

        console.warn(
          `🚫 [ACTIVE-TXN-RACE] Blocked parallel transaction for user ${userId}`
        );

        return res.status(409).json({
          success: false,
          code: 'TRANSACTION_IN_PROGRESS',
          message:
            `You already have a transaction being processed. ` +
            `Please wait ${retryAfterSeconds}s before starting another transaction.`,
          retryAfterSeconds,
          transactionInProgress: true,
          isDuplicate: false,
        });
      }

      // 4b. OTHER DB ERROR — fail closed
      console.error('❌ [ACTIVE-LOCK] Failed:', err.message);

      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message:
          'We could not securely start your transaction. Please try again shortly.',
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
        expiresAt: new Date(Date.now() + duplicateMs),
      });

      // 6. SUCCESS — both locks acquired
      req.transactionGuard = {
        activeUserKey,
        exactKey,
        serviceKey,
        userId: userId.toString(),
        lockCreatedAt: new Date(),
      };

      console.log(
        `🔐 [TRANSACTION-LOCK] ${serviceKey} locked for user ${userId}`
      );

      return next();
    } catch (err) {
      // 6a. EXACT DUPLICATE — release the ACTIVE lock we just took
      if (err && err.code === 11000) {
        try {
          await IdempotencyLock.deleteOne({
            key: activeUserKey,
            userId,
            lockType: 'ACTIVE_TRANSACTION',
          });
        } catch (releaseErr) {
          console.error(
            '⚠️ [ACTIVE-LOCK] Cleanup failed:',
            releaseErr.message
          );
        }

        let retryAfterSeconds = Math.max(
          1,
          Math.ceil(duplicateMs / 1000)
        );

        try {
          const existing = await IdempotencyLock.findOne({
            key: exactKey,
          }).lean();

          if (existing?.expiresAt) {
            retryAfterSeconds = getRetryAfterSeconds(
              existing.expiresAt,
              duplicateMs
            );
          }
        } catch (_) {
          // keep fallback
        }

        console.warn(
          `🚫 [DUPLICATE] Blocked duplicate ${serviceKey} for user ${userId}`
        );

        return res.status(409).json({
          success: false,
          code: 'DUPLICATE_TRANSACTION_BLOCKED',
          message:
            `This transaction has already been submitted. ` +
            `Please wait ${retryAfterSeconds}s before trying again.`,
          retryAfterSeconds,
          isDuplicate: true,
          transactionInProgress: false,
        });
      }

      // 6b. OTHER EXACT-LOCK ERROR — cleanup + fail closed
      console.error('❌ [EXACT-LOCK] Failed:', err.message);

      try {
        await IdempotencyLock.deleteOne({
          key: activeUserKey,
          userId,
          lockType: 'ACTIVE_TRANSACTION',
        });
      } catch (releaseErr) {
        console.error(
          '⚠️ [ACTIVE-LOCK] Cleanup failed:',
          releaseErr.message
        );
      }

      return res.status(503).json({
        success: false,
        code: 'TRANSACTION_GUARD_UNAVAILABLE',
        message:
          'We could not securely start your transaction. Please try again shortly.',
      });
    }
  };
}

// ============================================================
// RELEASE BOTH LOCKS (used on pre-provider failures)
// ============================================================
async function releaseLock(req, serviceKey) {
  try {
    const activeUserKey = buildUserActiveKey(req);
    const exactKey = buildKey(req, serviceKey);

    if (activeUserKey) {
      await IdempotencyLock.deleteOne({
        key: activeUserKey,
        userId: req.user?._id,
        lockType: 'ACTIVE_TRANSACTION',
      });
    }

    await IdempotencyLock.deleteOne({
      key: exactKey,
      userId: req.user?._id,
      serviceKey,
      lockType: 'EXACT_TRANSACTION',
    });

    console.log(
      `🔓 [TRANSACTION-LOCK] Released ${serviceKey} lock for user ${req.user?._id}`
    );
  } catch (err) {
    console.error(
      '⚠️ [TRANSACTION-LOCK] Release failed:',
      err.message
    );
  }
}

// ============================================================
// RELEASE ONLY ACTIVE USER LOCK (after final SUCCESS/FAILED)
// ============================================================
async function releaseActiveTransactionLock(req) {
  try {
    const activeUserKey = buildUserActiveKey(req);
    if (!activeUserKey) return;

    await IdempotencyLock.deleteOne({
      key: activeUserKey,
      userId: req.user?._id,
      lockType: 'ACTIVE_TRANSACTION',
    });

    console.log(
      `🔓 [ACTIVE-TXN] Released active transaction lock for user ${req.user?._id}`
    );
  } catch (err) {
    console.error('⚠️ [ACTIVE-TXN] Release failed:', err.message);
  }
}

module.exports = {
  atomicDuplicateGuard,
  releaseLock,
  releaseActiveTransactionLock,
  buildKey,
  buildUserActiveKey,
};
