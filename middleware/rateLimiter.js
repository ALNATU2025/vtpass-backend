// middleware/rateLimiter.js
const mongoose = require('mongoose');
const Transaction = mongoose.model('Transaction');

// In-memory store for rate limiting (fastest - microsecond response)
const requestCache = new Map();

// Clean up old entries every 30 seconds
// ✅ FIXED: Use 120s retention so we never prematurely delete an entry
// that a route wanted to keep for up to 90s (pending retry window).
setInterval(() => {
  const now = Date.now();
  let deletedCount = 0;
  for (const [key, data] of requestCache.entries()) {
    if (now - data.timestamp > 120000) { // 120 seconds — safe max
      requestCache.delete(key);
      deletedCount++;
    }
  }
  if (deletedCount > 0) {
    console.log(`🧹 Rate limiter cache cleaned: ${deletedCount} entries removed. Remaining: ${requestCache.size}`);
  }
}, 30000);

/**
 * PREVENTS RACE CONDITIONS - FRAUD PROTECTION
 * Blocks duplicate transactions within 30 seconds
 * This is your PRIMARY defense against the race condition bug
 */
// ==================== preventRaceCondition (STATUS-AWARE v2) ====================
// Blocks rapid duplicate requests BUT allows retry if the previous
// attempt is still Pending and enough time has passed OR the previous
// attempt has Failed.
//
// Real-world scenario fixed:
//   User clicks "Renew Compact" → VTpass takes 45s → user gets impatient,
//   cancels, opens the app again, clicks "Change to Compact Plus" within
//   the same minute. Old middleware blocked it. New middleware:
//     • If previous is Pending → allow only after `pendingRetryMs` (default 90s)
//     • If previous is Successful → block for `successBlockMs` (default 60s)
//     • If previous is Failed → allow immediately
// ======================================================================
const preventRaceCondition = (options = {}) => {
  const {
    windowMs = 30000,                 // Block window after SUCCESS (fallback)
    maxRequests = 1,
    keyPrefix = 'txn',
    checkDuplicateInDB = true,
    excludeStatuses = ['Failed'],     // Failed → allow immediately
    pendingRetryMs = 90000,           // Pending  → allow retry after 90s
    successBlockMs = 60000            // Successful → block 60s
  } = options;

  return async (req, res, next) => {
    try {
      // Get user ID from multiple possible locations
      const userId = req.user?._id?.toString() || req.body.userId || req.query.userId;
      if (!userId) return next();

      const serviceType = req.body.serviceType || req.body.serviceID || req.body.type || 'unknown';
      const phone = req.body.phone || req.body.billersCode || req.body.meterNumber || req.body.smartcardNumber || '';
      const amount = parseFloat(req.body.amount) || 0;
      const variationCode = req.body.variationCode || req.body.variation_code || '';

      // Faster cache key — includes user, service, recipient, amount
      const fingerprint = `${keyPrefix}_${userId}_${serviceType}_${phone}_${variationCode}_${amount}`;
      const now = Date.now();

      // ============================================================
      // ============ CHECK 1: DB (STATUS-AWARE) ====================
      // ============================================================
      // We do the DB check FIRST because it tells us the actual
      // status of the previous attempt — which the in-memory cache
      // cannot know.
      // ============================================================
      if (checkDuplicateInDB) {
        const lookbackMs = Math.max(successBlockMs, pendingRetryMs); // e.g. 90s
        const lookbackTime = new Date(now - lookbackMs);

        const query = {
          userId: userId,
          createdAt: { $gte: lookbackTime }
        };

        if (serviceType !== 'unknown') {
          query.type = { $regex: new RegExp(serviceType, 'i') };
        }

        if (phone && phone.length > 5) {
          query.$or = [
            { 'metadata.phone': phone },
            { 'metadata.billersCode': phone },
            { 'metadata.meterNumber': phone },
            { 'metadata.smartcardNumber': phone }
          ];
        }

        const recentTx = await Transaction.findOne(query).sort({ createdAt: -1 }).lean();

        if (recentTx) {
          const txStatus = (recentTx.status || '').toLowerCase();
          const ageMs = now - new Date(recentTx.createdAt).getTime();

          // ---- FAILED → allow immediately ----
          if (excludeStatuses.map(s => s.toLowerCase()).includes(txStatus)) {
            console.log(`✅ [RACE] Previous txn FAILED — allowing retry (age: ${Math.round(ageMs / 1000)}s)`);
            // fall through to next()
          }
          // ---- SUCCESSFUL → block for successBlockMs ----
          else if (txStatus === 'successful' || txStatus === 'completed') {
            if (ageMs < successBlockMs) {
              const waitSec = Math.ceil((successBlockMs - ageMs) / 1000);
              console.log(`🚫 [RACE] Previous txn SUCCESSFUL ${Math.round(ageMs / 1000)}s ago — block ${waitSec}s`);
              return res.status(409).json({
                success: false,
                code: 'RECENT_TRANSACTION_EXISTS',
                alreadyProcessed: true,
                message: `A transaction to this ${phone ? 'recipient' : 'service'} was just completed ${Math.round(ageMs / 1000)}s ago. Please wait ${waitSec}s before trying again.`,
                existingTransactionId: recentTx._id,
                existingStatus: recentTx.status,
                retryAfterSeconds: waitSec
              });
            }
          }
          // ---- PENDING / PROCESSING → block until pendingRetryMs ----
          else if (txStatus === 'pending' || txStatus === 'processing') {
            if (ageMs < pendingRetryMs) {
              const waitSec = Math.ceil((pendingRetryMs - ageMs) / 1000);
              console.log(`🔄 [RACE] Previous txn PENDING ${Math.round(ageMs / 1000)}s ago — block ${waitSec}s`);
              return res.status(409).json({
                success: false,
                code: 'TRANSACTION_PENDING',
                isPending: true,
                message: `Your previous transaction to this ${phone ? 'recipient' : 'service'} is still being processed by the provider. Please wait up to ${waitSec}s for confirmation before trying again.`,
                existingTransactionId: recentTx._id,
                existingStatus: recentTx.status,
                retryAfterSeconds: waitSec
              });
            }
            console.log(`✅ [RACE] Pending txn aged out (${Math.round(ageMs / 1000)}s) — allowing retry`);
          }
        }
      }

      // ============================================================
      // ============ CHECK 2: In-memory cache (fast backstop) ======
      // ============================================================
      // Only use the cache AFTER the DB check. This way a cached
      // fingerprint cannot block the user when the DB says the
      // previous attempt already failed.
      // ============================================================
      const cachedRequest = requestCache.get(fingerprint);
      if (cachedRequest && (now - cachedRequest.timestamp) < windowMs) {
        const timeDiff = now - cachedRequest.timestamp;
        console.log(`🚫 RACE CONDITION BLOCKED (CACHE): ${fingerprint} - ${timeDiff}ms ago`);
        return res.status(429).json({
          success: false,
          message: 'Duplicate request detected. Please wait a moment before trying again.',
          code: 'DUPLICATE_TRANSACTION_CACHE',
          retryAfter: Math.ceil((windowMs - timeDiff) / 1000),
          alreadyProcessed: true
        });
      }

      // ============================================================
      // ============ CHECK 3: Exact duplicate request_id ===========
      // ============================================================
      const requestId = req.body.request_id || req.body.requestId;
      if (requestId) {
        const existingRequest = await Transaction.findOne({
          $or: [
            { reference: requestId },
            { transactionId: requestId },
            { 'metadata.requestId': requestId }
          ]
        }).lean();

        if (existingRequest && existingRequest.status !== 'Failed') {
          console.log(`🚫 DUPLICATE request_id BLOCKED: ${requestId} already processed`);
          return res.status(409).json({
            success: false,
            message: 'This transaction has already been processed.',
            code: 'DUPLICATE_REQUEST_ID',
            existingTransactionId: existingRequest._id,
            alreadyProcessed: true
          });
        }
      }

      // ============================================================
      // ============ ALL CHECKS PASSED — Cache and move on =========
      // ============================================================
      requestCache.set(fingerprint, {
        timestamp: now,
        userId: userId,
        serviceType: serviceType,
        phone: phone,
        amount: amount,
        requestId: requestId || Date.now().toString()
      });

      console.log(`✅ RATE LIMITER PASSED: User ${userId} - ${serviceType} - ₦${amount}`);
      next();

    } catch (error) {
      console.error('❌ Rate limiter error:', error);
      next(); // Fail open — never block on internal errors
    }
  };
};

/**
 * Specific rate limiter for VTpass API calls
 * Prevents duplicate calls to VTpass with same request_id
 */
const preventDuplicateVtpassCall = () => {
  const vtpassCache = new Map();
  
  return async (req, res, next) => {
    try {
      const requestId = req.body.request_id || req.body.requestId;
      const userId = req.user?._id?.toString();
      
      if (!requestId) {
        return next();
      }
      
      const cacheKey = `vtpass_${requestId}`;
      const cachedCall = vtpassCache.get(cacheKey);
      const now = Date.now();
      
      // Check if this exact request_id was processed in last 60 seconds
      if (cachedCall && (now - cachedCall.timestamp) < 60000) {
        console.log(`🚫 DUPLICATE VTPASS CALL BLOCKED: request_id ${requestId} (${now - cachedCall.timestamp}ms ago)`);
        
        // Try to find the actual transaction
        const existingTransaction = await Transaction.findOne({ 
          $or: [
            { reference: requestId },
            { transactionId: requestId },
            { 'metadata.requestId': requestId }
          ]
        }).lean();
        
        if (existingTransaction && existingTransaction.status === 'Successful') {
          return res.json({
            success: true,
            message: 'Transaction already completed successfully',
            alreadyProcessed: true,
            transactionId: existingTransaction._id,
            newBalance: existingTransaction.balanceAfter
          });
        }
        
        return res.status(429).json({
          success: false,
          message: 'This transaction is already being processed. Please wait.',
          code: 'DUPLICATE_REQUEST',
          retryAfter: 60
        });
      }
      
      // Store in cache
      vtpassCache.set(cacheKey, {
        timestamp: now,
        userId: userId
      });
      
      // Clean up old entries
      setTimeout(() => {
        vtpassCache.delete(cacheKey);
      }, 60000);
      
      next();
    } catch (error) {
      console.error('VTpass duplicate check error:', error);
      next();
    }
  };
};

/**
 * User-specific rate limiter by service type
 * Limits number of purchases per minute per user per service
 */
const userServiceRateLimiter = (serviceType, maxPerMinute = 2, windowMs = 60000) => {
  const userServiceCache = new Map();
  
  // Clean up old entries every minute
  setInterval(() => {
    const now = Date.now();
    for (const [key, timestamps] of userServiceCache.entries()) {
      const validTimestamps = timestamps.filter(t => now - t < windowMs);
      if (validTimestamps.length === 0) {
        userServiceCache.delete(key);
      } else {
        userServiceCache.set(key, validTimestamps);
      }
    }
  }, 60000);
  
  return async (req, res, next) => {
    try {
      const userId = req.user?._id?.toString() || req.body.userId;
      if (!userId) return next();
      
      const key = `user_${userId}_${serviceType}`;
      const now = Date.now();
      
      let userRequests = userServiceCache.get(key) || [];
      
      // Clean old requests
      userRequests = userRequests.filter(timestamp => now - timestamp < windowMs);
      
      if (userRequests.length >= maxPerMinute) {
        const oldestTimestamp = userRequests[0];
        const timeToWait = Math.ceil((windowMs - (now - oldestTimestamp)) / 1000);
        
        console.log(`🚫 USER RATE LIMIT: User ${userId} exceeded ${maxPerMinute} ${serviceType} requests per minute`);
        
        return res.status(429).json({
          success: false,
          message: `You can only make ${maxPerMinute} ${serviceType} purchase(s) per minute. Please wait ${timeToWait} seconds.`,
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: timeToWait,
          maxPerMinute: maxPerMinute,
          serviceType: serviceType
        });
      }
      
      userRequests.push(now);
      userServiceCache.set(key, userRequests);
      
      next();
    } catch (error) {
      console.error('User rate limiter error:', error);
      next();
    }
  };
};

// Debug function to check cache status
const getCacheStats = () => {
  return {
    size: requestCache.size,
    keys: Array.from(requestCache.keys()),
    entries: Array.from(requestCache.entries()).map(([key, value]) => ({
      key,
      ageMs: Date.now() - value.timestamp,
      userId: value.userId,
      serviceType: value.serviceType
    }))
  };
};

module.exports = {
  preventRaceCondition,
  preventDuplicateVtpassCall,
  userServiceRateLimiter,
  getCacheStats
};
