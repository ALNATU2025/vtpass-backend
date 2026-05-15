// middleware/rateLimiter.js
const mongoose = require('mongoose');
const Transaction = mongoose.model('Transaction');

// In-memory store for rate limiting (fastest - microsecond response)
const requestCache = new Map();

// Clean up old entries every 30 seconds
setInterval(() => {
  const now = Date.now();
  let deletedCount = 0;
  for (const [key, data] of requestCache.entries()) {
    if (now - data.timestamp > 30000) { // 30 seconds
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
const preventRaceCondition = (options = {}) => {
  const {
    windowMs = 30000,        // 30 seconds window
    maxRequests = 1,          // Only 1 request allowed
    keyPrefix = 'txn',
    checkDuplicateInDB = true,
    excludeStatuses = ['Failed'] // Exclude failed transactions from duplicate check
  } = options;

  return async (req, res, next) => {
    try {
      // Get user ID from multiple possible locations
      const userId = req.user?._id?.toString() || req.body.userId || req.query.userId;
      const serviceType = req.body.serviceType || req.body.serviceID || req.body.type || 'unknown';
      const phone = req.body.phone || req.body.billersCode || '';
      const amount = parseFloat(req.body.amount) || 0;
      const variationCode = req.body.variationCode || req.body.variation_code || '';
      
      if (!userId) {
        return next(); // No user ID, skip rate limiting
      }
      
      // Create a unique fingerprint for this transaction
      // More specific = better protection
      const fingerprint = `${keyPrefix}_${userId}_${serviceType}_${phone}_${variationCode}_${amount}`;
      const now = Date.now();
      
      // ========== CHECK 1: In-memory cache (fastest - prevents 99% of race conditions) ==========
      const cachedRequest = requestCache.get(fingerprint);
      if (cachedRequest && (now - cachedRequest.timestamp) < windowMs) {
        const timeDiff = now - cachedRequest.timestamp;
        console.log(`🚫 RACE CONDITION BLOCKED (CACHE): ${fingerprint} - ${timeDiff}ms ago`);
        console.log(`   User: ${userId}, Service: ${serviceType}, Amount: ₦${amount}`);
        
        return res.status(429).json({
          success: false,
          message: 'Duplicate transaction detected. Please wait 30 seconds and try again.',
          code: 'DUPLICATE_TRANSACTION_CACHE',
          retryAfter: Math.ceil((windowMs - timeDiff) / 1000),
          alreadyProcessed: true
        });
      }
      
      // ========== CHECK 2: Database check for recent transactions ==========
      if (checkDuplicateInDB && userId) {
        const thirtySecondsAgo = new Date(now - windowMs);
        
        // Build query to find recent transactions
        const query = {
          userId: userId,
          status: { $nin: excludeStatuses }, // Exclude failed transactions
          createdAt: { $gte: thirtySecondsAgo }
        };
        
        // Add service type filter if available
        if (serviceType !== 'unknown') {
          query.type = { $regex: new RegExp(serviceType, 'i') };
        }
        
        // Add phone/meter filter for more precise matching
        if (phone && phone.length > 5) {
          query.$or = [
            { 'metadata.phone': phone },
            { 'metadata.billersCode': phone },
            { 'metadata.meterNumber': phone }
          ];
        }
        
        const recentTransaction = await Transaction.findOne(query).sort({ createdAt: -1 }).lean();
        
        if (recentTransaction) {
          const timeSinceLast = now - new Date(recentTransaction.createdAt).getTime();
          console.log(`🚫 DB DUPLICATE BLOCKED: User ${userId} - ${serviceType} - ${timeSinceLast}ms ago`);
          console.log(`   Last transaction ID: ${recentTransaction._id}, Status: ${recentTransaction.status}`);
          
          return res.status(409).json({
            success: false,
            message: 'A similar transaction was just processed. Please check your transaction history before trying again.',
            code: 'RECENT_TRANSACTION_EXISTS',
            existingTransactionId: recentTransaction._id,
            timeSinceLastMs: timeSinceLast,
            alreadyProcessed: true
          });
        }
      }
      
      // ========== CHECK 3: Check for exact same request_id (if provided) ==========
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
      
      // ========== ALL CHECKS PASSED - Store in cache ==========
      requestCache.set(fingerprint, {
        timestamp: now,
        userId: userId,
        serviceType: serviceType,
        phone: phone,
        amount: amount,
        requestId: requestId || Date.now().toString()
      });
      
      // Log for debugging
      console.log(`✅ RATE LIMITER PASSED: User ${userId} - ${serviceType} - ₦${amount}`);
      
      next();
    } catch (error) {
      console.error('❌ Rate limiter error:', error);
      next(); // Don't block on error - fail open
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
