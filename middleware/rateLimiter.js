// middleware/rateLimiter.js
const mongoose = require('mongoose');

// In-memory store for rate limiting (fastest)
const requestCache = new Map();

// Clean up old entries every minute
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of requestCache.entries()) {
    if (now - data.timestamp > 30000) { // 30 seconds
      requestCache.delete(key);
    }
  }
}, 60000);

/**
 * PREVENTS RACE CONDITIONS - FRAUD PROTECTION
 * Blocks duplicate transactions within 30 seconds
 */
const preventRaceCondition = (options = {}) => {
  const {
    windowMs = 30000,        // 30 seconds window
    maxRequests = 1,          // Only 1 request allowed
    keyPrefix = 'txn',
    checkDuplicateInDB = true
  } = options;

  return async (req, res, next) => {
    try {
      // Generate unique key based on user and transaction type
      const userId = req.user?._id || req.body.userId || req.query.userId;
      const serviceType = req.body.serviceType || req.body.serviceID || req.body.type || 'unknown';
      const phone = req.body.phone || req.body.billersCode || '';
      const amount = req.body.amount || 0;
      
      if (!userId) {
        return next(); // No user ID, skip rate limiting
      }
      
      // Create a unique fingerprint for this transaction
      const fingerprint = `${keyPrefix}_${userId}_${serviceType}_${phone}_${amount}`;
      const now = Date.now();
      
      // CHECK 1: In-memory cache (fastest)
      const cachedRequest = requestCache.get(fingerprint);
      if (cachedRequest && (now - cachedRequest.timestamp) < windowMs) {
        console.log(`🚫 RACE CONDITION BLOCKED: ${fingerprint} (${now - cachedRequest.timestamp}ms ago)`);
        return res.status(429).json({
          success: false,
          message: 'Duplicate transaction detected. Please wait and try again.',
          code: 'DUPLICATE_TRANSACTION',
          retryAfter: Math.ceil((windowMs - (now - cachedRequest.timestamp)) / 1000)
        });
      }
      
      // CHECK 2: Database check for recent successful transactions
      if (checkDuplicateInDB && userId) {
        const thirtySecondsAgo = new Date(now - windowMs);
        
        // Check for any successful transaction of same type in last 30 seconds
        const recentTransaction = await mongoose.model('Transaction').findOne({
          userId: userId,
          status: { $in: ['Successful', 'successful', 'Completed', 'completed'] },
          type: { $regex: new RegExp(serviceType, 'i') },
          createdAt: { $gte: thirtySecondsAgo }
        }).sort({ createdAt: -1 });
        
        if (recentTransaction) {
          console.log(`🚫 DB DUPLICATE BLOCKED: User ${userId} - ${serviceType} at ${recentTransaction.createdAt}`);
          return res.status(409).json({
            success: false,
            message: 'A similar transaction was just processed. Please check your transaction history.',
            code: 'RECENT_TRANSACTION_EXISTS',
            existingTransactionId: recentTransaction._id
          });
        }
      }
      
      // Store in cache
      requestCache.set(fingerprint, {
        timestamp: now,
        userId: userId,
        serviceType: serviceType,
        requestId: req.body.request_id || Date.now().toString()
      });
      
      next();
    } catch (error) {
      console.error('Rate limiter error:', error);
      next(); // Don't block on error
    }
  };
};

/**
 * Specific rate limiter for VTpass API calls
 * Prevents duplicate calls to VTpass
 */
const preventDuplicateVtpassCall = async (req, res, next) => {
  try {
    const requestId = req.body.request_id || req.query.request_id;
    const userId = req.user?._id || req.body.userId;
    
    if (!requestId) {
      return next();
    }
    
    // Check if this exact request_id was processed in last 60 seconds
    const existingRequest = requestCache.get(`vtpass_${requestId}`);
    if (existingRequest && (Date.now() - existingRequest.timestamp) < 60000) {
      console.log(`🚫 DUPLICATE VTPASS CALL BLOCKED: request_id ${requestId}`);
      return res.status(429).json({
        success: false,
        message: 'This transaction is already being processed. Please wait.',
        code: 'DUPLICATE_REQUEST'
      });
    }
    
    // Store in cache
    requestCache.set(`vtpass_${requestId}`, {
      timestamp: Date.now(),
      userId: userId
    });
    
    next();
  } catch (error) {
    console.error('VTpass duplicate check error:', error);
    next();
  }
};

/**
 * User-specific rate limiter by service type
 */
const userServiceRateLimiter = (serviceType, maxPerMinute = 2) => {
  const userServiceCache = new Map();
  
  return async (req, res, next) => {
    try {
      const userId = req.user?._id || req.body.userId;
      if (!userId) return next();
      
      const key = `user_${userId}_${serviceType}`;
      const now = Date.now();
      const windowMs = 60000; // 1 minute
      
      let userRequests = userServiceCache.get(key) || [];
      
      // Clean old requests
      userRequests = userRequests.filter(timestamp => now - timestamp < windowMs);
      
      if (userRequests.length >= maxPerMinute) {
        console.log(`🚫 USER RATE LIMIT: User ${userId} exceeded ${maxPerMinute} ${serviceType} requests per minute`);
        return res.status(429).json({
          success: false,
          message: `You can only make ${maxPerMinute} ${serviceType} purchase(s) per minute. Please wait.`,
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: Math.ceil((windowMs - (now - userRequests[0])) / 1000)
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

module.exports = {
  preventRaceCondition,
  preventDuplicateVtpassCall,
  userServiceRateLimiter
};
