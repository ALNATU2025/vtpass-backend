// --- File: index.js ---
const express = require('express');
const fetch = require("node-fetch");
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { body, validationResult, query } = require('express-validator');
const NodeCache = require('node-cache');
const { sendVerificationEmail } = require('./emailService');
const referralRoutes = require('./routes/referralRoutes');
const { 
  initSocketServer, 
  emitNotificationToUser, 
  emitBadgeUpdate,
  emitNotificationToAll,
  isUserOnline,
  getConnectedUsersCount,
  getUnreadCount
} = require('./socket-server');

const User = require('./models/User');
const Transaction = require('./models/Transaction');
const Notification = require('./models/Notification');
const Beneficiary = require('./models/Beneficiary');
const Settings = require('./models/AppSettings');
const AuthLog = require('./models/AuthLog');
const Alert = require('./models/Alert');
const Referral = require('./models/Referral');

const formatCurrency = (amount) => `₦${(amount || 0).toFixed(2)}`;
const adminExportRoutes = require('./routes/adminExportRoutes');
const { createNotificationAndSendPush, getUserUnreadCount } = require('./helpers/notificationHelper');

// ==================== COMMISSION STATS CACHE ====================
const commissionStatsCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache
const dashboardCache = new Map();
const DASHBOARD_CACHE_TTL = 5000; // 5 seconds cache




// Add this with your other imports (around line 10-20)
const { preventRaceCondition, preventDuplicateVtpassCall, userServiceRateLimiter } = require('./middleware/rateLimiter');








// ==================== REFUND & DISPUTE MODELS ====================

const DisputeSchema = new mongoose.Schema({
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', required: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['refund_request', 'failed_transaction', 'pending_transaction', 'incorrect_amount', 'service_not_delivered', 'other'], required: true },
  reason: { type: String, required: true },
  description: { type: String, default: '' },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'under_review', 'resolved', 'rejected', 'escalated'], default: 'pending', index: true },
  resolution: { type: String, default: '' },
  resolvedAt: Date,
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  evidence: [{ type: String }],
  adminNotes: [{
    note: String,
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});

const RefundSchema = new mongoose.Schema({
  originalTransactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', required: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  amount: { type: Number, required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'completed', 'failed'], default: 'pending', index: true },
  disputeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Dispute' },
  refundReference: { type: String, unique: true, required: true },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  processedAt: Date,
  completedAt: Date,
  failureReason: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  adminNote: String,
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});

const ReceiptSchema = new mongoose.Schema({
  receiptId: { type: String, unique: true, required: true, index: true },
  transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', index: true },
  refundId: { type: mongoose.Schema.Types.ObjectId, ref: 'Refund', index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['transaction', 'refund', 'status_update'], required: true },
  amount: { type: Number, required: true },
  status: String,
  description: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  receiptData: { type: mongoose.Schema.Types.Mixed, required: true },
  createdAt: { type: Date, default: Date.now, index: true }
});

const Dispute = mongoose.model('Dispute', DisputeSchema);
const Refund = mongoose.model('Refund', RefundSchema);
const Receipt = mongoose.model('Receipt', ReceiptSchema);


// Helper function to generate receipt ID
function generateReceiptId() {
  const timestamp = Date.now().toString();
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `RCPT_${timestamp}_${random}`;
}




// Try to load security middleware with error handling
let helmet, rateLimit, mongoSanitize, xss, hpp, moment;
try {
  helmet = require('helmet');
} catch (e) {
  console.log('helmet module not found. Security headers will not be applied.');
}
try {
  rateLimit = require('express-rate-limit');
} catch (e) {
  console.log('express-rate-limit module not found. Rate limiting will not be applied.');
}
try {
  mongoSanitize = require('mongo-sanitize');
} catch (e) {
  console.log('mongo-sanitize module not found. Input sanitization will not be applied.');
}
try {
  xss = require('xss-clean');
} catch (e) {
  console.log('xss-clean module not found. XSS protection will not be applied.');
}
try {
  hpp = require('hpp');
} catch (e) {
  console.log('hpp module not found. Parameter pollution protection will not be applied.');
}
try {
  moment = require('moment-timezone');
} catch (error) {
  console.log('moment-timezone not found, using moment as fallback');
  moment = require('moment');
}




// ==================== MEMORY MANAGEMENT ====================
// Increase memory limit to 2GB
const v8 = require('v8');
v8.setFlagsFromString('--max-old-space-size=2048');

// Memory usage logger (every 30 seconds)
setInterval(() => {
  const usage = process.memoryUsage();
  const heapUsedMB = (usage.heapUsed / 1024 / 1024).toFixed(2);
  const heapTotalMB = (usage.heapTotal / 1024 / 1024).toFixed(2);
  const rssMB = (usage.rss / 1024 / 1024).toFixed(2);
  
  if (heapUsedMB > 1500) {
    console.warn(`⚠️ HIGH MEMORY USAGE: Heap: ${heapUsedMB}MB / ${heapTotalMB}MB, RSS: ${rssMB}MB`);
  } else if (heapUsedMB > 1000) {
    console.log(`📊 Memory usage: Heap: ${heapUsedMB}MB / ${heapTotalMB}MB, RSS: ${rssMB}MB`);
  } else {
    // Only log every 5th time to reduce noise
    if (Math.random() < 0.2) {
      console.log(`📊 Memory usage: Heap: ${heapUsedMB}MB / ${heapTotalMB}MB, RSS: ${rssMB}MB`);
    }
  }
}, 30000);





dotenv.config();


// ==================== INITIALIZE EXPRESS APP FIRST ====================
const app = express();
app.set('trust proxy', 1);

// ==================== SUPER FAST FIXES (NOW AFTER app IS CREATED) ====================
// 1. INCREASE ALL TIMEOUTS (Prevents ECONNREFUSED)
// ==================== SUPER FAST FIXES ====================
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

axios.defaults.timeout = 30000;
axios.defaults.retry = 3;
axios.defaults.retryDelay = 1000;

// 3. ADD CONNECTION KEEP-ALIVE
const http = require('http');
const https = require('https');

// ✅ CREATE SERVER ONCE
const server = http.createServer(app);

// ✅ Initialize Socket.IO
const io = initSocketServer(server);
global.io = io;
global.emitNotificationToUser = emitNotificationToUser;
global.emitBadgeUpdate = emitBadgeUpdate;
global.emitNotificationToAll = emitNotificationToAll;
global.isUserOnline = isUserOnline;
global.getConnectedUsersCount = getConnectedUsersCount;
global.getUnreadCount = getUnreadCount;

const agent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 60000
});
axios.defaults.httpsAgent = agent;
// 4. ADD AUTO-RECOVERY FOR DEAD CONNECTIONS
setInterval(() => {
  if (mongoose.connection.readyState !== 1) {
    console.log('🔄 MongoDB disconnected, attempting to reconnect...');
    mongoose.connect(process.env.MONGO_URI).catch(console.error);
  }
}, 30000);



// 5. ADD CORS FIX FOR MOBILE APPS (app is now defined!)
// FIXED CORS CONFIGURATION - COPY THIS EXACTLY
// ==================== COMPLETE CORS FIX ====================
app.use((req, res, next) => {
  // IMPORTANT: Allow all origins for mobile apps
  const origin = req.headers.origin;
  
  // Allow all origins - mobile apps don't have same-origin policy issues
  res.header('Access-Control-Allow-Origin', origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD');
  res.header('Access-Control-Allow-Headers', [
    'Content-Type',
    'Authorization', 
    'x-refresh-token',
    'x-commission-usage',
    'Transaction-PIN',
    'Accept',
    'Origin',
    'X-Requested-With',
    'X-Client-Version',
    'User-Agent',
    'x-new-token',
    'x-new-refresh-token'
  ].join(', '));
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400');
  res.header('Access-Control-Expose-Headers', 'x-new-token, x-new-refresh-token');
  
  // Handle preflight requests immediately
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  
  next();
});

// 6. ADD REQUEST LOGGING FOR DEBUGGING
app.use((req, res, next) => {
  console.log(`📡 ${req.method} ${req.url} - ${new Date().toISOString()}`);
  next();
});

// 7. ADD KEEP-ALIVE PING (Prevents Render from sleeping) - IMPROVED
let keepAliveCount = 0;
setInterval(async () => {
  try {
    const response = await axios.get('https://vtpass-backend.onrender.com/health', { 
      timeout: 8000,
      headers: { 'User-Agent': 'Keep-Alive/1.0' }
    });
    keepAliveCount = 0;
    console.log(`💓 Keep-alive successful at ${new Date().toISOString()}`);
  } catch (error) {
    keepAliveCount++;
    console.log(`⚠️ Keep-alive failed (${keepAliveCount}/3)`);
    if (keepAliveCount >= 3) {
      console.log('🚨 Keep-alive failing repeatedly - checking server status...');
    }
  }
}, 3 * 60 * 1000); // Every 3 minutes

console.log('✅ SUPER FAST FIXES APPLIED!');
// ==================== END OF FIXES ====================






// Apply security middleware if available
if (helmet && typeof helmet === 'function') {
  try {
    app.use(helmet());
  } catch (error) {
    console.log('Error applying helmet middleware:', error);
  }
}
if (mongoSanitize && typeof mongoSanitize === 'function') {
  try {
    // Create custom middleware for mongo-sanitize
    app.use((req, res, next) => {
      // Sanitize req.body, req.query, and req.params
      if (req.body) req.body = mongoSanitize(req.body);
      if (req.query) req.query = mongoSanitize(req.query);
      if (req.params) req.params = mongoSanitize(req.params);
      next();
    });
  } catch (error) {
    console.log('Error applying mongo-sanitize middleware:', error);
  }
}
if (xss && typeof xss === 'function') {
  try {
    app.use(xss());
  } catch (error) {
    console.log('Error applying xss-clean middleware:', error);
  }
}
if (hpp && typeof hpp === 'function') {
  try {
    app.use(hpp());
  } catch (error) {
    console.log('Error applying hpp middleware:', error);
  }
}
// Apply rate limiting if available
if (rateLimit && typeof rateLimit === 'function') {
  try {
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later'
    });
    app.use(limiter);
  } catch (error) {
    console.log('Error setting up rate limiter:', error);
  }
}



// ✅ ADD THIS DEBUG ROUTE HERE (BEFORE ANY 404 HANDLERS)
app.get("/api/debug/ip", async (req, res) => {
  try {
    const response = await fetch("https://api.ipify.org?format=json");
    const data = await response.json();
    res.json({
      actualOutboundIP: data.ip,
      note: "This is the IP VTpass will see when your backend connects to them."
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});




// Standard middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//app.use(cors());


// ==================== SESSION ACTIVITY TRACKING ====================
// Add this BEFORE your routes

// Track user activity to prevent premature logout
const userActivityTracker = async (req, res, next) => {
  // Skip for public routes
  const publicRoutes = ['/api/users/login', '/api/users/register', '/health', '/api/debug'];
  if (publicRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }

  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return next();
  }

  try {
    const decoded = jwt.decode(token);
    if (decoded && decoded.id) {
      // Update last activity in background (don't wait)
      User.findByIdAndUpdate(decoded.id, {
        lastActivityAt: new Date()
      }).catch(err => console.log('Activity update error:', err.message));
    }
  } catch (e) {
    // Silently fail
  }
  next();
};

// Apply the middleware
app.use(userActivityTracker);

// ==================== HARD BLOCK UNAUTHORIZED FUNDING ====================
// 🚫 COMPLETELY DISABLE UNAUTHORIZED WALLET FUNDING ENDPOINTS
// MUST BE REGISTERED BEFORE ANY OTHER ROUTES THAT MIGHT MATCH

// Block ALL funding endpoints that are not the dedicated virtual account
app.all('/api/wallet/top-up', (req, res) => {
  console.warn(`🚨 [SECURITY] Unauthorized top-up attempt from IP ${req.ip}`);
  console.warn(`🔍 Headers: ${JSON.stringify(req.headers)}`);
  console.warn(`🔍 Body: ${JSON.stringify(req.body)}`);
  return res.status(403).json({
    success: false,
    message: 'This funding method has been deprecated. Please use your dedicated virtual account.',
    code: 'FUNDING_METHOD_BLOCKED',
    timestamp: new Date().toISOString()
  });
});

app.all('/api/wallet/force-topup', (req, res) => {
  console.warn(`🚨 [SECURITY] Unauthorized force-topup attempt from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'This funding method has been disabled for security reasons.',
    code: 'FUNDING_METHOD_DISABLED'
  });
});

app.all('/api/wallet/fund', (req, res) => {
  console.warn(`🚨 [SECURITY] Unauthorized fund attempt from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'This funding method is not allowed.',
    code: 'FUNDING_METHOD_DISABLED'
  });
});

// Block ALL PayStack endpoints
app.all('/api/payments/verify-paystack', (req, res) => {
  console.warn(`🚨 [SECURITY] Deprecated PayStack endpoint accessed from IP ${req.ip}`);
  console.warn(`🔍 Headers: ${JSON.stringify(req.headers)}`);
  console.warn(`🔍 Body: ${JSON.stringify(req.body)}`);
  return res.status(403).json({
    success: false,
    message: 'PayStack payments are no longer supported. Please use your dedicated virtual account.',
    code: 'PAYMENT_PROVIDER_DISABLED'
  });
});

app.all('/api/paystack/verify-transaction', (req, res) => {
  console.warn(`🚨 [SECURITY] Deprecated PayStack verify endpoint accessed from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'PayStack payments are no longer supported.',
    code: 'PAYMENT_PROVIDER_DISABLED'
  });
});

app.all('/api/paystack/*', (req, res) => {
  console.warn(`🚨 [SECURITY] Legacy PayStack route accessed from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'PayStack integration has been removed.',
    code: 'PAYMENT_PROVIDER_REMOVED'
  });
});

// 🚨 CRITICAL: Block ANY endpoint that could be used for unauthorized funding
app.all('/api/transactions/record', (req, res) => {
  console.warn(`🚨🚨🚨 [SECURITY] CRITICAL: Unauthorized transaction record attempt from IP ${req.ip}`);
  console.warn(`🔍 Headers: ${JSON.stringify(req.headers)}`);
  console.warn(`🔍 Body: ${JSON.stringify(req.body)}`);
  console.warn(`🔍 Query: ${JSON.stringify(req.query)}`);
  console.warn(`🔍 User-Agent: ${req.get('User-Agent')}`);
  return res.status(403).json({
    success: false,
    message: 'This endpoint has been disabled for security reasons.',
    code: 'ENDPOINT_DISABLED',
    incidentId: `INC_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
    timestamp: new Date().toISOString()
  });
});

app.all('/api/transactions/record-verified', (req, res) => {
  console.warn(`🚨🚨🚨 [SECURITY] CRITICAL: Unauthorized record-verified attempt from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'This endpoint has been disabled for security reasons.',
    code: 'ENDPOINT_DISABLED'
  });
});

app.all('/api/wallet/credit', (req, res) => {
  console.warn(`🚨 [SECURITY] Unauthorized wallet credit attempt from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'This funding method is not allowed.',
    code: 'FUNDING_METHOD_DISABLED'
  });
});

app.all('/api/wallet/add-funds', (req, res) => {
  console.warn(`🚨 [SECURITY] Unauthorized add-funds attempt from IP ${req.ip}`);
  return res.status(403).json({
    success: false,
    message: 'This funding method is not allowed.',
    code: 'FUNDING_METHOD_DISABLED'
  });
});

// 🚨 Block ANY route containing these keywords
app.use((req, res, next) => {
  const blockedKeywords = ['paystack', 'paystack_funding', 'wallet/fund', 'wallet/credit', 'wallet/add'];
  const url = req.url.toLowerCase();
  
  for (const keyword of blockedKeywords) {
    if (url.includes(keyword)) {
      console.warn(`🚨🚨🚨 [SECURITY] BLOCKED: ${req.method} ${req.url} from IP ${req.ip}`);
      console.warn(`🔍 Keyword matched: ${keyword}`);
      return res.status(403).json({
        success: false,
        message: 'This endpoint has been disabled for security reasons.',
        code: 'ENDPOINT_DISABLED'
      });
    }
  }
  next();
});
// ==================== END OF HARD BLOCK ====================

// ==================== MAINTENANCE MODE MIDDLEWARE - WITH READ-ONLY ACCESS ====================
app.use(async (req, res, next) => {
  try {
    // Skip maintenance check for these public routes
    const publicRoutes = [
      '/api/users/login',
      '/api/users/register',
      '/api/settings',
      '/health',
      '/api/health',
      '/api/auth/send-verification-otp',
      '/api/auth/verify-otp',
      '/api/debug/ip',
      '/api/maintenance-status',
      '/api/app/version',
      '/api/auth/check-duplicates'
    ];
    
    // ✅ ALWAYS allow admin routes to bypass maintenance
    const isAdminRoute = req.path.startsWith('/api/admin');
    
    // Skip maintenance for public routes
    if (publicRoutes.some(route => req.path.startsWith(route))) {
      return next();
    }
    
    // ✅ Skip maintenance for admin routes
    if (isAdminRoute) {
      console.log(`👑 Admin route bypass: ${req.method} ${req.path}`);
      return next();
    }
    
    // Check if the user is an admin via token
    let isAdminUser = false;
    const token = req.headers.authorization?.split(' ')[1];
    
    if (token) {
      try {
        const decoded = jwt.decode(token);
        if (decoded && decoded.id) {
          const user = await User.findById(decoded.id).select('isAdmin role').lean();
          if (user && (user.isAdmin === true || user.role === 'admin' || user.role === 'super_admin')) {
            isAdminUser = true;
          }
        }
      } catch (e) {
        // Token decode failed, continue
      }
    }
    
    // ✅ Allow admin users to bypass maintenance
    if (isAdminUser) {
      console.log(`👑 Admin user bypass: ${req.method} ${req.path}`);
      return next();
    }
    
    // 🔥 NEW: ALLOW READ-ONLY ENDPOINTS during maintenance
    const readOnlyEndpoints = [
      '/api/users/balance',
      '/api/users/commission-balance',
      '/api/commission/balance',
      '/api/transactions',
      '/api/commission/transactions',
      '/api/commission/stats',
      '/api/users/security-settings',
      '/api/beneficiaries',
      '/api/notifications',
      '/api/notifications/statistics',
      '/api/users/profile'
    ];
    
    const isReadOnly = readOnlyEndpoints.some(endpoint => req.path.startsWith(endpoint));
    
    // Check maintenance mode from database
    const settings = await Settings.findOne().lean();
    
    if (settings && settings.isMaintenanceMode === true) {
      // ✅ ALLOW read-only endpoints (GET requests only) during maintenance
      if (isReadOnly && req.method === 'GET') {
        console.log(`📖 READ-ONLY allowed during maintenance: ${req.method} ${req.path}`);
        return next();
      }
      
      // Block all other endpoints (POST, PUT, DELETE, etc.)
      console.log(`🚧 MAINTENANCE ACTIVE - Blocking: ${req.method} ${req.path}`);
      
      return res.status(503).json({
        success: false,
        message: settings.maintenanceMessage || 'System is currently under maintenance. Please try again later.',
        code: 'MAINTENANCE_MODE',
        maintenanceMode: true,
        maintenanceMessage: settings.maintenanceMessage || 'System under maintenance',
        readOnly: isReadOnly && req.method === 'GET'
      });
    }
    
    next();
  } catch (error) {
    console.error('Maintenance check error:', error);
    next();
  }
});
// ==================== END MAINTENANCE MIDDLEWARE ====================



// ================================================
// 📡 MAINTENANCE STATUS - WITH READ-ONLY INFO
// ================================================
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const settings = await Settings.findOne().lean();
    
    // Check if the requester is an admin
    let isAdmin = false;
    let adminDetails = {};
    
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      try {
        const decoded = jwt.decode(token);
        if (decoded && decoded.id) {
          const user = await User.findById(decoded.id).select('isAdmin role fullName email').lean();
          if (user && (user.isAdmin === true || user.role === 'admin' || user.role === 'super_admin')) {
            isAdmin = true;
            adminDetails = {
              name: user.fullName,
              email: user.email,
              role: user.role || 'admin'
            };
          }
        }
      } catch (e) {
        // Token decode failed
      }
    }
    
    const response = {
      success: true,
      maintenanceMode: settings?.isMaintenanceMode || false,
      message: settings?.maintenanceMessage || '',
      isAdmin: isAdmin,
      timestamp: new Date().toISOString(),
      // ✅ NEW: Tell frontend what's allowed during maintenance
      readOnlyAllowed: true,
      allowedEndpoints: [
        'View Balance',
        'View Transactions',
        'View Commission Balance',
        'View Notifications',
        'View Beneficiaries'
      ],
      blockedActions: [
        'New Transactions',
        'Airtime Purchase',
        'Data Purchase',
        'Electricity Bill Payment',
        'Cable TV Subscription',
        'International Airtime',
        'Education Purchase',
        'Insurance Purchase',
        'Money Transfer',
        'Wallet Funding'
      ]
    };
    
    // Add admin-specific info
    if (isAdmin) {
      response.adminDetails = adminDetails;
      response.maintenanceEnabled = settings?.isMaintenanceMode || false;
      response.maintenanceMessage = settings?.maintenanceMessage || '';
      response.adminNote = 'As an admin, you can still access all admin endpoints.';
    }
    
    res.json(response);
    
  } catch (error) {
    console.error('Maintenance status error:', error);
    res.json({
      success: false,
      maintenanceMode: false,
      message: 'Unable to fetch maintenance status',
      timestamp: new Date().toISOString(),
      readOnlyAllowed: false
    });
  }
});








app.use('/api/admin/export-transactions', adminExportRoutes);




const virtualAccountSyncRoutes = require("./routes/virtualAccountSyncRoutes");
app.use("/", virtualAccountSyncRoutes);


const transactionRoutes = require('./routes/transactionRoutes');
app.use('/api/transactions', transactionRoutes);
app.use('/api/referral', referralRoutes);


const commissionRoutes = require('./routes/commissionRoutes');
app.use('/api/commission', commissionRoutes);  // ← THIS LINE WAS MISSING

// ==================== RBAC ROUTES ====================
const rbacRoutes = require('./routes/rbacRoutes');
app.use('/api/rbac', rbacRoutes);



// Global OTP Variables (ADD THIS AT TOP, AFTER IMPORTS)
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
const otpStore = new Map();
const otpRequests = new Map(); // For rate limiting

// Clean expired OTPs periodically
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of otpStore.entries()) {
    if (data.expiresAt < now) {
      otpStore.delete(email);
    }
  }
  console.log(`🧹 Cleaned expired OTPs. Current store size: ${otpStore.size}`);
}, 5 * 60 * 1000);

// Clean old rate limiting entries
setInterval(() => {
  const now = Date.now();
  const window = 60 * 1000;
  
  for (const [email, timestamps] of otpRequests.entries()) {
    const recent = timestamps.filter(t => now - t < window);
    if (recent.length === 0) {
      otpRequests.delete(email);
    } else {
      otpRequests.set(email, recent);
    }
  }
  console.log(`🧹 Cleaned old rate limits. Current entries: ${otpRequests.size}`);
}, 10 * 60 * 1000);

// REMOVE OR COMMENT OUT THIS DUPLICATE protect FUNCTION
// const protect = async (req, res, next) => {
//   let token;
//   
//   if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
//     try {
//       token = req.headers.authorization.split(' ')[1];
//       const decoded = jwt.verify(token, process.env.JWT_SECRET);
//       req.user = await User.findById(decoded.id).select('-password');
//       next();
//     } catch (error) {
//       console.error('Auth error:', error);
//       res.status(401).json({ success: false, message: 'Not authorized' });
//     }
//   }
//   
//   if (!token) {
//     res.status(401).json({ success: false, message: 'Not authorized, no token' });
//   }
// };





// Initialize cache
const cache = new NodeCache({ stdTTL: 300 }); // 5 minutes cache
const userCache = new NodeCache({ stdTTL: 300, checkperiod: 60 }); // User cache for protect middleware
// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}
// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    cb(null, `${uuidv4()}-${file.originalname}`);
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 2 }, // 2MB limit
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  }
});


// ==================== STATIC FILE SERVING WITH CORS & CORP HEADERS ====================
// ✅ CRITICAL: Serve uploads WITH proper CORS + CORP headers
// This is REQUIRED for Flutter Web (browser) to load images
// MUST be registered BEFORE helmet() middleware so helmet doesn't override CORP
app.use('/uploads', (req, res, next) => {
  // Allow cross-origin image loading (Flutter Web)
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  // ✅ CRITICAL: This header allows Flutter Web to load images cross-origin
  res.header('Cross-Origin-Resource-Policy', 'cross-origin');
  // Allow caching
  res.header('Cache-Control', 'public, max-age=86400');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
}, express.static(uploadsDir, {
  maxAge: '1d',
  etag: true,
  lastModified: true,
}));

const PORT = process.env.PORT || 5000;

// ✅ Use the existing server instance (NO 'const' declaration)
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔌 Socket.IO server ready`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    mongoose.connection.close();
    process.exit(0);
  });
});



// Helper function to generate Request ID in Africa/Lagos timezone
function generateRequestId() {
  let lagosTime;
  if (moment && moment.tz) {
    lagosTime = moment.tz('Africa/Lagos');
  } else {
    // Fallback if moment-timezone is not available
    lagosTime = moment().utcOffset('+01:00');
  }
  
  const timestamp = lagosTime.format('YYYYMMDDHHmm');
  const suffix = uuidv4().replace(/-/g, '').substring(0, 12);
  return `${timestamp}_${suffix}`;
}
// Helper function to get current time in Africa/Lagos
function getLagosTime() {
  if (moment && moment.tz) {
    return moment.tz('Africa/Lagos').toDate();
  } else {
    // Fallback if moment-timezone is not available
    return moment().utcOffset('+01:00').toDate();
  }
}
// Password complexity validation
function validatePassword(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  return password.length >= minLength && 
         hasUpperCase && 
         hasLowerCase && 
         hasNumbers && 
         hasSpecialChar;
}





// Database Connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};
connectDB();

// ==================== JWT CONFIGURATION - LONG LASTING SESSION ====================
// JWT Token Generation - 30 days access + 180 days refresh
// This SAME function is used by BOTH email/password login AND biometric/PIN login
// ================================================================================

const generateToken = (id) => {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    console.error('❌ JWT_SECRET is not set!');
    throw new Error('JWT_SECRET not configured');
  }
  // ✅ 30 DAYS
  return jwt.sign({ id }, jwtSecret, { expiresIn: '30d' });
};

const generateRefreshToken = (id) => {
  const refreshSecret = process.env.REFRESH_TOKEN_SECRET;
  if (!refreshSecret) {
    console.error('❌ REFRESH_TOKEN_SECRET is not set!');
    throw new Error('REFRESH_TOKEN_SECRET not configured');
  }
  // ✅ 180 DAYS
  return jwt.sign({ id }, refreshSecret, { expiresIn: '180d' });
};

// ✅ Verify secrets are set
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set in environment variables');
  process.exit(1);
}

if (!process.env.REFRESH_TOKEN_SECRET) {
  console.error('❌ REFRESH_TOKEN_SECRET is not set in environment variables');
  process.exit(1);
}

// ✅ IMPROVED Auto-refresh token middleware
// This runs BEFORE protected routes and refreshes tokens that are about to expire
const autoRefreshToken = async (req, res, next) => {
  // Skip token refresh for public routes
  const publicRoutes = [
    '/api/users/register',
    '/api/users/login',
    '/api/users/refresh-token',
    '/api/users/forgot-password',
    '/api/users/reset-password',
    '/api/settings',
    '/api/debug/ip',
    '/health'
  ];
  
  if (publicRoutes.some(route => req.path.startsWith(route))) {
    return next();
  }
  
  const token = req.headers.authorization?.split(' ')[1];
  const refreshToken = req.headers['x-refresh-token'];
  
  // If no token at all, continue (will be caught by protect middleware)
  if (!token) {
    return next();
  }
  
  try {
    // Try to verify the current token without checking expiration
    const decoded = jwt.decode(token);
    if (!decoded) {
      return next();
    }
    
    // Check if token will expire in the next 15 minutes
    const tokenExp = decoded.exp * 1000;
    const now = Date.now();
    const expiresIn = tokenExp - now;
    
    // If token expires soon and we have a refresh token, refresh it
    if (expiresIn < (15 * 60 * 1000) && refreshToken) {
      console.log('🔄 Token expiring soon, refreshing...');
      
      try {
        const decodedRefresh = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedRefresh.id);
        
        if (user && user.refreshToken === refreshToken) {
          const newToken = generateToken(user._id);
          const newRefreshToken = generateRefreshToken(user._id);
          
          // Update refresh token in database
          user.refreshToken = newRefreshToken;
          user.lastTokenRefresh = new Date();
          await user.save();
          
          // Set new tokens in response headers so frontend can pick them up
          res.set('x-new-token', newToken);
          res.set('x-new-refresh-token', newRefreshToken);
          
          // Attach user to request for the protect middleware
          req.user = user;
          req.tokenRefreshed = true;
          
          console.log('✅ Token refreshed proactively');
          console.log(`   New access token: 30 days`);
          console.log(`   New refresh token: 180 days`);
          return next();
        }
      } catch (refreshError) {
        console.error('❌ Proactive refresh failed:', refreshError.message);
      }
    }
    
    return next();
  } catch (error) {
    console.error('Auto-refresh middleware error:', error);
    return next();
  }
};

// FINAL PROTECT MIDDLEWARE — FIXED VERSION
// ==================== FIXED PROTECT MIDDLEWARE ====================
// ==================== UPDATED PROTECT MIDDLEWARE ====================
const protect = async (req, res, next) => {
  let token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    console.log('❌ No token provided');
    return res.status(401).json({
      success: false,
      message: 'No token provided. Please log in.',
      code: 'NO_TOKEN'
    });
  }

  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('❌ JWT_SECRET not configured');
      return res.status(500).json({
        success: false,
        message: 'Server configuration error'
      });
    }

    const decoded = jwt.verify(token, jwtSecret);
    const user = await User.findById(decoded.id).select('-password').lean();
    
    if (!user) {
      console.log('❌ User not found for ID:', decoded.id);
      return res.status(401).json({ 
        success: false, 
        message: 'User not found', 
        code: 'USER_NOT_FOUND' 
      });
    }
    
    if (!user.isActive) {
      console.log('❌ Account deactivated for user:', user.email);
      return res.status(401).json({ 
        success: false, 
        message: 'Account deactivated', 
        code: 'INACTIVE' 
      });
    }

    req.user = user;
    req.userId = user._id;
    
    // ✅ Auto-refresh token if about to expire
    const tokenExp = decoded.exp * 1000;
    const now = Date.now();
    const timeToExpiry = tokenExp - now;
    const oneDayMs = 24 * 60 * 60 * 1000;

    if (timeToExpiry < oneDayMs && timeToExpiry > 0) {
      console.log(`🔄 Auto-refreshing token (expires in ${Math.round(timeToExpiry / 3600000)}h)`);
      
      try {
        const refreshToken = req.headers['x-refresh-token'];
        if (refreshToken) {
          const refreshSecret = process.env.REFRESH_TOKEN_SECRET;
          const decodedRefresh = jwt.verify(refreshToken, refreshSecret);
          
          if (decodedRefresh.id.toString() === user._id.toString()) {
            const newToken = generateToken(user._id);
            const newRefreshToken = generateRefreshToken(user._id);
            
            await User.findByIdAndUpdate(user._id, { 
              refreshToken: newRefreshToken,
              lastTokenRefresh: new Date()
            });
            
            res.set('x-new-token', newToken);
            res.set('x-new-refresh-token', newRefreshToken);
            console.log('✅ Token auto-refreshed successfully');
          }
        }
      } catch (refreshError) {
        console.log('⚠️ Auto-refresh failed:', refreshError.message);
      }
    }

    next();

  } catch (error) {
    console.error('❌ Protect middleware error:', error.name, error.message);
    
    if (error.name === 'TokenExpiredError') {
      const refreshToken = req.headers['x-refresh-token'];
      
      if (refreshToken) {
        try {
          const refreshSecret = process.env.REFRESH_TOKEN_SECRET;
          const decodedRefresh = jwt.verify(refreshToken, refreshSecret);
          
          const user = await User.findById(decodedRefresh.id);
          if (user && user.isActive) {
            const newToken = generateToken(user._id);
            const newRefreshToken = generateRefreshToken(user._id);
            
            user.refreshToken = newRefreshToken;
            user.lastTokenRefresh = new Date();
            await user.save();
            
            res.set('x-new-token', newToken);
            res.set('x-new-refresh-token', newRefreshToken);
            
            req.user = user;
            req.tokenRefreshed = true;
            
            console.log('✅ Token auto-refreshed via refresh token');
            return next();
          }
        } catch (refreshError) {
          console.error('❌ Auto-refresh failed:', refreshError.message);
        }
      }
      
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please login again.',
        code: 'TOKEN_EXPIRED',
        requiresRefresh: true
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. Please login again.',
        code: 'INVALID_TOKEN'
      });
    }

    return res.status(401).json({
      success: false,
      message: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};



// After your protect middleware (around line ~250), add:

// ==================== SERVICE AVAILABILITY MIDDLEWARE ====================

// Reusable middleware to check if a service is enabled globally
// ==================== SERVICE AVAILABILITY MIDDLEWARE - COMPLETE ====================
const checkServiceEnabled = (serviceKey) => {
  return async (req, res, next) => {
    try {
      const settings = await Settings.findOne();
      
      if (!settings || settings[serviceKey] === false) {
        const serviceNames = {
          // ===== CORE SERVICES =====
          'isAirtimeEnabled': 'Airtime service',
          'isDataEnabled': 'Data service',
          'isCableTvEnabled': 'Cable TV service',
          'isElectricityEnabled': 'Electricity service',
          'isTransferEnabled': 'Money transfer service',
          
          // ===== ADDITIONAL SERVICES =====
          'isInternationalAirtimeEnabled': 'International Airtime service',
          'isEducationEnabled': 'Education service',
          'isInsuranceEnabled': 'Insurance service',
          
          // ===== SYSTEM =====
          'isMaintenanceMode': 'Maintenance mode'
        };
        
        const serviceName = serviceNames[serviceKey] || 'This service';
        
        console.log(`🚫 [SERVICE DISABLED] ${serviceName} (${serviceKey}) is currently disabled`);
        
        return res.status(403).json({
          success: false,
          message: `${serviceName} is currently disabled. Please try again later.`,
          code: 'SERVICE_DISABLED',
          serviceKey: serviceKey,
          timestamp: new Date().toISOString()
        });
      }
      
      next();
    } catch (error) {
      console.error(`❌ Error checking ${serviceKey}:`, error);
      res.status(500).json({ 
        success: false, 
        message: 'Service availability check failed',
        code: 'SERVICE_CHECK_FAILED'
      });
    }
  };
};


// ================================================
// 📊 TRANSACTION LIMITS
// ================================================

// ================================================
// 📊 TRANSACTION LIMITS - COMPLETE
// ================================================

const TRANSACTION_LIMITS = {
  daily: {
    airtime: 5000,
    data: 10000,
    electricity: 100000,
    cable: 500000,
    transfer: 100000,
    international_airtime: 50000,
    education: 100000,
    insurance: 100000,
    proxy: 50000,
    walletFunding: 1000000,
    default: 100000
  },
  perTransaction: {
    airtime: 1000,
    data: 10000,
    electricity: 50000,
    cable: 100000,
    transfer: 50000,
    international_airtime: 10000,
    education: 50000,
    insurance: 50000,
    proxy: 50000,
    default: 50000
  }
};

// ==================== CHECK TRANSACTION LIMIT - FIXED VERSION ====================
// ==================== CHECK TRANSACTION LIMIT - COMPLETE FIX ====================
const checkTransactionLimit = (serviceType) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?._id;
      if (!userId) return next();
      
      const amount = parseFloat(req.body.amount || req.body.Amount || 0);
      if (amount <= 0) return next();
      
      // ================================================
      // COMPLETE SERVICE KEY MAPPING
      // ================================================
      let limitKey = serviceType;
      
     const serviceKeyMap = {
  // ===== AIRTIME =====
  'airtime': 'airtime',
  'airtime_purchase': 'airtime',
  'mtn': 'airtime',
  'airtel': 'airtime',
  'glo': 'airtime',
  'etisalat': 'airtime',
  '9mobile': 'airtime',
  'mtn-airtime': 'airtime',
  'airtel-airtime': 'airtime',
  'glo-airtime': 'airtime',
  'etisalat-airtime': 'airtime',
  '9mobile-airtime': 'airtime',
  
  // ===== DATA =====
  'data': 'data',
  'data_purchase': 'data',
  'mtn-data': 'data',
  'airtel-data': 'data',
  'glo-data': 'data',
  'etisalat-data': 'data',
  '9mobile-data': 'data',
  'glo-sme-data': 'data',
  
  // ===== CABLE TV =====
  'cable': 'cable',
  'cableTv': 'cable',
  'cabletv': 'cable',
  'cable-tv': 'cable',
  'tv': 'cable',
  'dstv': 'cable',
  'gotv': 'cable',
  'startimes': 'cable',
  'showmax': 'cable',
  
  // ===== ELECTRICITY =====
  'electricity': 'electricity',
  'electric': 'electricity',
  'ikeja-electric': 'electricity',
  'eko-electric': 'electricity',
  'abuja-electric': 'electricity',
  'ibadan-electric': 'electricity',
  'enugu-electric': 'electricity',
  'kano-electric': 'electricity',
  'ph-electric': 'electricity',
  'portharcourt-electric': 'electricity',
  'jos-electric': 'electricity',
  'kaduna-electric': 'electricity',
  'benin-electric': 'electricity',
  'aba-electric': 'electricity',
  'yola-electric': 'electricity',
  
  // ===== TRANSFER =====
  'transfer': 'transfer',
  'peer_transfer': 'transfer',
  'wallet_transfer': 'transfer',
  'send_money': 'transfer',
  
  // ===== INTERNATIONAL AIRTIME ✅ FIXED =====
  'international_airtime': 'international_airtime',
  'int_airtime': 'international_airtime',
  'foreign-airtime': 'international_airtime',
  'internationalAirtime': 'international_airtime', // ✅ ADD THIS
  'international-airtime': 'international_airtime', // ✅ ADD THIS
  
  // ===== EDUCATION =====
  'education': 'education',
  'waec': 'education',
  'waec-registration': 'education',
  'jamb': 'education',
  'jamb-registration': 'education',
  'neco': 'education',
  'nabteb': 'education',
  
  // ===== INSURANCE =====
  'insurance': 'insurance',
  'ui-insure': 'insurance',
  
  // ===== PROXY / DEFAULT =====
  'proxy': 'proxy',
};      
      if (serviceKeyMap[limitKey]) {
        limitKey = serviceKeyMap[limitKey];
      }
      
      console.log(`🔍 [LIMIT CHECK] Service: ${serviceType} → Key: ${limitKey}, Amount: ₦${amount}`);
      
      // ================================================
      // 🔥 GET USER - SIMPLIFIED AND RELIABLE
      // ================================================
      const user = await User.findById(userId).lean();
      if (!user) {
        console.log(`❌ User ${userId} not found`);
        return next();
      }
      
      // ================================================
      // 🔥 EXTRACT CUSTOM LIMITS - SAFELY
      // ================================================
      const customLimits = user.customLimits || {};
      
      console.log(`👤 User ${userId} customLimits found:`, Object.keys(customLimits).length > 0 ? 'YES' : 'NO');
      if (Object.keys(customLimits).length > 0) {
        console.log(`👤 User ${userId} customLimits:`, JSON.stringify(customLimits));
      }
      
      // ================================================
      // CHECK PER-TRANSACTION LIMIT
      // ================================================
      let perTxLimit = TRANSACTION_LIMITS.perTransaction[limitKey] || 
                       TRANSACTION_LIMITS.perTransaction.default;
      
      // Check if user has custom limit for this service
      const serviceLimit = customLimits[limitKey];
      if (serviceLimit && typeof serviceLimit === 'object') {
        // Check perTransaction
        if (serviceLimit.perTransaction && serviceLimit.perTransaction > 0) {
          perTxLimit = parseFloat(serviceLimit.perTransaction);
          console.log(`🔧 User ${userId} has CUSTOM per-transaction limit for ${limitKey}: ₦${perTxLimit}`);
        }
      }
      
      console.log(`📊 Per-transaction limit for ${limitKey}: ₦${perTxLimit}`);
      
      if (amount > perTxLimit) {
        console.log(`🚫 PER-TRANSACTION LIMIT EXCEEDED: ₦${amount} > ₦${perTxLimit}`);
        return res.status(400).json({
          success: false,
          message: `Maximum ${limitKey} per transaction is ₦${perTxLimit.toFixed(2)}.`,
          code: 'PER_TRANSACTION_LIMIT_EXCEEDED',
          limit: perTxLimit,
          requested: amount,
          isCustomLimit: customLimits[limitKey]?.perTransaction ? true : false,
          service: limitKey
        });
      }
      
      // ================================================
      // CHECK DAILY LIMIT
      // ================================================
      let dailyLimit = TRANSACTION_LIMITS.daily[limitKey] || 
                       TRANSACTION_LIMITS.daily.default;
      
      if (serviceLimit && typeof serviceLimit === 'object') {
        if (serviceLimit.dailyCap && serviceLimit.dailyCap > 0) {
          dailyLimit = parseFloat(serviceLimit.dailyCap);
          console.log(`🔧 User ${userId} has CUSTOM daily limit for ${limitKey}: ₦${dailyLimit}`);
        }
      }
      
      console.log(`📊 Daily limit for ${limitKey}: ₦${dailyLimit}`);
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      const serviceRegex = new RegExp(limitKey, 'i');
      
      const todayTotal = await Transaction.aggregate([
        {
          $match: {
            userId: new mongoose.Types.ObjectId(userId),
            type: { $regex: serviceRegex },
            status: { $regex: /success|completed|Successful/i },
            createdAt: { $gte: today }
          }
        },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]);
      
      const dailyTotal = todayTotal[0]?.total || 0;
      
      console.log(`📊 Today's total for ${limitKey}: ₦${dailyTotal}`);
      
      if (dailyTotal + amount > dailyLimit) {
        const remaining = Math.max(0, dailyLimit - dailyTotal);
        console.log(`🚫 DAILY LIMIT EXCEEDED: ₦${dailyTotal + amount} > ₦${dailyLimit}`);
        return res.status(400).json({
          success: false,
          message: `Daily ${limitKey} limit of ₦${dailyLimit.toFixed(2)} exceeded. Today: ₦${dailyTotal.toFixed(2)}. Remaining: ₦${remaining.toFixed(2)}.`,
          code: 'DAILY_LIMIT_EXCEEDED',
          dailyLimit: dailyLimit,
          dailyTotal: dailyTotal,
          requested: amount,
          remaining: remaining,
          isCustomLimit: customLimits[limitKey]?.dailyCap ? true : false,
          service: limitKey
        });
      }
      
      console.log(`✅ LIMIT CHECK PASSED: ₦${amount} (Per-txn: ₦${perTxLimit}, Daily: ₦${dailyTotal} → ₦${dailyTotal + amount})`);
      next();
      
    } catch (error) {
      console.error('❌ Limit check error:', error);
      console.error('❌ Error stack:', error.stack);
      next();
    }
  };
};



// ==================== SMART LIMIT CHECK - COMPLETE SERVICE MAPPING ====================
const smartLimitCheck = async (req, res, next) => {
  try {
    const { serviceID, variation_code, type, network, serviceType } = req.body;
    let limitService = 'proxy';
    
    // ================================================
    // ✅ FIX #1: Check explicit serviceType FIRST
    // This handles insurance, education, and any future
    // services that send an explicit serviceType field.
    // ================================================
    if (serviceType) {
      const normalizedServiceType = serviceType.toString().toLowerCase().trim();
      const validServiceTypes = [
        'airtime', 'data', 'cable', 'electricity', 
        'transfer', 'international_airtime', 'education', 
        'insurance', 'wallet'
      ];
      
      if (validServiceTypes.includes(normalizedServiceType)) {
        limitService = normalizedServiceType;
        console.log(`🔍 [SMART LIMIT] Explicit serviceType: "${serviceType}" → Limit Key: ${limitService}`);
        
        // Execute the limit check and return immediately
        await checkTransactionLimit(limitService)(req, res, next);
        return;
      }
    }
    
    // ================================================
    // COMPLETE SERVICE MAPPING - ALL SERVICES
    // ================================================
    const serviceLimitMap = {
      // ===== AIRTIME SERVICES =====
      'mtn': 'airtime',
      'airtel': 'airtime',
      'glo': 'airtime',
      'etisalat': 'airtime',
      '9mobile': 'airtime',
      'mtn-airtime': 'airtime',
      'airtel-airtime': 'airtime',
      'glo-airtime': 'airtime',
      'etisalat-airtime': 'airtime',
      '9mobile-airtime': 'airtime',
      
      // ===== DATA SERVICES =====
      'mtn-data': 'data',
      'airtel-data': 'data',
      'glo-data': 'data',
      'etisalat-data': 'data',
      '9mobile-data': 'data',
      'glo-sme-data': 'data',
      
      // ===== CABLE TV SERVICES =====
      'dstv': 'cable',
      'gotv': 'cable',
      'startimes': 'cable',
      'showmax': 'cable',
      
      // ===== ELECTRICITY SERVICES =====
      'ikeja-electric': 'electricity',
      'eko-electric': 'electricity',
      'abuja-electric': 'electricity',
      'ibadan-electric': 'electricity',
      'enugu-electric': 'electricity',
      'kano-electric': 'electricity',
      'ph-electric': 'electricity',
      'portharcourt-electric': 'electricity',
      'jos-electric': 'electricity',
      'kaduna-electric': 'electricity',
      'benin-electric': 'electricity',
      'aba-electric': 'electricity',
      'yola-electric': 'electricity',
      
      // ===== EDUCATION SERVICES =====
      'waec': 'education',
      'waec-registration': 'education',
      'jamb': 'education',
      'jamb-registration': 'education',
      'neco': 'education',
      'nabteb': 'education',
      
      // ===== INTERNATIONAL AIRTIME =====
      'foreign-airtime': 'international_airtime',
      'international-airtime': 'international_airtime',
      'international_airtime': 'international_airtime',
      'int_airtime': 'international_airtime',
      
      // ===== INSURANCE =====
      'ui-insure': 'insurance',
      'insurance': 'insurance',
      
      // ===== TRANSFER =====
      'transfer': 'transfer',
      'wallet-transfer': 'transfer',
    };
    
    // ================================================
    // ✅ FIX #2: Detect insurance by its UNIQUE fields
    // Insurance requests contain: plateNumber, vehicleMake, insuredName
    // ================================================
    if (req.body.plateNumber && req.body.vehicleMake && req.body.insuredName) {
      limitService = 'insurance';
      console.log(`🔍 [SMART LIMIT] Insurance detected by fields (plateNumber, vehicleMake, insuredName) → Limit Key: insurance`);
    }
    // Check by serviceID first
    else if (serviceID && serviceLimitMap[serviceID]) {
      limitService = serviceLimitMap[serviceID];
      console.log(`🔍 [SMART LIMIT] ServiceID: ${serviceID} → Limit Key: ${limitService}`);
    } 
    // Check by network for airtime/data
    else if (network && serviceLimitMap[network]) {
      limitService = serviceLimitMap[network];
      console.log(`🔍 [SMART LIMIT] Network: ${network} → Limit Key: ${limitService}`);
    }
    // Check by variation_code for cable TV
    else if (variation_code && (variation_code.includes('dstv') || variation_code.includes('gotv') || variation_code.includes('startimes'))) {
      limitService = 'cable';
      console.log(`🔍 [SMART LIMIT] Variation: ${variation_code} → Limit Key: cable`);
    }
    // Check by type for electricity
    else if (type && (type === 'prepaid' || type === 'postpaid')) {
      limitService = 'electricity';
      console.log(`🔍 [SMART LIMIT] Type: ${type} → Limit Key: electricity`);
    }
    // Check by operatorId for international airtime
    else if (req.body.operatorId && req.body.productTypeId) {
      limitService = 'international_airtime';
      console.log(`🔍 [SMART LIMIT] International Airtime detected → Limit Key: international_airtime`);
    }
    // Default
    else {
      console.log(`🔍 [SMART LIMIT] No mapping found for serviceID: ${serviceID}, using default: proxy`);
    }
    
    console.log(`🔍 [SMART LIMIT] Final limit key: ${limitService}`);
    
    // Execute the limit check with the determined service
    await checkTransactionLimit(limitService)(req, res, next);
    
  } catch (error) {
    console.error('❌ Smart limit check error:', error);
    next();
  }
};

// ================================================
// 🚫 PER-MINUTE TRANSACTION LIMIT
// Prevents multiple transactions in the same minute
// ================================================

const userTransactionTracker = new Map(); // Tracks recent transactions per user

const checkPerMinuteLimit = (serviceType) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?._id?.toString();
      if (!userId) return next();

      const now = Date.now();
      const oneMinuteAgo = now - 60000; // 60 seconds

      // Get user's transaction history
      if (!userTransactionTracker.has(userId)) {
        userTransactionTracker.set(userId, []);
      }

      const userHistory = userTransactionTracker.get(userId);
      
      // Clean old entries (older than 1 minute)
      const recentTransactions = userHistory.filter(t => t.timestamp > oneMinuteAgo);
      
      // Update the tracker with cleaned history
      userTransactionTracker.set(userId, recentTransactions);

      // Count transactions in the last minute
      const transactionCount = recentTransactions.length;
      
      // ⚠️ MAX 3 TRANSACTIONS PER MINUTE (adjust as needed)
      const MAX_PER_MINUTE = 3;

      if (transactionCount >= MAX_PER_MINUTE) {
        console.log(`🚫 [RATE LIMIT] User ${userId} exceeded ${MAX_PER_MINUTE} transactions in 1 minute`);
        console.log(`   Transactions in last minute: ${transactionCount}`);
        console.log(`   Timestamps: ${recentTransactions.map(t => new Date(t.timestamp).toISOString()).join(', ')}`);
        
        return res.status(429).json({
          success: false,
          message: `Too many transactions. Maximum ${MAX_PER_MINUTE} transactions per minute allowed. Please wait a moment.`,
          code: 'PER_MINUTE_LIMIT_EXCEEDED',
          limit: MAX_PER_MINUTE,
          currentCount: transactionCount,
          retryAfter: 60 // seconds
        });
      }

      // Store this transaction (will be removed after 1 minute)
      // We use a unique key to prevent duplicate tracking
      const uniqueKey = `${serviceType}_${req.body.phone || req.body.billersCode || Date.now()}`;
      recentTransactions.push({
        timestamp: now,
        key: uniqueKey,
        serviceType: serviceType,
        amount: parseFloat(req.body.amount || 0)
      });

      // Store back
      userTransactionTracker.set(userId, recentTransactions);

      next();
    } catch (error) {
      console.error('Per-minute limit check error:', error);
      next();
    }
  };
};

// Clean up old entries every minute
setInterval(() => {
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  
  for (const [userId, history] of userTransactionTracker.entries()) {
    const recent = history.filter(t => t.timestamp > oneMinuteAgo);
    if (recent.length === 0) {
      userTransactionTracker.delete(userId);
    } else {
      userTransactionTracker.set(userId, recent);
    }
  }
}, 60000); // Run every minute


// ================================================
// 🚫 GLOBAL PER-MINUTE LIMIT (All Services)
// ================================================

const globalTransactionTracker = new Map();

const checkGlobalPerMinuteLimit = async (req, res, next) => {
  try {
    const userId = req.user?._id?.toString();
    if (!userId) return next();

    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    if (!globalTransactionTracker.has(userId)) {
      globalTransactionTracker.set(userId, []);
    }

    const history = globalTransactionTracker.get(userId);
    const recent = history.filter(t => t > oneMinuteAgo);
    
    globalTransactionTracker.set(userId, recent);

    // ⚠️ MAX 5 TRANSACTIONS PER MINUTE ACROSS ALL SERVICES
    const MAX_GLOBAL_PER_MINUTE = 5;

    if (recent.length >= MAX_GLOBAL_PER_MINUTE) {
      console.log(`🚫 [GLOBAL LIMIT] User ${userId} exceeded ${MAX_GLOBAL_PER_MINUTE} total transactions in 1 minute`);
      
      return res.status(429).json({
        success: false,
        message: `Too many transactions. Maximum ${MAX_GLOBAL_PER_MINUTE} transactions per minute across all services. Please wait.`,
        code: 'GLOBAL_PER_MINUTE_LIMIT_EXCEEDED',
        limit: MAX_GLOBAL_PER_MINUTE,
        currentCount: recent.length,
        retryAfter: 60
      });
    }

    recent.push(now);
    globalTransactionTracker.set(userId, recent);

    next();
  } catch (error) {
    console.error('Global per-minute limit error:', error);
    next();
  }
};

// Clean up every minute
setInterval(() => {
  const now = Date.now();
  const oneMinuteAgo = now - 60000;
  
  for (const [userId, timestamps] of globalTransactionTracker.entries()) {
    const recent = timestamps.filter(t => t > oneMinuteAgo);
    if (recent.length === 0) {
      globalTransactionTracker.delete(userId);
    } else {
      globalTransactionTracker.set(userId, recent);
    }
  }
}, 60000);




// ==================== VTPASS REQUERY FUNCTION ====================
// @desc    Requery transaction status from VTpass
// @access  Internal
const vtpassRequery = async (requestId) => {
  try {
    console.log(`🔄 REQUERYING transaction: ${requestId}`);
    
    const response = await axios.post('https://vtpass.com/api/requery', {
      request_id: requestId
    }, {
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.VTPASS_API_KEY,
        'secret-key': process.env.VTPASS_SECRET_KEY,
      },
      timeout: 15000
    });
    
    console.log(`📡 Requery response for ${requestId}:`, response.data);
    
    return {
      success: true,
      data: response.data
    };
  } catch (error) {
    console.error(`❌ Requery failed for ${requestId}:`, error.message);
    return {
      success: false,
      message: error.message,
      data: null
    };
  }
};

// ==================== BACKGROUND REQUERY SERVICE ====================
// This runs every 30 seconds to check pending transactions
const pendingTransactionsCache = new Map();

const startBackgroundRequeryService = () => {
  console.log('🔄 Starting background requery service...');
  
  setInterval(async () => {
    try {
      // Find pending transactions from last 24 hours
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
      
      const pendingTransactions = await Transaction.find({
        status: { $in: ['Pending', 'Processing'] },
        createdAt: { $gte: oneDayAgo },
        type: { $in: ['Electricity Purchase', 'Data Purchase', 'Airtime Purchase', 'Cable TV Subscription'] }
      }).limit(50);
      
      if (pendingTransactions.length === 0) return;
      
      console.log(`🔍 Found ${pendingTransactions.length} pending transactions to requery`);
      
      for (const transaction of pendingTransactions) {
        const requestId = transaction.reference || transaction.transactionId;
        
        // Skip if we already requeried this in last 30 seconds
        const lastRequery = pendingTransactionsCache.get(requestId);
        if (lastRequery && (Date.now() - lastRequery) < 30000) {
          continue;
        }
        
        pendingTransactionsCache.set(requestId, Date.now());
        
        // Requery VTpass
        const requeryResult = await vtpassRequery(requestId);
        
        if (requeryResult.success && requeryResult.data) {
          const vtpassData = requeryResult.data;
          const transactionStatus = vtpassData.content?.transactions?.status || vtpassData.status;
          
          // Update transaction status based on VTpass response
          if (transactionStatus === 'delivered') {
            transaction.status = 'Successful';
            transaction.metadata.vtpassRequeryStatus = 'delivered';
            transaction.metadata.requeriedAt = new Date();
            await transaction.save();
            console.log(`✅ Transaction ${requestId} updated to Successful via requery`);
            
            // Create notification
            try {
              await Notification.create({
                recipient: transaction.userId,
                title: "Transaction Completed ✅",
                message: `Your ${transaction.type} of ₦${transaction.amount} has been confirmed.`,
                type: 'transaction',
                isRead: false
              });
            } catch (notifError) {
              console.error('Notification error:', notifError.message);
            }
          } else if (transactionStatus === 'failed') {
            transaction.status = 'Failed';
            transaction.metadata.vtpassRequeryStatus = 'failed';
            transaction.metadata.requeriedAt = new Date();
            await transaction.save();
            console.log(`❌ Transaction ${requestId} updated to Failed via requery`);
          }
        }
      }
      
      // Clean old cache entries (older than 1 hour)
      for (const [key, timestamp] of pendingTransactionsCache.entries()) {
        if (Date.now() - timestamp > 3600000) {
          pendingTransactionsCache.delete(key);
        }
      }
      
    } catch (error) {
      console.error('Background requery error:', error.message);
    }
  }, 30000); // Run every 30 seconds
};

// Start the background service when server starts
startBackgroundRequeryService();







// ==================== APP VERSION CHECK ENDPOINT ====================
// @desc    Check if app needs update
// @route   GET /api/app/version
// @access  Public
// ==================== APP VERSION CHECK ENDPOINT ====================
app.get('/api/app/version', async (req, res) => {
  try {
    const platform = req.query.platform || 'android';
    const currentVersion = req.query.version || '1.0.0';
    
    const versions = {
      android: {
        minimum: '1.4.0',  // ✅ Updated minimum version
        latest: '1.5.0',   // ✅ Updated to 1.5.0
        updateUrl: 'https://play.google.com/store/apps/details?id=com.dalabapay.official',
        whatsNew: [
          '🎉 New Service Commission Management',
          '⚡ Improved electricity bill payment',
          '🔒 Enhanced PIN security with lockout protection',
          '📱 Modernized UI/UX across all screens',
          '🐛 Bug fixes and performance improvements',
          '🔄 Better app update detection',
          '📊 Enhanced transaction history'
        ],
        isRequired: false,
        releaseDate: '2025-08-25'
      },
      ios: {
        minimum: '1.4.0',  // ✅ Updated minimum version
     
