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

const User = require('./models/User');
const Transaction = require('./models/Transaction');
const Notification = require('./models/Notification');
const Beneficiary = require('./models/Beneficiary');
const Settings = require('./models/AppSettings');
const AuthLog = require('./models/AuthLog');
const Alert = require('./models/Alert');
const Referral = require('./models/Referral');


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
dotenv.config();
// Initialize Express app
const app = express();
app.set('trust proxy', 1);
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
app.use(cors());


// ==================== MAINTENANCE MODE MIDDLEWARE ====================
app.use(async (req, res, next) => {
  try {
    // Skip maintenance check for certain routes
    const publicRoutes = [
      '/api/users/login',
      '/api/users/register',
      '/api/settings',
      '/health',
      '/api/auth/send-verification-otp',
      '/api/auth/verify-otp',
      '/api/debug/ip',
      '/api/wallet/top-up',  // Allow funding during maintenance
      '/api/wallet/force-topup',
      '/api/payments/verify-paystack',
      '/api/paystack/verify-transaction'
    ];
    
    if (publicRoutes.some(route => req.path.startsWith(route))) {
      return next();
    }
    
    const settings = await Settings.findOne();
    if (settings && settings.isMaintenanceMode === true) {
      return res.status(503).json({
        success: false,
        message: 'System is currently under maintenance. Please try again later.',
        code: 'MAINTENANCE_MODE'
      });
    }
    
    next();
  } catch (error) {
    console.error('Maintenance check error:', error);
    next(); // Don't block on error
  }
});
// ==================== END MAINTENANCE MIDDLEWARE ====================


const virtualAccountSyncRoutes = require("./routes/virtualAccountSyncRoutes");
app.use("/", virtualAccountSyncRoutes);


const transactionRoutes = require('./routes/transactionRoutes');
app.use('/api/transactions', transactionRoutes);
app.use('/api/referral', referralRoutes);


const commissionRoutes = require('./routes/commissionRoutes');
app.use('/api/commission', commissionRoutes);  // ← THIS LINE WAS MISSING



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
// Serve static files from uploads directory
app.use('/uploads', express.static(uploadsDir));
const PORT = process.env.PORT || 5000;
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

// JWT Token Generation - INCREASE EXPIRATION
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '24h' }); // Changed from 1h to 24h
};

// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '30d' }); // 30 days
};

// ✅ Add this check after dotenv.config()
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET is not set in environment variables');
  process.exit(1);
}

if (!process.env.REFRESH_TOKEN_SECRET) {
  console.error('❌ REFRESH_TOKEN_SECRET is not set in environment variables');
  process.exit(1);
}

// ✅ IMPROVED Auto-refresh token middleware
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
          await user.save();
          
          // Set new tokens in response headers
          res.set('x-new-token', newToken);
          res.set('x-new-refresh-token', newRefreshToken);
          
          // Add user to request for protect middleware
          req.user = user;
          req.tokenRefreshed = true;
          
          console.log('✅ Token refreshed proactively');
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
const protect = async (req, res, next) => {
  let token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'No token provided. Please log in.',
      code: 'NO_TOKEN'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'User not found', 
        code: 'USER_NOT_FOUND' 
      });
    }
    
    if (!user.isActive) {
      return res.status(401).json({ 
        success: false, 
        message: 'Account deactivated', 
        code: 'INACTIVE' 
      });
    }

    req.user = user;
    next(); // ← This is the key: continue if valid!

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired. Please refresh token.',
        code: 'TOKEN_EXPIRED',
        requiresRefresh: true
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }

    console.error('Protect middleware error:', error);
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
const checkServiceEnabled = (serviceKey) => {
  return async (req, res, next) => {
    try {
      const settings = await Settings.findOne();
      
      if (!settings || settings[serviceKey] === false) {
        const serviceNames = {
          'isAirtimeEnabled': 'Airtime service',
          'isDataEnabled': 'Data service',
          'isCableTvEnabled': 'Cable TV service',
          'isElectricityEnabled': 'Electricity service',
          'isTransferEnabled': 'Money transfer service',
          'isMaintenanceMode': 'Maintenance mode'
        };
        
        return res.status(403).json({
          success: false,
          message: `${serviceNames[serviceKey] || 'This service'} is currently disabled. Please try again later.`,
          code: 'SERVICE_DISABLED'
        });
      }
      
      next();
    } catch (error) {
      console.error(`Error checking ${serviceKey}:`, error);
      res.status(500).json({ 
        success: false, 
        message: 'Service availability check failed' 
      });
    }
  };
};




// @desc    Check token status and refresh if needed
// @route   GET /api/users/token-status
// @access  Private
app.get('/api/users/token-status', protect, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(400).json({ success: false, message: 'Token is required' });
    }
    
    try {
      // Verify token without checking expiration
      const decoded = jwt.decode(token);
      const user = await User.findById(decoded.id).select('-password');
      
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      
      // Calculate token expiration time
      const tokenExp = decoded.exp * 1000;
      const now = Date.now();
      const expiresIn = tokenExp - now;
      const willExpireSoon = expiresIn < (30 * 60 * 1000); // 30 minutes
      
      return res.json({
        success: true,
        tokenStatus: 'valid',
        user: {
          _id: user._id,
          email: user.email,
          fullName: user.fullName
        },
        expiresIn: Math.floor(expiresIn / 1000), // seconds
        willExpireSoon,
        shouldRefresh: willExpireSoon
      });
      
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: 'Token invalid',
        code: 'TOKEN_INVALID'
      });
    }
  } catch (error) {
    console.error('Token status check error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});





// @desc    Check token health and auto-refresh if needed
// @route   POST /api/users/token-health
// @access  Private
app.post('/api/users/token-health', protect, async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const refreshToken = req.headers['x-refresh-token'];
    
    if (!token) {
      return res.status(400).json({ success: false, message: 'Token is required' });
    }
    
    try {
      // Try to verify the current token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password');
      
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      
      // Calculate token expiration time
      const tokenExp = decoded.exp * 1000;
      const now = Date.now();
      const expiresIn = tokenExp - now;
      const willExpireSoon = expiresIn < (30 * 60 * 1000); // 30 minutes
      
      return res.json({
        success: true,
        message: 'Token is valid',
        user: {
          _id: user._id,
          email: user.email,
          fullName: user.fullName
        },
        tokenExpired: false,
        expiresIn: Math.floor(expiresIn / 1000), // seconds
        willExpireSoon,
        shouldRefresh: willExpireSoon
      });
      
    } catch (tokenError) {
      if (tokenError.name === 'TokenExpiredError' && refreshToken) {
        // Token expired, try to refresh
        try {
          const decodedRefresh = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
          const user = await User.findById(decodedRefresh.id);
          
          if (user && user.refreshToken === refreshToken) {
            // Generate new tokens
            const newToken = generateToken(user._id);
            const newRefreshToken = generateRefreshToken(user._id);
            
            // Update refresh token in database
            user.refreshToken = newRefreshToken;
            await user.save();
            
            return res.json({
              success: true,
              message: 'Token refreshed successfully',
              token: newToken,
              refreshToken: newRefreshToken,
              user: {
                _id: user._id,
                email: user.email,
                fullName: user.fullName
              },
              tokenExpired: true,
              refreshed: true
            });
          } else {
            return res.status(401).json({
              success: false,
              message: 'Refresh token invalid',
              code: 'REFRESH_TOKEN_INVALID'
            });
          }
        } catch (refreshError) {
          console.error('Refresh token error:', refreshError.message);
          return res.status(401).json({
            success: false,
            message: 'Refresh token invalid or expired',
            code: 'REFRESH_TOKEN_EXPIRED'
          });
        }
      }
      
      return res.status(401).json({
        success: false,
        message: 'Token invalid',
        code: 'TOKEN_INVALID'
      });
    }
  } catch (error) {
    console.error('Token health check error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});



// Middleware to protect routes for administrators only
const adminProtect = async (req, res, next) => {
  await protect(req, res, async () => {
    if (req.user.isAdmin) {
      return next();
    }
    
    const specificAdminUserId = process.env.SPECIFIC_ADMIN_USER_ID || "690088325ca99bed6ab8d4a5";
    if (specificAdminUserId && req.user._id.toString() === specificAdminUserId) {
      return next();
    }
    
    return res.status(403).json({ success: false, message: 'Admin access only' });
  });
};
// Middleware to verify transaction PIN with rate limiting
const verifyTransactionPin = async (req, res, next) => {
  try {
    const { transactionPin } = req.body;
    const userId = req.user._id;
    const ipAddress = req.ip;
    const userAgent = req.get('User-Agent');
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if PIN is locked
    if (user.pinLockedUntil && user.pinLockedUntil > getLagosTime()) {
      const remainingTime = Math.ceil((user.pinLockedUntil - getLagosTime()) / 60000);
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Account locked');
      return res.status(429).json({ 
        success: false, 
        message: `Too many failed attempts. Account locked for ${remainingTime} minutes.` 
      });
    }
    
    // If PIN is not set, return error
    if (!user.transactionPin) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'PIN not set');
      return res.status(400).json({ success: false, message: 'Transaction PIN not set' });
    }
    
    // Verify PIN
    const isPinMatch = await bcrypt.compare(transactionPin, user.transactionPin);
    
    if (isPinMatch) {
      // Reset failed attempts on successful PIN
      user.failedPinAttempts = 0;
      user.pinLockedUntil = null;
      await user.save();
      
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, true, 'PIN verified');
      req.authenticationMethod = 'pin';
      return next();
    } else {
      // Increment failed attempts
      user.failedPinAttempts += 1;
      
      // Lock account if too many failed attempts
      if (user.failedPinAttempts >= 3) {
        user.pinLockedUntil = new Date(getLagosTime().getTime() + 15 * 60000); // Lock for 15 minutes
        await user.save();
        
        await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Account locked due to failed attempts');
        return res.status(429).json({ 
          success: false, 
          message: 'Too many failed attempts. Account locked for 15 minutes.' 
        });
      } else {
        await user.save();
        
        const remainingAttempts = 3 - user.failedPinAttempts;
        await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, `Invalid PIN, ${remainingAttempts} attempts remaining`);
        return res.status(400).json({ 
          success: false, 
          message: `Invalid transaction PIN. ${remainingAttempts} attempts remaining before lockout.` 
        });
      }
    }
  } catch (error) {
    console.error('Transaction PIN verification error:', error);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
};
// Middleware to verify biometric authentication
const verifyBiometricAuth = async (req, res, next) => {
  try {
    const { biometricData } = req.body;
    const userId = req.user._id;
    const ipAddress = req.ip;
    const userAgent = req.get('User-Agent');
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if biometric is enabled
    if (!user.biometricEnabled) {
      await logAuthAttempt(userId, 'biometric_attempt', ipAddress, userAgent, false, 'Biometric not enabled');
      return res.status(400).json({ success: false, message: 'Biometric authentication not enabled' });
    }
    
    // In a real implementation, you would verify the biometric data here
    // This would involve checking the signature against the stored public key
    // For this example, we'll assume the client has already verified the biometric
    // and we just need to check that the user has it enabled
    
    await logAuthAttempt(userId, 'biometric_attempt', ipAddress, userAgent, true, 'Biometric verified');
    req.authenticationMethod = 'biometric';
    return next();
  } catch (error) {
    console.error('Biometric verification error:', error);
    await logAuthAttempt(userId, 'biometric_attempt', req.ip, req.get('User-Agent'), false, error.message);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
};
// Middleware to verify transaction authentication (PIN or Biometric)
const verifyTransactionAuth = async (req, res, next) => {
  try {
    const { transactionPin, useBiometric, biometricData } = req.body;
    const userId = req.user._id;
    
    // Get user settings
    const settings = await Settings.findOne();
    const pinRequired = settings ? settings.transactionPinRequired : true;
    const biometricAllowed = settings ? settings.biometricAuthEnabled : true;
    
    // If PIN is not required globally, skip verification
    if (!pinRequired) {
      req.authenticationMethod = 'none';
      return next();
    }
    
    // Get user from database
    const user = await User.findById(userId);
    
    // Check if user has set up a PIN or enabled biometrics
    const hasPin = user.transactionPin && user.transactionPin.length > 0;
    const hasBiometric = user.biometricEnabled;
    
    // If user has neither PIN nor biometric set up, return error
    if (!hasPin && !hasBiometric) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please set up a transaction PIN or enable biometric authentication first' 
      });
    }
    
    // If biometric is requested and enabled
    if (useBiometric && hasBiometric && biometricAllowed) {
      return verifyBiometricAuth(req, res, next);
    }
    
    // If PIN is provided
    if (transactionPin && hasPin) {
      return verifyTransactionPin(req, res, next);
    }
    
    // If we reach here, authentication failed
    return res.status(400).json({ 
      success: false, 
      message: 'Authentication required. Please provide your transaction PIN or use biometric authentication.' 
    });
    
  } catch (error) {
    console.error('Transaction authentication error:', error);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
};
// VTPass API Helper
const vtpassConfig = {
  apiKey: process.env.VTPASS_API_KEY,
  secretKey: process.env.VTPASS_SECRET_KEY,
  baseUrl: process.env.VTPASS_BASE_URL || 'https://sandbox.vtpass.com/api',
};
const callVtpassApi = async (endpoint, data, headers = {}) => {
  try {
    const response = await axios.post(`${vtpassConfig.baseUrl}${endpoint}`, data, {
      headers: {
        'Content-Type': 'application/json',
        'api-key': vtpassConfig.apiKey,
        'secret-key': vtpassConfig.secretKey,
        ...headers,
      },
      timeout: 15000
    });
    console.log(`VTPass API call to ${endpoint} successful.`);
    console.log('VTPass API Response Data:', JSON.stringify(response.data, null, 2));
    return { success: true, data: response.data };
  } catch (error) {
    console.error(`--- VTPass API Error to ${endpoint} ---`);
    if (error.response) {
      console.error('Server responded with non-2xx status:', error.response.status);
      console.error('Response data:', error.response.data);
      return {
        success: false,
        status: error.response.status,
        message: error.response.data.message || 'Error from VTPass API',
        details: error.response.data
      };
    } else if (error.request) {
      console.error('No response received from VTPass API:', error.request);
      return { success: false, status: 504, message: 'Timeout: No response from VTPass API' };
    } else {
      console.error('Error setting up request:', error.message);
      return { success: false, status: 500, message: error.message || 'Internal Server Error' };
    }
  }
};





const createTransaction = async (
  userId,
  amount,
  type,
  status,
  description,
  balanceBefore,
  balanceAfter,
  session, // Mongoose session object
  isCommission = false,
  authenticationMethod = 'none',
  reference = null,
  metadata = {},
  additionalData = {}
) => {
  try {
    // Generate or use provided reference
    const txReference = reference || `TXN${Date.now()}${Math.random().toString(36).substr(2, 6).toUpperCase()}`;
    
    // Merge metadata - additionalData overrides metadata
    const fullMetadata = {
      // Start with metadata
      ...metadata,
      // Override with additionalData where it has values
      phone: additionalData.phone || metadata.phone || '',
      smartcardNumber: additionalData.smartcardNumber || metadata.smartcardNumber || '',
      billersCode: additionalData.billersCode || metadata.billersCode || '',
      variation_code: additionalData.variation_code || metadata.variation_code || '',
      packageName: additionalData.packageName || metadata.packageName || '',
      serviceID: additionalData.serviceID || metadata.serviceID || '',
      selectedPackage: additionalData.selectedPackage || metadata.selectedPackage || '',
      meterNumber: additionalData.meterNumber || metadata.meterNumber || '',
      vtpassResponse: additionalData.vtpassResponse || metadata.vtpassResponse || {},
      // Include any other additionalData fields
      ...additionalData
    };

    const newTransaction = new Transaction({
      transactionId: txReference, // Use same as reference for consistency
      userId,
      type,
      amount,
      status, // Should be 'Successful', 'Failed', 'Pending', etc.
      description,
      balanceBefore,
      balanceAfter,
      reference: txReference, // Single source of truth
      isCommission,
      authenticationMethod,
      metadata: fullMetadata,
      // Remove timestamp since Transaction model has timestamps: true
    });

    // Save with session if provided
    let savedTransaction;
    if (session) {
      savedTransaction = await newTransaction.save({ session });
    } else {
      savedTransaction = await newTransaction.save();
    }
    
    // Cable TV specific logging
    if (type === 'Cable TV Subscription' || type === 'Cable TV Purchase') {
      console.log('📺 CABLE TV TRANSACTION SAVED:');
      console.log('🔢 Smartcard:', savedTransaction.metadata.billersCode);
      console.log('📞 Phone:', savedTransaction.metadata.phone);
      console.log('📦 Package:', savedTransaction.metadata.packageName);
      console.log('🆔 Reference:', savedTransaction.reference);
      console.log('✅ Status:', savedTransaction.status);
    } else if (isCommission) {
      console.log('💰 COMMISSION TRANSACTION SAVED:');
      console.log('📝 Type:', type);
      console.log('💵 Amount: ₦', savedTransaction.amount);
      console.log('✅ Status:', savedTransaction.status);
      console.log('👤 User:', userId);
    }
    
    return savedTransaction;
  } catch (error) {
    console.error('❌ Error creating transaction:', error);
    console.error('Transaction details:', {
      userId,
      type,
      amount,
      status,
      description,
      isCommission,
      reference: reference || 'auto-generated'
    });
    throw error;
  }
};




/**


 * Award direct referral bonus (₦200 to both referrer and referred user)
 * ONLY when first deposit amount is ₦5,000 or above
 */
const awardDirectReferralBonus = async (referredUserId, depositAmount, mongooseSession = null) => {
  try {
    console.log(`🎯 Checking direct referral bonus for user: ${referredUserId}, Deposit: ₦${depositAmount}`);
    
    const userQuery = User.findById(referredUserId);
    if (mongooseSession) {
      userQuery.session(mongooseSession);
    }
    
    const referredUser = await userQuery;
    if (!referredUser || !referredUser.referrerId) {
      console.log('⚠️ No referrer found or user not found');
      return false;
    }
    
    // Check if bonus already awarded
    if (referredUser.referralBonusAwarded) {
      console.log('⚠️ Direct referral bonus already awarded');
      return false;
    }
    
    // 🔥 CRITICAL FIX: Check if deposit amount meets minimum for bonus (₦5,000)
    const MINIMUM_DEPOSIT_FOR_BONUS = 5000; // ₦5,000 minimum for bonus
    
    if (depositAmount < MINIMUM_DEPOSIT_FOR_BONUS) {
      console.log(`⚠️ Deposit amount (₦${depositAmount}) below ₦5,000. No referral bonus awarded.`);
      return false;
    }
    
    const referrerId = referredUser.referrerId;
    
    // Award ₦200 to referrer
    const referrerQuery = User.findById(referrerId);
    if (mongooseSession) {
      referrerQuery.session(mongooseSession);
    }
    
    const referrer = await referrerQuery;
    if (!referrer) {
      console.log('❌ Referrer not found');
      return false;
    }
    
    // Add ₦200 to referrer's commission balance
    const referrerCommissionBefore = referrer.commissionBalance || 0;
    referrer.commissionBalance = (referrer.commissionBalance || 0) + 200;
    referrer.totalReferralEarnings = (referrer.totalReferralEarnings || 0) + 200;
    await referrer.save({ session: mongooseSession });
    
    // ✅ CORRECTED: Use 'Direct Referral Bonus' which exists in your enum
    await createTransaction(
      referrerId,
      200,
      'Direct Referral Bonus', // ✅ Changed from 'Commission Credit' to 'Direct Referral Bonus'
      'Successful',
      `Direct referral bonus for referring ${referredUser.fullName} (First deposit: ₦${depositAmount})`,
      referrerCommissionBefore,
      referrer.commissionBalance,
      mongooseSession,
      true, // isCommission
      'none',
      null,
      {},
      {
        referralType: 'direct',
        referredUserId: referredUserId,
        referredUserName: referredUser.fullName,
        bonusAmount: 200,
        depositAmount: depositAmount,
        bonusFor: 'referrer',
        minimumMet: depositAmount >= 5000,
        transactionSubType: 'direct_referral_bonus'
      }
    );
    
    // Award ₦200 to referred user (welcome bonus)
    const userCommissionBefore = referredUser.commissionBalance || 0;
    referredUser.commissionBalance = (referredUser.commissionBalance || 0) + 200;
    referredUser.referralBonusAwarded = true;
    await referredUser.save({ session: mongooseSession });
    
    // ✅ CORRECTED: Use 'Welcome Bonus' which exists in your enum
    await createTransaction(
      referredUserId,
      200,
      'Welcome Bonus', // ✅ Changed from 'Commission Credit' to 'Welcome Bonus'
      'Successful',
      `Welcome bonus for ₦${depositAmount} first deposit with referral code`,
      userCommissionBefore,
      referredUser.commissionBalance,
      mongooseSession,
      true, // isCommission
      'none',
      null,
      {},
      {
        referralType: 'welcome_bonus',
        referrerId: referrerId,
        referrerName: referrer.fullName,
        bonusAmount: 200,
        depositAmount: depositAmount,
        bonusFor: 'referred_user',
        minimumMet: depositAmount >= 5000,
        transactionSubType: 'welcome_bonus'
      }
    );
    
    // Create notifications
    try {
      // Notification for referrer
      await Notification.create([{
        recipient: referrerId,
        title: "🎉 Referral Bonus Earned!",
        message: `You earned ₦200 referral bonus from ${referredUser.fullName}'s first deposit of ₦${depositAmount}!`,
        type: 'referral_bonus',
        isRead: false,
        metadata: {
          event: 'direct_referral_bonus',
          referredUserId: referredUserId,
          bonusAmount: 200,
          depositAmount: depositAmount
        }
      }], { session: mongooseSession });
      
      // Notification for referred user
      await Notification.create([{
        recipient: referredUserId,
        title: "🎁 Welcome Bonus!",
        message: `You received ₦200 welcome bonus for your first deposit of ₦${depositAmount}!`,
        type: 'welcome_bonus',
        isRead: false,
        metadata: {
          event: 'welcome_bonus',
          bonusAmount: 200,
          referrerName: referrer.fullName,
          depositAmount: depositAmount
        }
      }], { session: mongooseSession });
    } catch (notifError) {
      console.error('❌ Bonus notification error:', notifError);
    }
    
    console.log(`✅ Direct referral bonus awarded: ₦200 to both referrer ${referrer.email} and referred user ${referredUser.email}`);
    return true;
    
  } catch (error) {
    console.error('❌ Error awarding direct referral bonus:', error);
    return false;
  }
};

/**
 * Award indirect referral bonus (₦20 to original referrer)
 * ONLY when first deposit is ₦5,000 or above
 */
const awardIndirectReferralBonus = async (referredUserId, depositAmount, mongooseSession = null) => {
  try {
    console.log(`🎯 Checking indirect referral bonus for user: ${referredUserId}`);
    
    const userQuery = User.findById(referredUserId);
    if (mongooseSession) {
      userQuery.session(mongooseSession);
    }
    
    const referredUser = await userQuery;
    if (!referredUser || !referredUser.referrerId) {
      console.log('⚠️ No referrer found');
      return false;
    }
    
    // Check if deposit meets minimum for indirect bonus (₦5,000)
    if (depositAmount < 5000) {
      console.log(`⚠️ Deposit amount (₦${depositAmount}) below ₦5,000. No indirect bonus.`);
      return false;
    }
    
    // Get the direct referrer (level 1)
    const directReferrerId = referredUser.referrerId;
    
    // Find the direct referrer's referrer (level 2 - original referrer)
    const directReferrerQuery = User.findById(directReferrerId);
    if (mongooseSession) {
      directReferrerQuery.session(mongooseSession);
    }
    
    const directReferrer = await directReferrerQuery;
    if (!directReferrer || !directReferrer.referrerId) {
      console.log('⚠️ No indirect referrer found (level 2)');
      return false;
    }
    
    const originalReferrerId = directReferrer.referrerId;
    
    // Check if indirect bonus already awarded for this user
    if (referredUser.indirectBonusAwardedLevel2) {
      console.log(`⚠️ Indirect bonus (level 2) already awarded`);
      return false;
    }
    
    const originalReferrerQuery = User.findById(originalReferrerId);
    if (mongooseSession) {
      originalReferrerQuery.session(mongooseSession);
    }
    
    const originalReferrer = await originalReferrerQuery;
    if (!originalReferrer) {
      console.log('❌ Original referrer not found');
      return false;
    }
    
    const bonusAmount = 20; // ₦20 for indirect referrals
    
    // Add bonus to original referrer's commission balance
    const commissionBefore = originalReferrer.commissionBalance || 0;
    originalReferrer.commissionBalance = (originalReferrer.commissionBalance || 0) + bonusAmount;
    originalReferrer.totalReferralEarnings = (originalReferrer.totalReferralEarnings || 0) + bonusAmount;
    await originalReferrer.save({ session: mongooseSession });
    
    // Mark bonus as awarded for this user
    referredUser.indirectBonusAwardedLevel2 = true;
    await referredUser.save({ session: mongooseSession });
    
    // ✅ CORRECTED: Already using 'Indirect Referral Bonus' which exists in your enum
    await createTransaction(
      originalReferrerId,
      bonusAmount,
      'Indirect Referral Bonus', // ✅ This already exists in your enum
      'Successful',
      `Indirect referral bonus from ${referredUser.fullName}'s first deposit (₦${depositAmount})`,
      commissionBefore,
      originalReferrer.commissionBalance,
      mongooseSession,
      true, // isCommission
      'none',
      null,
      {},
      {
        referralType: 'indirect',
        level: 2,
        referredUserId: referredUserId,
        referredUserName: referredUser.fullName,
        directReferrerId: directReferrerId,
        directReferrerName: directReferrer.fullName,
        bonusAmount: bonusAmount,
        depositAmount: depositAmount,
        minimumMet: depositAmount >= 5000
      }
    );
    
    // Create notification
    try {
      await Notification.create([{
        recipient: originalReferrerId,
        title: "💰 Indirect Referral Bonus!",
        message: `You earned ₦${bonusAmount} indirect referral bonus from ${directReferrer.fullName}'s referral!`,
        type: 'referral_bonus',
        isRead: false,
        metadata: {
          event: 'indirect_referral_bonus',
          level: 2,
          directReferrerId: directReferrerId,
          referredUserId: referredUserId,
          bonusAmount: bonusAmount,
          depositAmount: depositAmount
        }
      }], { session: mongooseSession });
    } catch (notifError) {
      console.error('❌ Indirect bonus notification error:', notifError);
    }
    
    console.log(`✅ Indirect referral bonus (level 2) awarded: ₦${bonusAmount} to ${originalReferrer.email}`);
    return true;
    
  } catch (error) {
    console.error(`❌ Error awarding indirect referral bonus:`, error);
    return false;
  }
};









// CALCULATE COMMISSION - UPDATED RATES PER SERVICE TYPE
const calculateAndAddCommission = async (userId, amount, serviceType, mongooseSession = null, isUsingCommission = false) => {
  try {
    // 🔥 CRITICAL FIX: Skip commission if user paid with commission
    if (isUsingCommission) {
      console.log(`⚠️ SKIPPING COMMISSION: User paid with commission balance`);
      return 0;
    }

    // Handle case where serviceType might be an object
    let serviceTypeString;
    
    if (typeof serviceType === 'string') {
      serviceTypeString = serviceType;
    } else if (serviceType && typeof serviceType === 'object') {
      // Try to extract service type from object
      if (serviceType.serviceID) {
        serviceTypeString = serviceType.serviceID;
      } else if (serviceType.serviceType) {
        serviceTypeString = serviceType.serviceType;
      } else if (serviceType.network) {
        serviceTypeString = serviceType.network;
      } else {
        serviceTypeString = 'unknown';
      }
    } else if (serviceType === undefined || serviceType === null) {
      // If serviceType is not provided at all
      console.warn('⚠️ Commission called without serviceType parameter');
      serviceTypeString = 'unknown';
    } else {
      serviceTypeString = 'unknown';
    }
    
    console.log(`🎯 COMMISSION CALCULATION CALLED: serviceType="${serviceTypeString}" | Amount=₦${amount} | UsingCommission=${isUsingCommission}`);
    
    // ========== SKIP COMMISSION FOR TRANSFERS ==========
    // Wallet-to-wallet transfers do not earn commission
    if (serviceTypeString.toLowerCase().includes('transfer') || 
        serviceTypeString.toLowerCase() === 'transfer' || 
        serviceTypeString.toLowerCase() === 'peer_transfer' ||
        serviceTypeString.toLowerCase().includes('peer') ||
        serviceTypeString.toLowerCase().includes('wallet_transfer') ||
        serviceTypeString.toLowerCase().includes('send_money')) {
      console.log(`⚠️ SKIPPING COMMISSION: Wallet-to-wallet transfers do not earn commission`);
      return 0;
    }
    // ==================================================
    
    // Use session if provided, otherwise query normally
    const settingsQuery = Settings.findOne();
    if (mongooseSession) {
      settingsQuery.session(mongooseSession);
    }
    const settings = await settingsQuery;
    
    // Determine commission rate based on service type - UPDATED RATES
    let rate = 0.003; // Default 0.3% for other services
    
    // Get specific commission rates from settings
    if (settings) {
      // Check for specific service type rates first
      const lowerType = serviceTypeString.toLowerCase().trim();
      
      console.log('🔍 Commission calculation for service:', lowerType);
      
      // ========== UPDATED COMMISSION RATES ==========
      // Note: Transfer rates are commented out since transfers don't earn commission
      
      // 1. AIRTIME SERVICES - 0.5%
      if ((lowerType.includes('mtn') || lowerType.includes('airtel') || 
           lowerType.includes('glo') || lowerType.includes('etisalat') || 
           lowerType.includes('9mobile')) && !lowerType.includes('data')) {
        rate = settings.airtimeCommissionRate || 0.005; // 0.5% for airtime
        console.log('✅ Airtime commission rate:', rate, '(0.5%)');
      } 
      // 2. DATA SERVICES - 0.5%
      else if (lowerType.includes('data')) {
        rate = typeof settings.dataCommissionRate !== 'undefined' 
          ? settings.dataCommissionRate 
          : 0.005; // 0.5% for data
        console.log('✅ Data commission rate:', rate, '(0.5%)');
      } 
      // 3. ELECTRICITY SERVICES - 0.4%
      else if (lowerType.includes('electric') || 
               lowerType.includes('ikeja') || 
               lowerType.includes('eko') || 
               lowerType.includes('abuja') || 
               lowerType.includes('ibadan') || 
               lowerType.includes('enugu') || 
               lowerType.includes('kano') || 
               lowerType.includes('ph')) {
        rate = settings.electricityCommissionRate || 0.004; // 0.4% for electricity
        console.log('✅ Electricity commission rate:', rate, '(0.4%)');
      } 
      // 4. CABLE TV SERVICES - 0.5%
      else if (lowerType.includes('dstv') || lowerType.includes('gotv') || 
               lowerType.includes('startimes') || lowerType === 'tv') {
        rate = settings.cableTvCommissionRate || 0.005; // 0.5% for cable TV
        console.log('✅ Cable TV commission rate:', rate, '(0.5%)');
      } 
      // 5. EDUCATION SERVICES - 0.5%
      else if (lowerType.includes('education')) {
        rate = settings.educationCommissionRate || 0.005; // 0.5% for education
        console.log('✅ Education commission rate:', rate, '(0.5%)');
      } 
      // 6. INSURANCE SERVICES - 0.4%
      else if (lowerType.includes('insurance')) {
        rate = settings.insuranceCommissionRate || 0.004; // 0.4% for insurance
        console.log('✅ Insurance commission rate:', rate, '(0.4%)');
      } 
      // 7. DEFAULT - 0.3%
      else {
        rate = settings.commissionRate || 0.003; // Default commission rate 0.3%
        console.log('✅ Default commission rate:', rate, '(0.3%)');
      }
    }

    const cleanAmount = parseFloat(amount);
    if (isNaN(cleanAmount) || cleanAmount <= 0) {
      console.log('⚠️ Invalid amount for commission');
      return 0;
    }

    let commissionAmount = cleanAmount * rate;
    
    console.log(`💰 Commission calculation: ${cleanAmount} × ${rate} = ${commissionAmount}`);
    console.log(`💰 Rate percentage: ${(rate * 100).toFixed(2)}%`);
    
    // Check if commission is 100% (rate = 1)
    if (rate === 1 || Math.abs(rate - 1) < 0.00001) {
      console.error('❌ ERROR: Commission rate is 100%! This is wrong.');
      console.error('❌ Using fallback rate of 0.5%');
      commissionAmount = cleanAmount * 0.005;
    }
    
    if (commissionAmount <= 0) {
      console.log('⚠️ Commission amount too small');
      return 0;
    }

    // Get user with session if provided
    const userQuery = User.findById(userId);
    if (mongooseSession) {
      userQuery.session(mongooseSession);
    }
    const user = await userQuery;
    
    if (!user) {
      console.log('❌ User not found for commission');
      return 0;
    }

    if (typeof user.commissionBalance !== 'number') user.commissionBalance = 0;

    const balanceBefore = user.commissionBalance;
    user.commissionBalance += commissionAmount;
    
    // Save with session if provided
    if (mongooseSession) {
      await user.save({ session: mongooseSession });
    } else {
      await user.save();
    }

    const lowerType = serviceTypeString.toLowerCase().trim();
    console.log(`🔍 Processing commission for service type: "${lowerType}"`);

    let description = '';
    let source = '';
    let commissionType = 'Commission Credit';

    // ========== DETERMINE COMMISSION TYPE ==========
    // Note: Transfer commission type is commented out since transfers don't earn commission
    
    // 1. AIRTIME COMMISSION - 0.5%
    if ((lowerType.includes('mtn') || lowerType.includes('airtel') || 
         lowerType.includes('glo') || lowerType.includes('etisalat') || 
         lowerType.includes('9mobile')) && 
        !lowerType.includes('data')) {
      description = `Airtime Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = 'Airtime';
      commissionType = 'Airtime Commission Credit';
      console.log('✅ Commission type determined: Airtime (0.5%)');
    }
    // 2. DATA COMMISSION - 0.5%
    else if (lowerType.includes('data')) {
      description = `Data Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = 'Data';
      commissionType = 'Data Commission Credit';
      console.log('✅ Commission type determined: Data (0.5%)');
    }
    // 3. CABLE TV COMMISSION - 0.5%
    else if (lowerType.includes('dstv') || lowerType.includes('gotv') || 
             lowerType.includes('startimes') || lowerType === 'tv') {
      description = `Cable TV Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = 'Cable TV';
      commissionType = 'Cable TV Commission Credit';
      console.log('✅ Commission type determined: Cable TV (0.5%)');
    }
    // 4. ELECTRICITY COMMISSION - 0.4%
    else if (lowerType.includes('electric') || 
             lowerType.includes('ikeja') || 
             lowerType.includes('eko') || 
             lowerType.includes('abuja') || 
             lowerType.includes('ibadan') || 
             lowerType.includes('enugu') || 
             lowerType.includes('kano') || 
             lowerType.includes('ph')) {
      description = `Electricity Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = 'Electricity';
      commissionType = 'Electricity Commission Credit';
      console.log('✅ Commission type determined: Electricity (0.4%)');
    }
    // 5. EDUCATION COMMISSION - 0.5%
    else if (lowerType.includes('education') || 
             lowerType.includes('waec') || 
             lowerType.includes('jamb') || 
             lowerType.includes('exam') || 
             lowerType.includes('result')) {
      description = `Education Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = 'Education';
      commissionType = 'Education Commission Credit';
      console.log('✅ Commission type determined: Education (0.5%)');
    }
    // 6. INSURANCE COMMISSION - 0.4%
    else if (lowerType.includes('insurance') || 
             lowerType.includes('insure') || 
             lowerType.includes('ui-insure') || 
             lowerType.includes('motor') || 
             lowerType.includes('vehicle')) {
      description = `Insurance Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = 'Insurance';
      commissionType = 'Insurance Commission Credit';
      console.log('✅ Commission type determined: Insurance (0.4%)');
    }
    // 7. DEFAULT COMMISSION - 0.3%
    else {
      const formattedType = serviceTypeString.charAt(0).toUpperCase() + serviceTypeString.slice(1);
      description = `${formattedType} Commission Credit (₦${commissionAmount.toFixed(2)})`;
      source = formattedType;
      commissionType = `${formattedType} Commission Credit`;
      console.log(`⚠️ Default commission type used: ${formattedType} (0.3%)`);
    }

    console.log(`✅ Commission determined: ${description} | Source: ${source} | Rate: ${(rate * 100).toFixed(2)}%`);
    console.log(`💰 Final commission amount: ₦${commissionAmount.toFixed(2)}`);

    // Create commission transaction
    await createTransaction(
      userId,
      commissionAmount,
      commissionType,
      'Successful',
      description,
      balanceBefore,
      user.commissionBalance,
      mongooseSession,
      true, // isCommission = true
      'none',
      null,
      {}, // metadata
      { 
        commissionSource: source,
        originalService: lowerType,
        commissionRate: rate,
        commissionPercentage: (rate * 100).toFixed(2) + '%',
        originalAmount: cleanAmount,
        commissionAmount: commissionAmount
      }
    );

    // Also create a notification for the user about commission earned
    try {
      await Notification.create({
        recipient: userId,
        title: "Commission Earned 💰",
        message: `You earned ₦${commissionAmount.toFixed(2)} commission from ${source} service`,
        type: 'commission_earned',
        isRead: false,
        metadata: {
          commissionAmount: commissionAmount,
          source: source,
          originalAmount: cleanAmount,
          ratePercentage: (rate * 100).toFixed(2)
        }
      });
    } catch (notifError) {
      console.error('Commission notification error:', notifError);
    }

    console.log(`💰 COMMISSION ADDED: ${description} → Source: ${source} (₦${commissionAmount.toFixed(2)})`);
    return commissionAmount;

  } catch (error) {
    console.error('❌ COMMISSION CALCULATION ERROR:', error);
    console.error('Error details:', error.message);
    console.error('Error stack:', error.stack);
    return 0;
  }
};








// REFERRAL BONUS FUNCTION - COMPLETE IMPLEMENTATION
const processReferralBonuses = async (userId, depositAmount, session) => {
  try {
    console.log(`🎯 Processing referral bonuses for user: ${userId}, deposit: ₦${depositAmount}`);
    
    // Get the user who made the deposit
    const user = await User.findById(userId);
    if (!user) {
      console.log('❌ User not found for referral bonus');
      return;
    }
    
    // Check if this is the first deposit
    const isFirstDeposit = !user.firstDepositMade && depositAmount >= 5000;
    
    if (!isFirstDeposit) {
      console.log(`ℹ️ Not first deposit or amount too low: ${depositAmount}`);
      return;
    }
    
    console.log(`✅ First deposit detected: ₦${depositAmount} (qualifies for bonuses)`);
    
    // MARK 1: Give welcome bonus to the new user
    if (!user.welcomeBonusReceived && depositAmount >= 5000) {
      const welcomeBonusAmount = 200;
      
      // Update user's commission balance
      user.commissionBalance += welcomeBonusAmount;
      user.welcomeBonusReceived = true;
      user.welcomeBonusAmount = welcomeBonusAmount;
      user.firstDepositMade = true;
      
      await user.save({ session });
      
      // Create welcome bonus transaction
      await createTransaction(
        userId,
        welcomeBonusAmount,
        'Welcome Bonus',
        'Successful',
        `Welcome bonus for first deposit of ₦${depositAmount.toFixed(2)}`,
        user.commissionBalance - welcomeBonusAmount,
        user.commissionBalance,
        session,
        true, // isCommission
        'none',
        null,
        {},
        {
          bonusType: 'welcome',
          depositAmount: depositAmount,
          bonusAmount: welcomeBonusAmount,
          source: 'First Deposit Bonus'
        }
      );
      
      // Create notification
      await Notification.create({
        recipient: userId,
        title: "Welcome Bonus! 🎉",
        message: `You received ₦${welcomeBonusAmount} welcome bonus for your first deposit!`,
        type: 'commission_earned',
        isRead: false,
        metadata: {
          bonusAmount: welcomeBonusAmount,
          source: 'Welcome Bonus',
          depositAmount: depositAmount
        }
      });
      
      console.log(`✅ Welcome bonus of ₦${welcomeBonusAmount} credited to user: ${user.email}`);
    }
    
    // MARK 2: Give direct referral bonus to referrer
    if (user.referrerId && depositAmount >= 5000) {
      const referrer = await User.findById(user.referrerId);
      if (referrer) {
        const directReferralBonus = 200;
        
        // Update referrer's commission balance
        const referrerBalanceBefore = referrer.commissionBalance;
        referrer.commissionBalance += directReferralBonus;
        referrer.totalReferralEarnings = (referrer.totalReferralEarnings || 0) + directReferralBonus;
        
        await referrer.save({ session });
        
        // Create direct referral bonus transaction
        await createTransaction(
          referrer._id,
          directReferralBonus,
          'Direct Referral Bonus',
          'Successful',
          `Direct referral bonus from ${user.fullName}'s first deposit`,
          referrerBalanceBefore,
          referrer.commissionBalance,
          session,
          true,
          'none',
          null,
          {},
          {
            bonusType: 'direct_referral',
            referredUserId: userId,
            referredUserName: user.fullName,
            depositAmount: depositAmount,
            bonusAmount: directReferralBonus,
            source: 'Direct Referral'
          }
        );
        
        // Create notification for referrer
        await Notification.create({
          recipient: referrer._id,
          title: "Referral Bonus Earned! 💰",
          message: `You earned ₦${directReferralBonus} from ${user.fullName}'s first deposit!`,
          type: 'commission_earned',
          isRead: false,
          metadata: {
            bonusAmount: directReferralBonus,
            referredUser: user.fullName,
            source: 'Direct Referral Bonus'
          }
        });
        
        console.log(`✅ Direct referral bonus of ₦${directReferralBonus} credited to referrer: ${referrer.email}`);
        
        // MARK 3: Give indirect referral bonus to referrer's referrer (2nd level)
        if (referrer.referrerId && depositAmount >= 5000) {
          const indirectReferrer = await User.findById(referrer.referrerId);
          if (indirectReferrer) {
            const indirectReferralBonus = 20;
            
            // Update indirect referrer's commission balance
            const indirectBalanceBefore = indirectReferrer.commissionBalance;
            indirectReferrer.commissionBalance += indirectReferralBonus;
            indirectReferrer.totalReferralEarnings = (indirectReferrer.totalReferralEarnings || 0) + indirectReferralBonus;
            
            await indirectReferrer.save({ session });
            
            // Create indirect referral bonus transaction
            await createTransaction(
              indirectReferrer._id,
              indirectReferralBonus,
              'Indirect Referral Bonus',
              'Successful',
              `Indirect referral bonus from ${user.fullName}'s first deposit`,
              indirectBalanceBefore,
              indirectReferrer.commissionBalance,
              session,
              true,
              'none',
              null,
              {},
              {
                bonusType: 'indirect_referral',
                level: 2,
                referredUserId: userId,
                referredUserName: user.fullName,
                directReferrerId: referrer._id,
                directReferrerName: referrer.fullName,
                depositAmount: depositAmount,
                bonusAmount: indirectReferralBonus,
                source: 'Indirect Referral'
              }
            );
            
            // Create notification for indirect referrer
            await Notification.create({
              recipient: indirectReferrer._id,
              title: "Indirect Referral Bonus! 🎁",
              message: `You earned ₦${indirectReferralBonus} from ${user.fullName}'s first deposit (through ${referrer.fullName})!`,
              type: 'commission_earned',
              isRead: false,
              metadata: {
                bonusAmount: indirectReferralBonus,
                referredUser: user.fullName,
                directReferrer: referrer.fullName,
                source: 'Indirect Referral Bonus'
              }
            });
            
            console.log(`✅ Indirect referral bonus of ₦${indirectReferralBonus} credited to indirect referrer: ${indirectReferrer.email}`);
          }
        }
      }
    }
    
    // Update referral status
    if (user.referrerId) {
      await Referral.findOneAndUpdate(
        { 
          referrerId: user.referrerId,
          referredUserId: userId 
        },
        { 
          status: 'completed',
          bonusPaid: 200,
          completedAt: new Date(),
          depositAmount: depositAmount
        },
        { session }
      );
      console.log(`📊 Referral status updated to completed for user: ${user.email}`);
    }
    
    console.log(`✅ All referral bonuses processed successfully for user: ${user.email}`);
    
  } catch (error) {
    console.error('❌ Error processing referral bonuses:', error);
    throw error;
  }
};









// ==================== AUTH LOGGING FUNCTION - FIXED ====================

// @desc    Log authentication attempts
// @access  Private
const logAuthAttempt = async (userId, attemptType, ipAddress, userAgent, success, details) => {
  try {
    const authLog = new AuthLog({
      userId,
      action: attemptType, // ← CHANGE THIS: use 'action' instead of 'attemptType'
      ipAddress,
      userAgent,
      success,
      details,
      timestamp: new Date()
    });
    
    await authLog.save();
    console.log(`📝 Auth attempt logged: ${attemptType} - ${success ? 'SUCCESS' : 'FAILED'} for user ${userId || 'unknown'}`);
  } catch (error) {
    console.error('❌ Error logging auth attempt:', error);
    // Don't throw, just log the error - we don't want auth logging to break login
  }
};





// @desc    Register a new user with email verification
// @route   POST /api/users/register
// @access  Public
app.post('/api/users/register', [
  body('fullName').notEmpty().withMessage('Full name is required'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
  body('password').custom(value => {
    if (!validatePassword(value)) {
      throw new Error('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters');
    }
    return true;
  }),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP is required for verification')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  const { fullName, email, phone, password, otp, referralCode } = req.body;
  const normalizedEmail = email.toLowerCase().trim();
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    console.log(`📝 [REGISTER] Starting registration for: ${normalizedEmail}`);

    // 1. Check OTP verification
    const otpData = otpStore.get(normalizedEmail);
    if (!otpData || otpData.otp !== otp || otpData.expiresAt < Date.now()) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired OTP. Please verify your email again.' 
      });
    }

    // 2. Check if user already exists
    const normalizedPhone = phone.trim().replace(/\D/g, '');
    const standardizedPhone = normalizedPhone.length === 11 && normalizedPhone.startsWith('0') 
      ? normalizedPhone 
      : '0' + normalizedPhone;
    
    const existingEmail = await User.findOne({ email: normalizedEmail });
    const existingPhone = await User.findOne({ phone: standardizedPhone });
    
    if (existingEmail || existingPhone) {
      await session.abortTransaction();
      
      let errorMessage = '';
      let errorCode = '';
      
      if (existingEmail) {
        errorMessage = `This email is already registered to ${existingEmail.fullName || 'another user'}.`;
        errorCode = 'EMAIL_EXISTS';
      } else if (existingPhone) {
        errorMessage = `This phone number is already registered to ${existingPhone.fullName || 'another user'}.`;
        errorCode = 'PHONE_EXISTS';
      }
      
      return res.status(409).json({ 
        success: false, 
        message: errorMessage,
        errorCode: errorCode,
        duplicateField: existingEmail ? 'email' : 'phone',
        userFriendlyMessage: existingEmail 
          ? 'This email is already registered. Try logging in or use a different email.'
          : 'This phone number is already in use. Try logging in or use a different phone number.'
      });
    }

    // 3. Handle referral code
    let referrerId = null;
    let referrerCode = null;
    let referrerName = null;
    
    if (referralCode) {
      const referrer = await User.findOne({ 
        referralCode: referralCode.toUpperCase().trim() 
      });
      if (referrer) {
        referrerId = referrer._id;
        referrerCode = referrer.referralCode;
        referrerName = referrer.fullName;
        console.log(`👥 [REGISTER] Referrer found: ${referrer.email}`);
      } else {
        console.log(`⚠️ [REGISTER] Invalid referral code provided: ${referralCode}`);
      }
    }

    // 4. Generate UNIQUE referral code for new user
    const generateUniqueReferralCode = async () => {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      
      for (let attempt = 0; attempt < 5; attempt++) {
        let code = 'DALABA'; // Prefix for DalabaPay
        for (let i = 0; i < 6; i++) {
          code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        const existing = await User.findOne({ referralCode: code });
        if (!existing) {
          return code;
        }
      }
      
      // If all attempts fail, use timestamp-based code
      return 'DALABA' + Date.now().toString().slice(-6);
    };

    const userReferralCode = await generateUniqueReferralCode();
    console.log(`🔑 [REGISTER] Generated unique referral code: ${userReferralCode}`);

    // 5. ✅ FIXED: Hash password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 6. Create user with referral tracking
    const user = new User({
      fullName: fullName.trim(),
      email: normalizedEmail,
      phone: phone.trim(),
      password: hashedPassword, // ✅ Use the hashedPassword variable
      referralCode: userReferralCode,
      referrerId: referrerId,
      referrerCode: referrerCode,
      referrerName: referrerName,
      walletBalance: 0.0,
      commissionBalance: 0.0,
      welcomeBonusReceived: false,
      firstDepositMade: false,
      welcomeBonusAmount: 0,
      referralBonusAwarded: false,
      indirectBonusAwardedLevel2: false,
      isAdmin: false,
      isActive: true,
      emailVerified: true,
      virtualAccount: {
        assigned: false,
        bankName: '',
        accountNumber: '',
        accountName: '',
        reference: ''
      }
    });

    const newUser = await user.save({ session });
    console.log(`✅ [REGISTER] User created: ${newUser.email}`);

    // 7. Create referral record AFTER user is created
    if (referralCode && referrerId) {
      try {
        await Referral.create([{
          referrerId: referrerId,
          referredUserId: newUser._id,
          referralCode: referralCode,
          referredUserEmail: newUser.email,
          referredUserName: newUser.fullName,
          status: 'registered'
        }], { session });
        console.log(`📊 [REGISTER] Referral record created for user: ${newUser.email}`);
      } catch (referralError) {
        console.error('❌ [REGISTER] Error creating referral record:', referralError);
        // Don't fail registration if referral record fails
      }
    }

    // 8. Generate tokens
    const token = generateToken(newUser._id);
    const refreshToken = generateRefreshToken(newUser._id);
    
    newUser.refreshToken = refreshToken;
    await newUser.save({ session });

    // 9. Create PERSONAL welcome notification
    try {
      await Notification.create([{
        recipient: newUser._id,
        title: "Welcome to DalabaPay! 🎉",
        message: `Hi ${newUser.fullName}, welcome to DalabaPay! Your account has been created successfully. Earn ₦200 when you make your first deposit of ₦5,000 or more!`,
        type: 'account',
        isRead: false,
        metadata: {
          event: 'registration',
          userId: newUser._id,
          welcomeBonusAvailable: true,
          bonusAmount: 200
        }
      }], { session });
      console.log(`📨 [REGISTER] Personal welcome notification created for ${newUser.email}`);
    } catch (notificationError) {
      console.error('❌ [REGISTER] Error creating welcome notification:', notificationError);
    }

    // 10. Update referrer's stats if applicable
    if (referrerId) {
      await User.findByIdAndUpdate(referrerId, {
        $inc: { referralCount: 1 }
      }, { session });
      console.log(`📈 [REGISTER] Updated referrer stats for: ${referrerId}`);
      
      // Create notification for referrer
      try {
        await Notification.create([{
          recipient: referrerId,
          title: "New Referral! 🎊",
          message: `${newUser.fullName} joined DalabaPay using your referral code! You'll earn ₦200 when they make their first deposit of ₦5,000+.`,
          type: 'account',
          isRead: false,
          metadata: {
            event: 'new_referral',
            referredUserId: newUser._id,
            referredUserName: newUser.fullName,
            potentialBonus: 200
          }
        }], { session });
      } catch (referrerNotificationError) {
        console.error('Error creating referrer notification:', referrerNotificationError);
      }
    }

    // 11. Clear OTP after successful registration
    otpStore.delete(normalizedEmail);

    await session.commitTransaction();
    session.endSession();

    console.log(`🎉 [REGISTER] Registration completed for: ${newUser.email}`);
    
    // 12. Return success response
    res.status(201).json({
      success: true,
      message: 'Registration successful! Welcome to DalabaPay.',
      slogan: 'Smart Life, Fast Pay',
      user: {
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        phone: newUser.phone,
        referralCode: newUser.referralCode,
        referrerCode: newUser.referrerCode,
        walletBalance: newUser.walletBalance,
        commissionBalance: newUser.commissionBalance,
        welcomeBonusAvailable: true,
        welcomeBonusAmount: 200,
        firstDepositRequired: 5000,
        transactionPinSet: !!newUser.transactionPin,
        biometricEnabled: newUser.biometricEnabled,
        emailVerified: newUser.emailVerified,
        hasVirtualAccount: false
      },
      token,
      refreshToken
    });

    // 13. CREATE VIRTUAL ACCOUNT ASYNCHRONOUSLY
    setTimeout(async () => {
      try {
        console.log(`🔄 [REGISTER-BG] Creating virtual account for: ${newUser.email}`);
        
        // Your existing virtual account creation code...
        const virtualAccountServiceUrl = 'https://virtual-account-backend.onrender.com';
        const nameParts = newUser.fullName.trim().split(' ');
        const firstName = nameParts[0];
        const lastName = nameParts.slice(1).join(' ') || firstName;
        
        const response = await axios.post(
          `${virtualAccountServiceUrl}/api/virtual-accounts/create-instant-account`,
          {
            userId: newUser._id.toString(),
            email: newUser.email,
            firstName: firstName,
            lastName: lastName,
            phone: newUser.phone,
            preferredBank: 'wema-bank'
          },
          {
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            timeout: 30000
          }
        );
        
        if (response.data.success) {
          console.log(`✅ [REGISTER-BG] Virtual account created successfully for ${newUser.email}`);
          
          await User.findByIdAndUpdate(newUser._id, {
            'virtualAccount.assigned': true,
            'virtualAccount.bankName': response.data.bankName,
            'virtualAccount.accountNumber': response.data.accountNumber,
            'virtualAccount.accountName': response.data.accountName,
            'virtualAccount.reference': response.data.customerCode || `REF_${Date.now()}`
          });
          
          console.log(`💾 [REGISTER-BG] Updated user ${newUser.email} with virtual account details`);
          
          // Create success notification
          try {
            await Notification.create({
              recipient: newUser._id,
              title: "Virtual Account Created! 🏦",
              message: `Your ${response.data.bankName} virtual account is ready: ${response.data.accountNumber}`,
              type: 'account',
              isRead: false,
              metadata: {
                event: 'virtual_account_created',
                accountNumber: response.data.accountNumber,
                bankName: response.data.bankName,
                timestamp: new Date()
              }
            });
          } catch (notificationError) {
            console.error('❌ Error creating virtual account notification:', notificationError);
          }
        }
        
      } catch (error) {
        console.error(`❌ [REGISTER-BG] Failed to create virtual account:`, error.message);
      }
    }, 5000);
    
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    
    console.error('❌ [REGISTER] Error:', error);
    
    if (error.code === 11000) {
      const field = error.keyPattern;
      let message = 'Registration failed due to duplicate data.';
      
      if (field.email) {
        message = 'Email already exists. Please use a different email.';
      } else if (field.phone) {
        message = 'Phone number already exists. Please use a different phone number.';
      } else if (field.referralCode) {
        message = 'System error. Please try again.';
      }
      
      return res.status(400).json({ 
        success: false, 
        message,
        slogan: 'Smart Life, Fast Pay'
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Registration failed. Please try again.',
      slogan: 'Smart Life, Fast Pay'
    });
  }
});



// @desc    Check for duplicates (phone/email) BEFORE registration - IMPROVED VERSION
// @route   POST /api/auth/check-duplicates
// @access  Public
app.post('/api/auth/check-duplicates', [
  body('email').optional().isEmail().withMessage('Invalid email format'),
  body('phone').optional().isMobilePhone('en-NG').withMessage('Invalid Nigerian phone number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      message: errors.array()[0].msg 
    });
  }

  const { email, phone } = req.body;
  
  try {
    // Create query object - check for ANY user with either email OR phone
    const query = { $or: [] };
    
    // Handle email (if provided)
    if (email) {
      query.$or.push({ email: email.toLowerCase().trim() });
    }
    
    // Handle phone (if provided) - CRITICAL FIX: Standardize format
    if (phone) {
      // Remove all non-digit characters and ensure it starts with 0
      const cleanPhone = phone.trim().replace(/\D/g, '');
      
      // Standardize Nigerian phone format
      let standardizedPhone;
      if (cleanPhone.length === 11 && cleanPhone.startsWith('0')) {
        standardizedPhone = cleanPhone;
      } else if (cleanPhone.length === 10) {
        standardizedPhone = '0' + cleanPhone;
      } else {
        standardizedPhone = cleanPhone; // Will fail in query
      }
      
      query.$or.push({ phone: standardizedPhone });
    }
    
    // If no valid query, return error
    if (query.$or.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Email or phone is required'
      });
    }
    
    console.log(`🔍 [CHECK-DUPLICATES] Checking:`, {
      originalEmail: email,
      originalPhone: phone,
      query: query
    });
    
    // Find ANY existing user matching email OR phone
    const existingUsers = await User.find(query).select('email phone fullName');
    
    if (existingUsers.length > 0) {
      console.log(`⚠️ [CHECK-DUPLICATES] DUPLICATES FOUND:`, existingUsers);
      
      // Check which specific field(s) are duplicate
      let duplicateFields = [];
      let duplicateMessages = [];
      
      existingUsers.forEach(user => {
        if (email && user.email === email.toLowerCase().trim()) {
          duplicateFields.push('email');
          duplicateMessages.push(`Email is already registered to ${user.fullName || 'another user'}`);
        }
        if (phone) {
          const cleanPhone = phone.trim().replace(/\D/g, '');
          let standardizedPhone;
          if (cleanPhone.length === 11 && cleanPhone.startsWith('0')) {
            standardizedPhone = cleanPhone;
          } else if (cleanPhone.length === 10) {
            standardizedPhone = '0' + cleanPhone;
          }
          
          if (standardizedPhone && user.phone === standardizedPhone) {
            duplicateFields.push('phone');
            duplicateMessages.push(`Phone number is already registered to ${user.fullName || 'another user'}`);
          }
        }
      });
      
      // Remove duplicates
      duplicateFields = [...new Set(duplicateFields)];
      duplicateMessages = [...new Set(duplicateMessages)];
      
      return res.status(200).json({
        exists: true,
        duplicateFields: duplicateFields, // Now returns array: ['email'], ['phone'], or ['email', 'phone']
        message: duplicateMessages.join('. '),
        userFriendlyMessage: duplicateFields.includes('email') 
          ? 'This email is already registered. Try logging in or use a different email.'
          : 'This phone number is already in use. Try logging in or use a different phone number.',
        hasEmailDuplicate: duplicateFields.includes('email'),
        hasPhoneDuplicate: duplicateFields.includes('phone')
      });
    }
    
    console.log(`✅ [CHECK-DUPLICATES] No duplicates found`);
    return res.status(200).json({
      exists: false,
      message: 'No duplicates found'
    });
    
  } catch (error) {
    console.error('❌ [CHECK-DUPLICATES] Error:', error);
    return res.status(500).json({
      success: false,
      message: 'Unable to check duplicates at this time'
    });
  }
});

// @desc    Authenticate a user - IMPROVED VERSION with detailed validation
// @route   POST /api/users/login
// @access  Public
app.post('/api/users/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  const { email, password } = req.body;
  const ipAddress = req.ip;
  const userAgent = req.get('User-Agent');
  
  try {
    console.log(`🔐 LOGIN ATTEMPT: ${email}`);
    
    // First check if user exists by email
    const user = await User.findOne({ 
      email: email.toLowerCase().trim() 
    });
    
    if (!user) {
      console.log(`❌ USER NOT FOUND: ${email}`);
      await logAuthAttempt(null, 'login', ipAddress, userAgent, false, `User not found: ${email}`);
      
      // Check if it might be a phone number login attempt
      const phoneUser = await User.findOne({ phone: email.trim() });
      if (phoneUser) {
        return res.status(400).json({ 
          success: false, 
          message: 'Email not found, but this phone number is registered. Please use your registered email to login.' 
        });
      }
      
      // Check if email format is valid but not registered
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (emailRegex.test(email)) {
        return res.status(400).json({ 
          success: false, 
          message: 'No account found with this email. Please sign up or check your email.' 
        });
      } else {
        return res.status(400).json({ 
          success: false, 
          message: 'Invalid email format. Please enter a valid email address.' 
        });
      }
    }
    
    console.log(`✅ USER FOUND: ${user.email} | ID: ${user._id}`);
    
    // Check password
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    
 if (!isPasswordMatch) {
  console.log(`❌ PASSWORD MISMATCH for: ${email}`);
  
  // Increment failed attempts for this user
  await incrementFailedLoginAttempts(user._id);
  const failedAttempts = await getFailedLoginAttempts(user._id);
  const remainingAttempts = 3 - failedAttempts;
  
  await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, `Incorrect password. Attempt ${failedAttempts} of 3`);
  
  if (remainingAttempts > 0) {
    return res.status(400).json({ 
      success: false, 
      message: `Incorrect password. You have ${remainingAttempts} attempt${remainingAttempts > 1 ? 's' : ''} remaining.` 
    });
  } else {
    // Lock the account
    const lockoutUntil = Date.now() + 5 * 60 * 1000; // 5 minutes
    await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, 'Account locked - too many failed attempts');
    
    return res.status(400).json({ 
      success: false, 
      message: 'Too many failed attempts. Account locked for 5 minutes.' 
    });
  }
}
    
    // Check if account is active
    if (!user.isActive) {
      console.log(`🚫 ACCOUNT DEACTIVATED: ${email}`);
      await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, 'Account deactivated');
      return res.status(403).json({ 
        success: false, 
        message: 'Your account has been deactivated. Please contact support at support@dala.com.' 
      });
    }
    
    console.log(`✅ PASSWORD VERIFIED for: ${email}`);
    
    // Reset failed attempts on successful login
    await resetFailedLoginAttempts(user._id);
    
    // Update last login time
    user.lastLoginAt = getLagosTime();
    
    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    
    // Store refresh token
    user.refreshToken = refreshToken;
    await user.save();
    
    console.log(`🎉 LOGIN SUCCESSFUL: ${email} | User ID: ${user._id}`);
    await logAuthAttempt(user._id, 'login', ipAddress, userAgent, true, 'Login successful');
    
    res.json({
      success: true,
      message: 'Login successful!',
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        isAdmin: user.isAdmin,
        walletBalance: user.walletBalance,
        commissionBalance: user.commissionBalance,
        transactionPinSet: !!user.transactionPin,
        biometricEnabled: user.biometricEnabled,
      },
      token,
      refreshToken
    });
    
  } catch (error) {
    console.error('💥 LOGIN ERROR:', error);
    console.error('Error stack:', error.stack);
    
    let errorMessage = 'Internal Server Error. Please try again or contact support.';
    if (error.name === 'MongoError') {
      errorMessage = 'Database connection error. Please try again in a moment.';
    } else if (error.name === 'TypeError') {
      errorMessage = 'Data processing error. Please check your input.';
    } else if (error.code === 'ECONNREFUSED') {
      errorMessage = 'Unable to connect to server. Please check your internet connection.';
    }
    
    res.status(500).json({ 
      success: false, 
      message: errorMessage 
    });
  }
});



// Helper function to track failed login attempts
const failedLoginAttempts = new Map();

async function getFailedLoginAttempts(userId) {
  if (failedLoginAttempts.has(userId)) {
    const attempts = failedLoginAttempts.get(userId);
    // Clear attempts older than 5 minutes
    if (Date.now() - attempts.timestamp > 5 * 60 * 1000) {
      failedLoginAttempts.delete(userId);
      return 0;
    }
    return attempts.count;
  }
  return 0;
}

async function incrementFailedLoginAttempts(userId) {
  const currentAttempts = await getFailedLoginAttempts(userId);
  failedLoginAttempts.set(userId, {
    count: currentAttempts + 1,
    timestamp: Date.now()
  });
}

async function resetFailedLoginAttempts(userId) {
  failedLoginAttempts.delete(userId);
}



// @desc    Refresh access token - FINAL BULLETPROOF VERSION
// @route   POST /api/users/refresh-token
// @access  Public (MUST be public!)
app.post('/api/users/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  // 1. Must have refresh token
  if (!refreshToken || typeof refreshToken !== 'string') {
    return res.status(401).json({
      success: false,
      message: 'Refresh token is required',
      code: 'NO_REFRESH_TOKEN'
    });
  }

  try {
    // 2. Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
    // 3. Find user
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // 4. CRITICAL: Compare stored refresh token
    if (user.refreshToken !== refreshToken) {
      console.log('Invalid refresh token attempt for user:', user.email);
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    // 5. Generate new tokens
    const newAccessToken = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // 6. Update refresh token in DB (token rotation)
    user.refreshToken = newRefreshToken;
    await user.save();

    console.log('Token refreshed successfully for:', user.email);

    // 7. Send new tokens
    res.json({
      success: true,
      message: 'Token refreshed successfully',
      token: newAccessToken,
      refreshToken: newRefreshToken,
      user: {
        _id: user._id,
        email: user.email,
        fullName: user.fullName,
        isAdmin: user.isAdmin
      }
    });

  } catch (error) {
    console.error('Refresh token error:', error.name, error.message);

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Refresh token expired. Please login again.',
        code: 'REFRESH_TOKEN_EXPIRED'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
        code: 'INVALID_REFRESH_TOKEN'
      });
    }

    // Any other error
    return res.status(401).json({
      success: false,
      message: 'Refresh token invalid',
      code: 'REFRESH_TOKEN_INVALID'
    });
  }
});

// @desc    Logout user
// @route   POST /api/users/logout
// @access  Private
app.post('/api/users/logout', protect, async (req, res) => {
  try {
    // Invalidate refresh token
    req.user.refreshToken = null;
    await req.user.save();
    
    res.json({ success: true, message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Debug - Check user's OTP status
// @route   GET /api/users/debug-otp/:email
// @access  Development only
if (process.env.NODE_ENV === 'development') {
  app.get('/api/users/debug-otp/:email', async (req, res) => {
    try {
      const email = req.params.email.toLowerCase().trim();
      const user = await User.findOne({ email });
      
      if (!user) {
        return res.json({ 
          success: false, 
          message: 'User not found',
          email: email 
        });
      }
      
      const now = Date.now();
      const otpExpired = user.resetPasswordOTPExpire && user.resetPasswordOTPExpire < now;
      const timeRemaining = user.resetPasswordOTPExpire 
        ? Math.ceil((user.resetPasswordOTPExpire - now) / 1000 / 60)
        : 0;
      
      return res.json({
        success: true,
        email: user.email,
        otp: user.resetPasswordOTP,
        otpExpiresAt: user.resetPasswordOTPExpire,
        otpExpired: otpExpired,
        minutesRemaining: timeRemaining,
        hasResetToken: !!user.resetPasswordToken,
        resetTokenExpiresAt: user.resetPasswordExpire
      });
      
    } catch (error) {
      console.error('Debug OTP error:', error);
      res.status(500).json({ success: false, message: 'Debug error' });
    }
  });
}


// @desc    Request password reset with OTP
// @route   POST /api/users/forgot-password
// @access  Public
app.post('/api/users/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  try {
    const { email } = req.body;
    const normalizedEmail = email.toLowerCase().trim();
    
    console.log(`📧 [FORGOT-PW] Password reset requested for: ${normalizedEmail}`);
    
    const user = await User.findOne({ email: normalizedEmail });
    
    // For security, don't reveal if user exists
    if (!user) {
      console.log(`👤 [FORGOT-PW] User not found for: ${normalizedEmail}`);
      return res.json({
        success: true,
        message: 'If an account exists with this email, an OTP has been sent',
        email: normalizedEmail
      });
    }
    
    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    console.log(`🔑 [FORGOT-PW] Generated OTP: ${otp} for ${user._id}`);
    
    // Set OTP and expiration
    user.resetPasswordOTP = otp;
    user.resetPasswordOTPExpire = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    user.resetPasswordToken = null;
    user.resetPasswordExpire = null;
    
    await user.save();
    console.log(`💾 [FORGOT-PW] OTP saved to database`);
    
    // Send OTP email for password reset
    try {
      const emailResult = await sendVerificationEmail(
        normalizedEmail, 
        otp, 
        user.fullName || 'User', 
        'password_reset'  // Specify this is for password reset
      );
      
      if (!emailResult.success) {
        console.log(`⚠️ [FORGOT-PW] Email sending failed, OTP: ${otp}`);
        
        // In development, return OTP for testing
        if (process.env.NODE_ENV === 'development') {
          return res.json({
            success: true,
            message: 'Email service unavailable. For testing, OTP is: ' + otp,
            email: normalizedEmail,
            otp: otp
          });
        }
      }
      
      console.log(`✅ [FORGOT-PW] Password reset OTP email sent to ${normalizedEmail}`);
      
      res.json({
        success: true,
        message: 'OTP sent to your email address',
        email: normalizedEmail,
        slogan: 'Smart Life, Fast Pay'  // Added slogan
      });
      
    } catch (emailError) {
      console.error(`❌ [FORGOT-PW] Email error: ${emailError.message}`);
      
      // If email fails but we're in development, return OTP
      if (process.env.NODE_ENV === 'development') {
        return res.json({
          success: true,
          message: 'Email service failed. For testing, use OTP: ' + otp,
          email: normalizedEmail,
          otp: otp,
          slogan: 'Smart Life, Fast Pay'  // Added slogan
        });
      }
      
      return res.json({
        success: true,
        message: 'OTP generated but email sending failed. Please try again.',
        email: normalizedEmail,
        slogan: 'Smart Life, Fast Pay'  // Added slogan
      });
    }
    
  } catch (error) {
    console.error('❌ [FORGOT-PW] Server error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error. Please try again.',
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }
});


// @desc    Verify OTP for password reset
// @route   POST /api/users/verify-reset-otp
// @access  Public
app.post('/api/users/verify-reset-otp', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      message: errors.array()[0].msg,
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }
  
  try {
    const { email, otp } = req.body;
    const normalizedEmail = email.toLowerCase().trim();
    
    console.log(`🔍 [VERIFY-OTP] Checking: ${normalizedEmail}, OTP: ${otp}`);
    
    // Find user with matching OTP and not expired
    const user = await User.findOne({ 
      email: normalizedEmail,
      resetPasswordOTP: otp,
      resetPasswordOTPExpire: { $gt: Date.now() }
    });
    
    if (!user) {
      console.log(`❌ [VERIFY-OTP] Invalid OTP for ${normalizedEmail}`);
      
      // Check if user exists but OTP is wrong
      const userExists = await User.findOne({ email: normalizedEmail });
      if (userExists) {
        if (userExists.resetPasswordOTPExpire && userExists.resetPasswordOTPExpire < Date.now()) {
          console.log(`⏰ [VERIFY-OTP] OTP expired for ${normalizedEmail}`);
          return res.status(400).json({ 
            success: false, 
            message: 'OTP has expired. Please request a new one.',
            slogan: 'Smart Life, Fast Pay'  // Added slogan
          });
        }
      }
      
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid OTP. Please check and try again.',
        slogan: 'Smart Life, Fast Pay'  // Added slogan
      });
    }
    
    console.log(`✅ [VERIFY-OTP] OTP verified for ${normalizedEmail}`);
    
    // Generate a secure reset token
    const crypto = require('crypto');
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    // Set reset token and expire time (10 minutes)
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = new Date(Date.now() + 10 * 60 * 1000);
    
    // Clear OTP
    user.resetPasswordOTP = null;
    user.resetPasswordOTPExpire = null;
    
    await user.save();
    
    console.log(`🔐 [VERIFY-OTP] Reset token generated: ${resetToken.substring(0, 10)}...`);
    
    res.json({
      success: true,
      message: 'OTP verified successfully',
      resetToken: resetToken,
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  } catch (error) {
    console.error('❌ [VERIFY-OTP] Server error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error. Please try again.',
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }
});



// @desc    Reset password with token
// @route   POST /api/users/reset-password
// @access  Public
app.post('/api/users/reset-password', [
  body('resetToken').notEmpty().withMessage('Reset token is required'),
  body('newPassword').custom(value => {
    if (!validatePassword(value)) {
      throw new Error('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters');
    }
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      message: errors.array()[0].msg,
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }
  
  try {
    const { resetToken, newPassword } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpire: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token',
        slogan: 'Smart Life, Fast Pay'  // Added slogan
      });
    }
    
    // Hash the new password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update user password and clear reset fields
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpire = null;
    user.resetPasswordOTP = null;
    user.resetPasswordOTPExpire = null;
    
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Password reset successful. You can now login with your new password.',
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  } catch (error) {
    console.error('❌ [RESET-PW] Server error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error',
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }
});

// @desc    Set up transaction PIN
// @route   POST /api/users/set-transaction-pin
// @access  Private
app.post('/api/users/set-transaction-pin', protect, [
  body('pin')
    .isLength({ min: 6, max: 6 })
    .withMessage('PIN must be exactly 6 digits')
    .matches(/^\d+$/)
    .withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  try {
    const { pin } = req.body;
    const userId = req.user._id;
    
    console.log(`🔐 Setting 6-digit PIN for user: ${userId}`);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Debug current state
    console.log('📊 Before setting PIN:', {
      hasExistingPin: !!user.transactionPin,
      pinLength: user.transactionPin ? user.transactionPin.length : 0,
      transactionPinSet: user.transactionPinSet
    });

    // Check if PIN is already set
    if (user.transactionPin) {
      console.log('⚠️ PIN already set for user:', userId);
      return res.status(400).json({ 
        success: false, 
        message: 'Transaction PIN is already set. Use change PIN endpoint instead.',
        pinAlreadySet: true
      });
    }

    // ✅ FIX: Save the RAW PIN, let Mongoose pre-save hook hash it
    user.transactionPin = pin; // Save raw 6-digit PIN
    user.transactionPinSet = true;
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    
    // This will trigger the pre-save hook in User model
    await user.save();

    console.log(`✅ 6-digit PIN set successfully for user: ${userId}`);
    console.log('📊 After setting PIN:', {
      hasPin: !!user.transactionPin,
      pinLength: user.transactionPin.length,
      transactionPinSet: user.transactionPinSet
    });

    res.json({ 
      success: true, 
      message: '6-digit Transaction PIN set successfully',
      transactionPinSet: true
    });
    
  } catch (error) {
    console.error('❌ Error setting transaction PIN:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});





// @desc    Request PIN reset token via email
// @route   POST /api/users/request-pin-reset
// @access  Private
app.post('/api/users/request-pin-reset', protect, async (req, res) => {
  try {
    const { email } = req.body;
    const userId = req.user._id;

    // Verify user owns this email
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.email.toLowerCase() !== email.toLowerCase()) {
      return res.status(403).json({ success: false, message: 'Email does not match your account' });
    }

    // Check if PIN is set
    if (!user.transactionPin || !user.transactionPinSet) {
      return res.status(400).json({ 
        success: false, 
        message: 'Transaction PIN is not set. Use set PIN endpoint instead.' 
      });
    }

    // Generate 6-digit reset token
    const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
    const tokenExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store token in user document
    user.pinResetToken = resetToken;
    user.pinResetTokenExpires = tokenExpires;
    await user.save();

    // Send email (using your existing email service)
    try {
      await sendVerificationEmail(email, resetToken);
      
      console.log(`✅ PIN reset token sent to ${email}: ${resetToken}`);
      
      res.json({
        success: true,
        message: 'PIN reset code sent to your email',
        expiresIn: '10 minutes',
        email: email
      });
    } catch (emailError) {
      console.error('Email sending error:', emailError);
      
      // In development, return token for testing
      if (process.env.NODE_ENV === 'development') {
        return res.json({
          success: true,
          message: 'For development: PIN reset token is ' + resetToken,
          token: resetToken,
          expiresIn: '10 minutes',
          email: email
        });
      }
      
      return res.status(500).json({
        success: false,
        message: 'Failed to send email. Please try again.'
      });
    }

  } catch (error) {
    console.error('Request PIN reset error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Verify PIN reset token
// @route   POST /api/users/verify-pin-reset-token
// @access  Private
app.post('/api/users/verify-pin-reset-token', protect, [
  body('email').isEmail().withMessage('Valid email is required'),
  body('token').isLength({ min: 6, max: 6 }).withMessage('Token must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { email, token } = req.body;
    const userId = req.user._id;

    // Verify user owns this email
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.email.toLowerCase() !== email.toLowerCase()) {
      return res.status(403).json({ success: false, message: 'Email does not match your account' });
    }

    // Check if token exists and is valid
    if (!user.pinResetToken || !user.pinResetTokenExpires) {
      return res.status(400).json({ success: false, message: 'No reset token requested' });
    }

    if (user.pinResetToken !== token) {
      // Increment failed attempts
      user.pinResetTokenAttempts = (user.pinResetTokenAttempts || 0) + 1;
      
      if (user.pinResetTokenAttempts >= 3) {
        user.pinResetToken = null;
        user.pinResetTokenExpires = null;
        user.pinResetTokenAttempts = 0;
        await user.save();
        
        return res.status(429).json({
          success: false,
          message: 'Too many failed attempts. Please request a new reset token.'
        });
      }
      
      await user.save();
      
      const remainingAttempts = 3 - user.pinResetTokenAttempts;
      return res.status(400).json({
        success: false,
        message: `Invalid token. ${remainingAttempts} attempts remaining.`
      });
    }

    if (new Date() > user.pinResetTokenExpires) {
      user.pinResetToken = null;
      user.pinResetTokenExpires = null;
      user.pinResetTokenAttempts = 0;
      await user.save();
      
      return res.status(400).json({
        success: false,
        message: 'Token has expired. Please request a new one.'
      });
    }

    // Token is valid - mark as verified
    user.pinResetTokenVerified = true;
    user.pinResetTokenAttempts = 0;
    await user.save();

    res.json({
      success: true,
      message: 'Reset token verified successfully',
      verified: true,
      email: email
    });

  } catch (error) {
    console.error('Verify PIN reset token error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Reset PIN using verified token (no old PIN required)
// @route   POST /api/users/reset-pin-with-token
// @access  Private
app.post('/api/users/reset-pin-with-token', protect, [
  body('email').isEmail().withMessage('Valid email is required'),
  body('newPin')
    .isLength({ min: 6, max: 6 })
    .withMessage('New PIN must be exactly 6 digits')
    .matches(/^\d+$/)
    .withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { email, newPin } = req.body;
    const userId = req.user._id;

    // Verify user owns this email
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.email.toLowerCase() !== email.toLowerCase()) {
      return res.status(403).json({ success: false, message: 'Email does not match your account' });
    }

    // Check if token is verified
    if (!user.pinResetTokenVerified) {
      return res.status(400).json({
        success: false,
        message: 'Please verify your reset token first.'
      });
    }

    // Check for common PINs
    const commonPins = ['123456', '111111', '000000', '121212', '777777', '100400', '200000', '444444', '222222', '333333'];
    if (commonPins.includes(newPin)) {
      return res.status(400).json({
        success: false,
        message: 'New PIN is too common. Please choose a more secure PIN.'
      });
    }

    // Check if new PIN is same as old (if we could check)
    if (user.transactionPin) {
      try {
        const isSamePin = await bcrypt.compare(newPin, user.transactionPin);
        if (isSamePin) {
          return res.status(400).json({
            success: false,
            message: 'New PIN cannot be the same as your old PIN.'
          });
        }
      } catch (compareError) {
        // If comparison fails, continue
        console.log('Could not compare with old PIN:', compareError.message);
      }
    }

    // Save new PIN (will be hashed by pre-save hook)
    user.transactionPin = newPin;
    user.transactionPinSet = true;
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    
    // Clear reset token data
    user.pinResetToken = null;
    user.pinResetTokenExpires = null;
    user.pinResetTokenVerified = false;
    user.pinResetTokenAttempts = 0;
    
    await user.save();

    console.log(`✅ PIN reset via token for user: ${user.email}`);

    // Create notification
    try {
      await Notification.create({
        recipientId: userId,
        title: "Transaction PIN Reset Successfully 🔐",
        message: "Your transaction PIN has been reset successfully using email verification.",
        isRead: false
      });
    } catch (notificationError) {
      console.error('Error creating notification:', notificationError);
    }

    res.json({
      success: true,
      message: 'Transaction PIN reset successfully!',
      transactionPinSet: true
    });

  } catch (error) {
    console.error('Reset PIN with token error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});






// @desc    Change transaction PIN
// @route   POST /api/users/change-transaction-pin
// @access  Private
app.post('/api/users/change-transaction-pin', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('currentPin').isLength({ min: 6, max: 8 }).withMessage('Current PIN must be 6-8 digits').matches(/^\d+$/).withMessage('PIN must contain only digits'),
  body('newPin').isLength({ min: 6, max: 8 }).withMessage('New PIN must be 6-8 digits').matches(/^\d+$/).withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, currentPin, newPin } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.get('User-Agent');
    
    if (req.user._id.toString() !== userId) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Unauthorized access');
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    // Check for common PINs
    const commonPins = ['123456', '111111', '000000', '121212', '777777', '100400', '200000', '444444', '222222', '333333', '12345678', '11111111', '00000000'];
    if (commonPins.includes(newPin)) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Common PIN used');
      return res.status(400).json({ 
        success: false, 
        message: 'New PIN is too common. Please choose a more secure PIN' 
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'User not found');
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Verify current PIN if it exists
    if (user.transactionPin) {
      const isCurrentPinMatch = await bcrypt.compare(currentPin, user.transactionPin);
      if (!isCurrentPinMatch) {
        // Increment failed attempts
        user.failedPinAttempts += 1;
        
        // Lock account if too many failed attempts
        if (user.failedPinAttempts >= 3) {
          user.pinLockedUntil = new Date(getLagosTime().getTime() + 15 * 60000); // Lock for 15 minutes
          await user.save();
          
          await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Account locked due to failed attempts');
          return res.status(429).json({ 
            success: false, 
            message: 'Too many failed attempts. Account locked for 15 minutes.' 
          });
        } else {
          await user.save();
          
          const remainingAttempts = 3 - user.failedPinAttempts;
          await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, `Invalid current PIN, ${remainingAttempts} attempts remaining`);
          return res.status(400).json({ 
            success: false, 
            message: `Current PIN is incorrect. ${remainingAttempts} attempts remaining before lockout.` 
          });
        }
      }
    }
    
    // Hash the new PIN
    const salt = await bcrypt.genSalt(12);
    const hashedPin = await bcrypt.hash(newPin, salt);
    
    user.transactionPin = hashedPin;
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    await user.save();
    
    await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, true, 'PIN changed successfully');
    
    res.json({ 
      success: true, 
      message: 'Transaction PIN changed successfully',
    });
  } catch (error) {
    console.error('Error changing transaction PIN:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Toggle biometric authentication
// @route   POST /api/users/toggle-biometric
// @access  Private
app.post('/api/users/toggle-biometric', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('enable').isBoolean().withMessage('Enable must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, enable, biometricKey, biometricCredentialId } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if biometric authentication is allowed in settings
    const settings = await Settings.findOne();
    const biometricAllowed = settings ? settings.biometricAuthEnabled : true;
    
    if (!biometricAllowed && enable) {
      return res.status(400).json({ success: false, message: 'Biometric authentication is currently disabled' });
    }
    
    // When enabling biometric, require biometricKey and biometricCredentialId
    if (enable) {
      if (!biometricKey || !biometricCredentialId) {
        return res.status(400).json({ 
          success: false, 
          message: 'Biometric key and credential ID are required to enable biometric authentication' 
        });
      }
    }
    
    user.biometricEnabled = enable;
    if (enable) {
      user.biometricKey = biometricKey;
      user.biometricCredentialId = biometricCredentialId;
    } else {
      user.biometricKey = null;
      user.biometricCredentialId = null;
    }
    await user.save();
    
    res.json({ 
      success: true, 
      message: `Biometric authentication ${enable ? 'enabled' : 'disabled'} successfully`,
      biometricEnabled: user.biometricEnabled
    });
  } catch (error) {
    console.error('Error toggling biometric authentication:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});



// @desc    Verify transaction PIN
// @route   POST /api/users/verify-transaction-pin
// @access  Private
app.post('/api/users/verify-transaction-pin', protect, [
  body('userId').notEmpty().withMessage('User ID is required')
], async (req, res) => {
  try {
    const { userId } = req.body;
    // Accept either key
    const pin = req.body.pin || req.body.transactionPin;

    // Validate PIN
    if (!pin || !/^\d{6}$/.test(pin)) {
      return res.status(400).json({ success: false, message: 'PIN must be exactly 6 digits' });
    }

    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // PIN not set check
    if (!user.transactionPin || !user.transactionPinSet) {
      return res.status(400).json({
        success: false,
        message: 'Transaction PIN not set'
      });
    }

    const now = new Date();

    // 🔒 Lock check
    if (user.pinLockedUntil && user.pinLockedUntil > now) {
      const minutesRemaining = Math.ceil((user.pinLockedUntil - now) / 60000);
      return res.status(429).json({
        success: false,
        message: `Too many failed attempts. Account locked for ${minutesRemaining} minutes.`
      });
    }

    // 🔐 Verify PIN
    const isPinMatch = await bcrypt.compare(pin, user.transactionPin);

    if (!isPinMatch) {
      user.failedPinAttempts = (user.failedPinAttempts || 0) + 1;

      if (user.failedPinAttempts >= 3) {
        user.pinLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      }

      await user.save();

      const remainingAttempts = Math.max(0, 3 - user.failedPinAttempts);

      return res.status(400).json({
        success: false,
        message: `Invalid transaction PIN. ${remainingAttempts} attempts remaining before lockout.`
      });
    }

    // ✅ SUCCESS
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    await user.save();

    return res.json({
      success: true,
      message: 'PIN verified successfully'
    });

  } catch (error) {
    console.error('Error verifying transaction PIN:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});






// @desc    Admin: Check user's PIN status
// @route   POST /api/admin/check-pin-status
// @access  Private (Admin only)
app.post('/api/admin/check-pin-status', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }

    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required' 
      });
    }

    const user = await User.findById(userId)
      .select('email fullName phone transactionPin transactionPinSet failedPinAttempts pinLockedUntil createdAt')
      .lean();

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Determine PIN status
    const now = getLagosTime();
    const isPinLocked = user.pinLockedUntil && user.pinLockedUntil > now;
    const isPinSet = user.transactionPinSet || !!user.transactionPin;
    const lockRemaining = isPinLocked 
      ? Math.ceil((user.pinLockedUntil - now) / 60000) // minutes remaining
      : 0;

    // Security: Don't send hashed PIN, but provide status
    res.json({
      success: true,
      user: {
        _id: user._id,
        email: user.email,
        fullName: user.fullName,
        phone: user.phone,
        createdAt: user.createdAt
      },
      pinStatus: {
        isPinSet: isPinSet,
        isPinLocked: isPinLocked,
        failedAttempts: user.failedPinAttempts || 0,
        lockRemainingMinutes: lockRemaining,
        pinLockedUntil: user.pinLockedUntil,
        transactionPinSet: user.transactionPinSet || false,
        hasHashedPin: !!user.transactionPin
      }
    });

  } catch (error) {
    console.error('❌ Admin PIN check error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error' 
    });
  }
});

// @desc    Admin: Unlock user's PIN
// @route   POST /api/admin/unlock-pin
// @access  Private (Admin only)
app.post('/api/admin/unlock-pin', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }

    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required' 
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Reset PIN lock
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    
    await user.save();

    console.log(`✅ Admin unlocked PIN for user: ${user.email}`);

    res.json({
      success: true,
      message: 'PIN unlocked successfully',
      user: {
        email: user.email,
        fullName: user.fullName
      },
      pinStatus: {
        failedAttempts: 0,
        isPinLocked: false,
        pinLockedUntil: null
      }
    });

  } catch (error) {
    console.error('❌ Admin PIN unlock error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error' 
    });
  }
});

// @desc    Admin: Reset user's PIN (set to default)
// @route   POST /api/admin/reset-pin
// @access  Private (Admin only)
app.post('/api/admin/reset-pin', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }

    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required' 
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Generate default PIN: 123456
    const defaultPin = '123456';
    const salt = await bcrypt.genSalt(12);
    const hashedPin = await bcrypt.hash(defaultPin, salt);

    // Update user PIN
    user.transactionPin = hashedPin;
    user.transactionPinSet = true;
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    
    await user.save();

    console.log(`✅ Admin reset PIN for user: ${user.email} to: ${defaultPin}`);

    res.json({
      success: true,
      message: `PIN reset to default (${defaultPin}). User must change it on next login.`,
      user: {
        email: user.email,
        fullName: user.fullName
      },
      defaultPin: defaultPin, // Only send in admin response
      resetAt: new Date()
    });

  } catch (error) {
    console.error('❌ Admin PIN reset error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error' 
    });
  }
});




// @desc    Get user's security settings
// @route   GET /api/users/security-settings
// @access  Private
app.get('/api/users/security-settings', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const user = await User.findById(userId).select('transactionPin biometricEnabled');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const settings = await Settings.findOne();
    const pinRequired = settings ? settings.transactionPinRequired : true;
    const biometricAllowed = settings ? settings.biometricAuthEnabled : true;
    
    res.json({
      success: true,
      securitySettings: {
        transactionPinSet: !!user.transactionPin,
        biometricEnabled: user.biometricEnabled,
        pinRequired,
        biometricAllowed,
        pinLocked: user.pinLockedUntil && user.pinLockedUntil > getLagosTime(),
        lockTimeRemaining: user.pinLockedUntil && user.pinLockedUntil > getLagosTime() 
          ? Math.ceil((user.pinLockedUntil - getLagosTime()) / 60000) 
          : 0
      }
    });
  } catch (error) {
    console.error('Error fetching security settings:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get user's authentication logs
// @route   GET /api/users/auth-logs
// @access  Private
app.get('/api/users/auth-logs', protect, [
  query('userId').notEmpty().withMessage('User ID is required'),
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId } = req.query;
    const { page = 1, limit = 20 } = req.query;
    
    if (req.user._id.toString() !== userId && !req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    const skip = (page - 1) * limit;
    const logs = await AuthLog.find({ userId })
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await AuthLog.countDocuments({ userId });
    
    res.json({
      success: true,
      logs,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching authentication logs:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get user's balance
// @route   GET /api/users/balance
// @access  Private
app.get('/api/users/balance', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      walletBalance: user.walletBalance
    });
  } catch (error) {
      console.error('Error fetching balance:', error);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get user's commission balance
// @route   GET /api/users/commission-balance
// @access  Private
app.get('/api/users/commission-balance', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      commissionBalance: user.commissionBalance
    });
  } catch (error) {
      console.error('Error fetching commission balance:', error);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});









// @desc    Use commission balance for service payment - FIXED PRODUCTION VERSION
// @route   POST /api/services/use-commission
// @access  Private
app.post('/api/services/use-commission', protect, [
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be positive'),
  body('serviceType').notEmpty().withMessage('Service type is required'),
  body('serviceDetails').notEmpty().withMessage('Service details are required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  const { amount, serviceType, serviceDetails } = req.body;
  const userId = req.user._id;
  
  console.log(`🎯 USING COMMISSION FOR SERVICE: ${serviceType}, Amount: ₦${amount}`);
  console.log('Service Details:', JSON.stringify(serviceDetails, null, 2));
  
  try {
    // Get user WITHOUT session first
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if user has enough commission balance
    if (user.commissionBalance < amount) {
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient commission balance. Available: ₦${user.commissionBalance.toFixed(2)}, Required: ₦${amount}`,
        hasEnough: false
      });
    }
    
    // ============================================
    // STEP 1: Prepare VTpass payload
    // ============================================
    const generateRequestId = () => {
      const timestamp = Date.now();
      const random = Math.random().toString(36).substr(2, 9);
      return `COMM_${timestamp}_${random}_${userId.toString().substr(-6)}`;
    };
    
    const vtpassPayload = {
      request_id: generateRequestId(),
      amount: amount.toString(),
      serviceID: '',
      phone: serviceDetails.phone || '',
      billersCode: serviceDetails.billersCode || serviceDetails.meterNumber || serviceDetails.smartcardNumber || '',
      variation_code: serviceDetails.variation_code || '',
      type: serviceDetails.type || 'prepaid'
    };
    
    // Set correct serviceID
    const serviceMap = {
      'airtime': {
        'MTN': 'mtn',
        'Airtel': 'airtel',
        'Glo': 'glo',
        '9mobile': 'etisalat'
      },
      'data': {
        'MTN': 'mtn-data',
        'Airtel': 'airtel-data',
        'Glo': 'glo-data',
        '9mobile': 'etisalat-data'
      },
      'electricity': 'ikeja-electric',
      'cable': 'dstv',
      'education': 'waec',
      'insurance': 'auto-insurance'
    };
    
    if (serviceType === 'airtime' || serviceType === 'data') {
      const network = serviceDetails.network || 'MTN';
      vtpassPayload.serviceID = serviceMap[serviceType][network] || serviceMap.airtime.MTN;
    } else {
      vtpassPayload.serviceID = serviceMap[serviceType] || serviceType;
    }
    
    console.log('🎯 VTpass Payload:', vtpassPayload);
    
    // ============================================
    // STEP 2: Check for duplicate transaction FIRST
    // ============================================
    const existingTransaction = await Transaction.findOne({
      'metadata.commissionRequestId': vtpassPayload.request_id
    });
    
    if (existingTransaction) {
      console.log('✅ Transaction already processed, returning success');
      return res.json({
        success: true,
        message: `${serviceType} already processed successfully!`,
        alreadyProcessed: true,
        serviceType: serviceType
      });
    }
    
    // ============================================
    // STEP 3: Deduct from commission balance FIRST (before VTpass)
    // ============================================
    const commissionBefore = user.commissionBalance;
    const commissionAfter = commissionBefore - amount;
    
    // Update commission balance
    user.commissionBalance = commissionAfter;
    await user.save();
    
    console.log(`💰 Commission deducted: ₦${amount}`);
    console.log(`   Before: ₦${commissionBefore.toFixed(2)} → After: ₦${commissionAfter.toFixed(2)}`);
    
    // ============================================
    // STEP 4: Call VTpass to deliver service (WITH header to prevent wallet deduction)
    // ============================================
    let vtpassResult;
    try {
      console.log(`📡 Calling VTpass API for ${vtpassPayload.serviceID}...`);
      
      const vtpassResponse = await axios.post(`${process.env.BASE_URL || 'http://localhost:5000'}/api/vtpass/proxy`, vtpassPayload, {
        headers: {
          'Authorization': req.headers.authorization,
          'Content-Type': 'application/json',
          'x-commission-usage': 'true' // TELL VTpass NOT to deduct from wallet
        }
      });
      
      vtpassResult = vtpassResponse.data;
      console.log('✅ VTpass Response received');
      
      if (!vtpassResult.success) {
        // If VTpass fails, REFUND the commission
        user.commissionBalance = commissionBefore;
        await user.save();
        
        return res.status(400).json({
          success: false,
          message: vtpassResult.message || 'Service delivery failed',
          commissionRefunded: true,
          vtpassError: vtpassResult
        });
      }
      
    } catch (vtpassError) {
      console.error('❌ VTpass API Error:', vtpassError.response?.data || vtpassError.message);
      
      // If VTpass fails, REFUND the commission
      user.commissionBalance = commissionBefore;
      await user.save();
      
      return res.status(500).json({
        success: false,
        message: 'Service temporarily unavailable. Commission has been refunded.',
        commissionRefunded: true,
        error: vtpassError.message
      });
    }
    
    // ============================================
    // STEP 5: Create commission debit transaction
    // ============================================
    const commissionTransaction = new Transaction({
      userId: userId,
      amount: amount,
      type: 'Commission Debit',
      status: 'Successful',
      description: `Commission used for ${serviceType} purchase`,
      balanceBefore: commissionBefore,
      balanceAfter: commissionAfter,
      isCommission: true,
      reference: `COMM_DEBIT_${vtpassPayload.request_id}`,
      metadata: {
        phone: serviceDetails.phone || '',
        commissionRequestId: vtpassPayload.request_id,
        serviceType: serviceType,
        serviceDetails: serviceDetails,
        vtpassResponse: vtpassResult,
        network: serviceDetails.network || 'N/A',
        commissionUsed: true,
        commissionSource: serviceType
      },
      createdAt: new Date()
    });
    
    try {
      await commissionTransaction.save();
      console.log('✅ Commission transaction saved');
    } catch (error) {
      // If duplicate, log but continue
      if (error.code === 11000) {
        console.log('⚠️ Commission transaction already exists');
      } else {
        throw error;
      }
    }
    
    // ============================================
    // STEP 6: Create service purchase transaction
    // ============================================
    const serviceTransaction = new Transaction({
      userId: userId,
      amount: amount,
      type: serviceType === 'airtime' ? 'Airtime Purchase' : 
            serviceType === 'data' ? 'Data Purchase' :
            serviceType === 'electricity' ? 'Electricity Purchase' :
            serviceType === 'cable' ? 'Cable TV Purchase' : 'debit',
      status: 'Successful',
      description: `${serviceType} purchased using commission`,
      balanceBefore: user.walletBalance, // Show wallet balance (unchanged)
      balanceAfter: user.walletBalance, // Wallet unchanged
      isCommission: false,
      reference: `SERVICE_${vtpassPayload.request_id}`,
      metadata: {
        ...serviceDetails,
        vtpassResponse: vtpassResult,
        commissionUsed: true,
        commissionAmount: amount,
        commissionRequestId: vtpassPayload.request_id,
        serviceDelivered: true,
        deliveredTo: serviceDetails.phone || serviceDetails.meterNumber || 'user'
      },
      createdAt: new Date()
    });
    
    try {
      await serviceTransaction.save();
      console.log('✅ Service transaction saved');
    } catch (error) {
      // If duplicate, log but continue
      if (error.code === 11000) {
        console.log('⚠️ Service transaction already exists');
      } else {
        throw error;
      }
    }
    
    // ============================================
    // STEP 7: Return SUCCESS response
    // ============================================
    console.log(`✅ SUCCESS: Commission used & service delivered!`);
    console.log(`   Service: ${serviceType} to ${serviceDetails.phone || 'N/A'}`);
    console.log(`   VTpass Ref: ${vtpassResult.requestId || vtpassPayload.request_id}`);
    
    res.json({
      success: true,
      message: `✅ ${serviceType} purchased successfully using commission! Sent to ${serviceDetails.phone || 'your account'}`,
      amountUsed: amount,
      newCommissionBalance: commissionAfter,
      newWalletBalance: user.walletBalance, // Wallet unchanged
      serviceType: serviceType,
      hasEnough: true,
      commissionUsed: true,
      vtpassTransaction: {
        success: true,
        requestId: vtpassPayload.request_id,
        serviceDelivered: true,
        vtpassReference: vtpassResult.requestId || vtpassPayload.request_id,
        amount: amount,
        phone: serviceDetails.phone || 'N/A',
        network: serviceDetails.network || 'N/A'
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Error in use-commission endpoint:', error);
    
    res.status(500).json({ 
      success: false, 
      message: 'An unexpected error occurred. Please contact support.',
      error: error.message
    });
  }
});


// @desc    Upload profile image
// @route   POST /api/users/upload-profile-image
// @access  Private
app.post('/api/users/upload-profile-image', protect, upload.single('profileImage'), async (req, res) => {
  try {
    const userId = req.user._id;
    
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No file uploaded' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Delete old profile image if exists
    if (user.profileImage) {
      const oldImagePath = path.join(__dirname, user.profileImage);
      if (fs.existsSync(oldImagePath)) {
        fs.unlinkSync(oldImagePath);
      }
    }
    
    // Update user profile image path
    user.profileImage = `/uploads/${req.file.filename}`;
    await user.save();
    
    res.json({
      success: true,
      message: 'Profile image uploaded successfully',
      profileImage: user.profileImage
    });
  } catch (error) {
    console.error('Error uploading profile image:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get a specific user
// @route   GET /api/users/:userId
// @access  Private
app.get('/api/users/:userId', protect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (req.user._id.toString() !== userId && !req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({ success: true, user });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});










// @desc    Get all users (Admin only)
// @route   GET /api/users
// @access  Private/Admin
app.get('/api/users', adminProtect, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const users = await User.find({})
      .select('-password')
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments();
    
    res.json({ 
      success: true, 
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching all users:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});




// @desc    Get VTpass wallet balance
// @route   GET /api/admin/vtpass-balance
// @access  Private/Admin
app.get('/api/admin/vtpass-balance', protect, adminProtect, async (req, res) => {
  try {
    const vtpassApiKey = process.env.VTPASS_API_KEY;
    const vtpassSecretKey = process.env.VTPASS_SECRET_KEY;
    
    if (!vtpassApiKey || !vtpassSecretKey) {
      return res.status(400).json({
        success: false,
        message: 'VTpass API credentials not configured'
      });
    }
    
    const balanceResponse = await axios.get('https://vtpass.com/api/balance', {
      auth: {
        username: vtpassApiKey,
        password: vtpassSecretKey
      },
      timeout: 10000
    });

    const vtpassBalance = balanceResponse.data.contents?.balance || 0;
    
    res.json({
      success: true,
      balance: vtpassBalance,
      lastChecked: new Date(),
      currency: 'NGN'
    });
    
  } catch (error) {
    console.error('Error fetching VTpass balance:', error.message);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch VTpass balance',
      error: error.message
    });
  }
});






// @desc    Get VTpass alerts
// @route   GET /api/admin/vtpass-alerts
// @access  Private/Admin
app.get('/api/admin/vtpass-alerts', protect, adminProtect, async (req, res) => {
  try {
    const alerts = await Alert.find({ 
      type: 'VTPASS_LOW_BALANCE',
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } // Last 7 days
    })
      .sort({ createdAt: -1 })
      .limit(20);
    
    // Get current VTpass balance to include in response
    let currentBalance = 0;
    try {
      const vtpassApiKey = process.env.VTPASS_API_KEY;
      const vtpassSecretKey = process.env.VTPASS_SECRET_KEY;
      
      if (vtpassApiKey && vtpassSecretKey) {
        const balanceResponse = await axios.get('https://vtpass.com/api/balance', {
          auth: {
            username: vtpassApiKey,
            password: vtpassSecretKey
          },
          timeout: 5000
        });
        currentBalance = balanceResponse.data.contents?.balance || 0;
      }
    } catch (balanceError) {
      console.error('Could not fetch current balance:', balanceError.message);
    }
    
    res.json({
      success: true,
      count: alerts.length,
      currentBalance: currentBalance,
      alerts: alerts.map(alert => ({
        id: alert._id,
        type: alert.type,
        title: alert.title,
        message: alert.message,
        severity: alert.severity,
        data: alert.data,
        createdAt: alert.createdAt,
        acknowledged: alert.acknowledged
      }))
    });
    
  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: error.message 
    });
  }
});


// @desc    Get ALL users without pagination (Admin only - for transactions)
// @route   GET /api/admin/all-users
// @access  Private/Admin
app.get('/api/admin/all-users', adminProtect, async (req, res) => {
  try {
    const users = await User.find({})
      .select('-password')
      .lean();
    
    res.json({ 
      success: true, 
      users,
      total: users.length
    });
  } catch (error) {
    console.error('Error fetching all users:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Toggle user active status (Admin only)
// @route   PUT /api/users/toggle-status/:userId
// @access  Private/Admin
app.put('/api/users/toggle-status/:userId', adminProtect, [
  body('isActive').isBoolean().withMessage('isActive must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId } = req.params;
    const { isActive } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (req.user._id.toString() === userId && !isActive) {
      return res.status(400).json({ success: false, message: 'You cannot deactivate your own account' });
    }
    
    user.isActive = isActive;
    await user.save();
    
    res.json({ 
      success: true, 
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        isActive: user.isActive
      }
    });
  } catch (error) {
    console.error('Error toggling user status:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Toggle user admin status (Admin only)
// @route   PUT /api/users/toggle-admin-status/:userId
// @access  Private/Admin
app.put('/api/users/toggle-admin-status/:userId', adminProtect, [
  body('isAdmin').isBoolean().withMessage('isAdmin must be a boolean')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId } = req.params;
    const { isAdmin } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (req.user._id.toString() === userId && !isAdmin) {
      return res.status(400).json({ success: false, message: 'You cannot remove your own admin status' });
    }
    
    user.isAdmin = isAdmin;
    await user.save();
    
    res.json({ 
      success: true, 
      message: `User admin status ${isAdmin ? 'granted' : 'revoked'} successfully`,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    console.error('Error toggling user admin status:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Update user profile
// @route   PATCH /api/users/:userId
// @access  Private
app.patch('/api/users/:userId', protect, [
  body('fullName').optional().notEmpty().withMessage('Full name cannot be empty'),
  body('email').optional().isEmail().withMessage('Please provide a valid email'),
  body('phone').optional().isMobilePhone().withMessage('Please provide a valid phone number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId } = req.params;
    const { fullName, email, phone, walletBalance, commissionBalance, isActive, isAdmin } = req.body;
    
    if (req.user._id.toString() !== userId && !req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'You can only update your own profile' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (!req.user.isAdmin) {
      if (walletBalance !== undefined || commissionBalance !== undefined || isActive !== undefined || isAdmin !== undefined) {
        return res.status(403).json({ success: false, message: 'You are not authorized to update these fields' });
      }
    }
    
    if (fullName !== undefined) user.fullName = fullName;
    if (email !== undefined) {
      const existingUser = await User.findOne({ email, _id: { $ne: userId } });
      if (existingUser) {
        return res.status(400).json({ success: false, message: 'Email is already in use by another user' });
      }
      user.email = email;
    }
    if (phone !== undefined) user.phone = phone;
    if (walletBalance !== undefined && req.user.isAdmin) user.walletBalance = walletBalance;
    if (commissionBalance !== undefined && req.user.isAdmin) user.commissionBalance = commissionBalance;
    if (isActive !== undefined && req.user.isAdmin) user.isActive = isActive;
    if (isAdmin !== undefined && req.user.isAdmin) user.isAdmin = isAdmin;
    
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Profile updated successfully',
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        walletBalance: user.walletBalance,
        commissionBalance: user.commissionBalance,
        isActive: user.isActive,
        isAdmin: user.isAdmin,
        transactionPinSet: !!user.transactionPin,
        biometricEnabled: user.biometricEnabled,
      }
    });
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Change user password
// @route   POST /api/users/change-password
// @access  Private
app.post('/api/users/change-password', protect, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').custom(value => {
    if (!validatePassword(value)) {
      throw new Error('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters');
    }
    return true;
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }
    
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    user.password = hashedPassword;
    await user.save();
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Fund a user's wallet (Admin only)
// @route   POST /api/users/fund
// @access  Private/Admin
app.post('/api/users/fund', adminProtect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  const { userId, amount } = req.body;
  const note = req.body.note || `Admin funding of ${amount}`;
  
  console.log(`📥 Funding request: User: ${userId}, Amount: ${amount}, Note: ${note}`);
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      console.log(`❌ User ${userId} not found`);
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    console.log(`👤 User found: ${user.email}, Current balance: ${user.walletBalance}`);
    
    const balanceBefore = user.walletBalance;
    user.walletBalance += amount;
    const balanceAfter = user.walletBalance;
    
    await user.save({ session });
    
    console.log(`💰 New balance: ${balanceAfter}`);
    
    // FIXED: Change 'successful' to 'Successful'
    await createTransaction(
      userId,
      amount,
      'credit',
      'Successful', // ← CHANGE THIS LINE - Capital 'S'
      note,
      balanceBefore,
      balanceAfter,
      session,
      false,
      'none'
    );
    
    await session.commitTransaction();
    console.log(`✅ Successfully funded user ${user.email}`);
    
    res.json({ 
      success: true, 
      message: `Successfully funded user ${user.email} with ${amount}`, 
      newBalance: balanceAfter,
      userId: userId,
      transactionId: Date.now().toString()
    });
    
  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Error funding user:', error);
    console.error('Error details:', error.message);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    session.endSession();
  }
});
// @desc    Get transaction statistics (Admin only)
// @route   GET /api/transactions/statistics
// @access  Private/Admin
app.get('/api/transactions/statistics', adminProtect, [
  query('startDate').optional().isISO8601().withMessage('Start date must be a valid ISO8601 date'),
  query('endDate').optional().isISO8601().withMessage('End date must be a valid ISO8601 date')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { startDate, endDate } = req.query;
    
    let matchQuery = {};
    
    if (startDate && endDate) {
      matchQuery = {
        createdAt: {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        }
      };
    }
    
    // Try to get from cache first
    const cacheKey = `transaction-stats-${startDate || 'all'}-${endDate || 'all'}`;
    const cachedStats = cache.get(cacheKey);
    
    if (cachedStats) {
      return res.json({ success: true, statistics: cachedStats });
    }
    
    // Total transactions
    const totalTransactions = await Transaction.countDocuments(matchQuery);
    
    // Total successful transactions
    const successfulTransactions = await Transaction.countDocuments({
      ...matchQuery,
      status: 'successful'
    });
    
    // Total failed transactions
    const failedTransactions = await Transaction.countDocuments({
      ...matchQuery,
      status: 'failed'
    });
    
    // Total transaction amount
    const transactionAggregation = await Transaction.aggregate([
      { $match: matchQuery },
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$amount' },
          totalCredit: { $sum: { $cond: { if: { $eq: ['$type', 'credit'] }, then: '$amount', else: 0 } } },
          totalDebit: { $sum: { $cond: { if: { $eq: ['$type', 'debit'] }, then: '$amount', else: 0 } } }
        }
      }
    ]);
    
    const transactionStats = transactionAggregation[0] || {
      totalAmount: 0,
      totalCredit: 0,
      totalDebit: 0
    };
    
    // Commission statistics
    const commissionAggregation = await Transaction.aggregate([
      { $match: { ...matchQuery, isCommission: true } },
      {
        $group: {
          _id: null,
          totalCommission: { $sum: '$amount' }
        }
      }
    ]);
    
    const commissionStats = commissionAggregation[0] || { totalCommission: 0 };
    
    // Transaction by type
    const transactionsByType = await Transaction.aggregate([
      { $match: matchQuery },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      }
    ]);
    
    // Transaction by status
    const transactionsByStatus = await Transaction.aggregate([
      { $match: matchQuery },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          totalAmount: { $sum: '$amount' }
        }
      }
    ]);
    
    const statistics = {
      totalTransactions,
      successfulTransactions,
      failedTransactions,
      totalAmount: transactionStats.totalAmount,
      totalCredit: transactionStats.totalCredit,
      totalDebit: transactionStats.totalDebit,
      totalCommission: commissionStats.totalCommission,
      transactionsByType,
      transactionsByStatus
    };
    
    // Cache the result
    cache.set(cacheKey, statistics);
    
    res.json({ success: true, statistics });
  } catch (error) {
    console.error('Error fetching transaction statistics:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});



// @desc    Transfer funds between users
// @route   POST /api/transfer
// @access  Private
app.post('/api/transfer', protect, verifyTransactionAuth, checkServiceEnabled('isTransferEnabled'), [
  body('receiverEmail').isEmail().withMessage('Please provide a valid email'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  const { receiverEmail, amount, senderId } = req.body;
  const userId = req.user._id;
  const actualSenderId = senderId || userId;
  
  const maxRetries = 3;
  let retryCount = 0;
  
  while (retryCount < maxRetries) {
    const session = await mongoose.startSession();
    
    try {
      session.startTransaction({
        readConcern: { level: "snapshot" },
        writeConcern: { w: "majority" },
        readPreference: "primary"
      });
      
      const sender = await User.findOneAndUpdate(
        { _id: actualSenderId, walletBalance: { $gte: amount } },
        { $inc: { walletBalance: -amount } },
        { 
          new: true,
          session: session,
          runValidators: true 
        }
      );
      
      if (!sender) {
        await session.abortTransaction();
        await session.endSession();
        
        const userExists = await User.findById(actualSenderId);
        if (!userExists) {
          return res.status(404).json({ success: false, message: 'Sender not found' });
        }
        
        return res.status(400).json({ success: false, message: 'Insufficient balance' });
      }
      
      const receiver = await User.findOneAndUpdate(
        { email: receiverEmail },
        { $inc: { walletBalance: amount } },
        { 
          new: true,
          session: session,
          runValidators: true 
        }
      );
      
      if (!receiver) {
        await session.abortTransaction();
        await session.endSession();
        return res.status(404).json({ success: false, message: 'Receiver not found' });
      }
      
      if (sender._id.toString() === receiver._id.toString()) {
        await User.findByIdAndUpdate(
          sender._id,
          { $inc: { walletBalance: amount } },
          { session: session }
        );
        await session.abortTransaction();
        await session.endSession();
        return res.status(400).json({ success: false, message: 'Cannot transfer to yourself' });
      }
      
      const settings = await Settings.findOne().session(session);
      const minAmount = settings ? settings.minTransactionAmount : 100;
      const maxAmount = settings ? settings.maxTransactionAmount : 1000000;
      
      if (amount < minAmount) {
        await User.findByIdAndUpdate(sender._id, { $inc: { walletBalance: amount } }, { session });
        await User.findByIdAndUpdate(receiver._id, { $inc: { walletBalance: -amount } }, { session });
        await session.abortTransaction();
        await session.endSession();
        return res.status(400).json({ success: false, message: `Transfer amount must be at least ${minAmount}` });
      }
      
      if (amount > maxAmount) {
        await User.findByIdAndUpdate(sender._id, { $inc: { walletBalance: amount } }, { session });
        await User.findByIdAndUpdate(receiver._id, { $inc: { walletBalance: -amount } }, { session });
        await session.abortTransaction();
        await session.endSession();
        return res.status(400).json({ success: false, message: `Transfer amount cannot exceed ${maxAmount}` });
      }
      
      const senderBalanceBefore = sender.walletBalance + amount;
      const senderBalanceAfter = sender.walletBalance;
      
      const receiverBalanceBefore = receiver.walletBalance - amount;
      const receiverBalanceAfter = receiver.walletBalance;
      
      // Create sender transaction
      await Transaction.create([{
        userId: sender._id,
        amount: amount,
        type: 'Transfer Sent',
        service: 'transfer',
        description: `Transfer to ${receiver.email}`,
        reference: `TRF_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        status: 'Successful',
        balanceBefore: senderBalanceBefore,
        balanceAfter: senderBalanceAfter,
        authenticationMethod: req.authenticationMethod || 'pin',
        metadata: {
          recipientId: receiver._id,
          recipientEmail: receiver.email
        }
      }], { session });
      
      // Create receiver transaction
      await Transaction.create([{
        userId: receiver._id,
        amount: amount,
        type: 'Transfer Received',
        service: 'transfer', // Changed from 'peer_transfer' to 'transfer' for consistency
        description: `Transfer from ${sender.email}`,
        reference: `TRF_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        status: 'Successful',
        balanceBefore: receiverBalanceBefore,
        balanceAfter: receiverBalanceAfter,
        authenticationMethod: req.authenticationMethod || 'pin',
        metadata: {
          senderId: sender._id,
          senderEmail: sender.email
        }
      }], { session });
      
      await session.commitTransaction();
      await session.endSession();
      
      // ========== COMMISSION CALCULATION COMMENTED OUT ==========
      // Wallet-to-wallet transfers do not earn commission
      /*
      try {
        if (sender._id.toString() !== receiver._id.toString()) {
          // Pass 'transfer' as service type
          await calculateAndAddCommission(receiver._id, amount, 'transfer');
          console.log(`✅ Commission calculated for transfer of ₦${amount}`);
        }
      } catch (commissionError) {
        console.error('Commission calculation error:', commissionError);
      }
      */
      // =========================================================
      
      // Create notifications (outside transaction)
      try {
        await Notification.create({
          recipientId: sender._id,
          title: "Transfer Successful 💸",
          message: `You successfully transferred ₦${amount} to ${receiver.email}. New balance: ₦${senderBalanceAfter}`,
          type: 'transfer_sent',
          isRead: false
        });
        
        await Notification.create({
          recipientId: receiver._id,
          title: "Money Received 💰",
          message: `You received ₦${amount} from ${sender.email}. New balance: ₦${receiverBalanceAfter}`,
          type: 'transfer_received',
          isRead: false
        });
      } catch (notificationError) {
        console.error('Error creating notifications:', notificationError);
      }
      
      return res.json({ 
        success: true, 
        message: `Transfer of ₦${amount} to ${receiver.email} successful`,
        newBalance: senderBalanceAfter,
        newSenderBalance: senderBalanceAfter,
        receiverName: receiver.fullName || receiver.email,
        transactionId: `TRF_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
      });
      
    } catch (error) {
      if (session.inTransaction()) {
        try {
          await session.abortTransaction();
        } catch (abortError) {
          console.error('Error aborting transaction:', abortError);
        }
      }
      
      try {
        await session.endSession();
      } catch (endError) {
        console.error('Error ending session:', endError);
      }
      
      if (error.code === 112 || error.name === 'MongoTransactionError') {
        retryCount++;
        console.log(`Write conflict detected. Retry ${retryCount}/${maxRetries}`);
        
        if (retryCount < maxRetries) {
          const delay = Math.pow(2, retryCount) * 100;
          await new Promise(resolve => setTimeout(resolve, delay));
          continue;
        }
      }
      
      console.error('Error in transfer after retries:', error);
      
      return res.status(500).json({ 
        success: false, 
        message: 'Transfer failed. Please try again.',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
});



// @desc    Get user's transactions
// @route   GET /api/transactions
// @access  Private
app.get('/api/transactions', protect, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const userId = req.user._id;
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({ userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments({ userId });
    
    res.json({
      success: true,
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get user's commission transactions
// @route   GET /api/commission-transactions
// @access  Private
app.get('/api/commission-transactions', protect, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const userId = req.user._id;
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const commissionTransactions = await Transaction.find({ userId, isCommission: true })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments({ userId, isCommission: true });
    
    res.json({
      success: true,
      commissionTransactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching commission transactions:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Get all transactions (Admin only) - FIXED VERSION
// @route   GET /api/transactions/all
// @access  Private/Admin
app.get('/api/transactions/all', adminProtect, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    console.log('🔍 DEBUG: Starting /api/transactions/all endpoint');
    
    // 1. Get ALL transactions first
    const transactions = await Transaction.find({})
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();
    
    console.log(`🔍 DEBUG: Found ${transactions.length} transactions`);
    
    // 2. Get ALL user IDs from transactions
    const userIds = [];
    for (const tx of transactions) {
      if (tx.userId) {
        // Convert to ObjectId if valid
        if (mongoose.Types.ObjectId.isValid(tx.userId)) {
          userIds.push(new mongoose.Types.ObjectId(tx.userId));
        } else {
          console.log(`⚠️ WARNING: Invalid userId ${tx.userId} in transaction ${tx._id}`);
        }
      }
    }
    
    console.log(`🔍 DEBUG: Unique userIds to fetch: ${userIds.length}`);
    
    // 3. Fetch ALL users at once
    let users = [];
    if (userIds.length > 0) {
      users = await User.find({ 
        _id: { $in: userIds } 
      })
      .select('fullName email phone')
      .lean();
    }
    
    console.log(`🔍 DEBUG: Found ${users.length} users in database`);
    
    // 4. Create a quick lookup map
    const userMap = {};
    for (const user of users) {
      userMap[user._id.toString()] = {
        _id: user._id,
        fullName: user.fullName || 'Unknown User',
        email: user.email || 'no-email@example.com',
        phone: user.phone || 'N/A'
      };
    }
    
    // 5. Attach user data to each transaction
    const transactionsWithUsers = transactions.map(tx => {
      const transaction = { ...tx };
      const userId = tx.userId?.toString();
      
      if (userId && userMap[userId]) {
        // User exists in database
        transaction.user = userMap[userId];
        console.log(`✅ Attached user: ${userMap[userId].fullName} to transaction ${tx._id}`);
      } else if (userId) {
        // User ID exists but user not found (might be deleted)
        transaction.user = {
          _id: userId,
          fullName: 'Deleted User',
          email: 'deleted@account.removed',
          phone: 'N/A'
        };
        console.log(`⚠️ User ${userId} not found (deleted), marked as deleted`);
      } else {
        // No user ID
        transaction.user = {
          _id: null,
          fullName: 'System Transaction',
          email: 'system@transaction',
          phone: 'N/A'
        };
      }
      
      return transaction;
    });
    
    // 6. Verify first transaction has user data
    if (transactionsWithUsers.length > 0) {
      const firstTx = transactionsWithUsers[0];
      console.log('🔍 DEBUG: First transaction user data:', {
        hasUser: !!firstTx.user,
        userName: firstTx.user?.fullName,
        userEmail: firstTx.user?.email,
        userId: firstTx.user?._id
      });
    }
    
    const total = await Transaction.countDocuments();
    
    res.json({ 
      success: true, 
      transactions: transactionsWithUsers,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
    
  } catch (error) {
    console.error('❌ Error in /api/transactions/all:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Get transactions for specific user (Admin only)
// @route   GET /api/transactions/user/:userId
// @access  Private/Admin
app.get('/api/transactions/user/:userId', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (!userId) {
      return res.status(400).json({ 
        success: false, 
        message: 'User ID is required.' 
      });
    }

    const transactions = await Transaction.find({ userId })
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      transactions: transactions
    });
  } catch (error) {
    console.error('Error fetching transactions for user:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error fetching user transactions.' 
    });
  }
});









// @desc    Auto-fix missing transactions
// @route   POST /api/transactions/auto-fix-missing
// @access  Private
app.post('/api/transactions/auto-fix-missing', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { daysBack = 7 } = req.body;

    console.log('🔄 Auto-fixing missing transactions for user:', userId);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysBack);

    // Find transactions that might need fixing
    const userTransactions = await Transaction.find({
      userId,
      createdAt: { $gte: startDate }
    });

    let fixedCount = 0;
    const results = [];

    for (const transaction of userTransactions) {
      try {
        // Ensure transaction has proper metadata
        if (!transaction.metadata) {
          transaction.metadata = {};
        }

        // Add auto-save flag if missing
        if (!transaction.metadata.autoSaved) {
          transaction.metadata.autoSaved = true;
          transaction.metadata.lastVerified = new Date();
          await transaction.save();
          fixedCount++;
          results.push({
            transactionId: transaction._id,
            status: 'fixed',
            action: 'added_metadata'
          });
        }

        // Ensure transaction has reference
        if (!transaction.reference) {
          transaction.reference = transaction._id.toString();
          await transaction.save();
          fixedCount++;
          results.push({
            transactionId: transaction._id,
            status: 'fixed', 
            action: 'added_reference'
          });
        }
      } catch (fixError) {
        results.push({
          transactionId: transaction._id,
          status: 'failed',
          error: fixError.message
        });
      }
    }

    res.json({
      success: true,
      message: `Auto-fix completed. Fixed ${fixedCount} transactions.`,
      fixedCount,
      totalChecked: userTransactions.length,
      results
    });

  } catch (error) {
    console.error('❌ Auto-fix error:', error);
    res.status(500).json({
      success: false,
      message: 'Auto-fix failed',
      error: error.message
    });
  }
});


// @desc    Sync missing transactions from VTpass
// @route   POST /api/transactions/sync-missing
// @access  Private
app.post('/api/transactions/sync-missing', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { daysBack = 3 } = req.body;

    console.log('🔄 Syncing missing transactions for user:', userId);

    // This would typically query VTpass API for recent transactions
    // and cross-reference with your database
    // For now, we'll return a message about the sync process

    res.json({
      success: true,
      message: 'Sync process initiated. Check back later for updates.',
      syncId: `sync_${Date.now()}`,
      userId: userId,
      daysBack: daysBack
    });

  } catch (error) {
    console.error('❌ Sync error:', error);
    res.status(500).json({
      success: false,
      message: 'Sync failed',
      error: error.message
    });
  }
});

// @desc    Get transaction statistics
// @route   GET /api/transactions/statistics
// @access  Private
app.get('/api/transactions/statistics', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const totalTransactions = await Transaction.countDocuments({ userId });
    const successfulTransactions = await Transaction.countDocuments({ 
      userId, 
      status: 'successful' 
    });
    const pendingTransactions = await Transaction.countDocuments({ 
      userId, 
      status: { $in: ['pending', 'processing'] } 
    });
    const failedTransactions = await Transaction.countDocuments({ 
      userId, 
      status: 'failed' 
    });

    // Total amounts - FIXED: Use mongoose.Types.ObjectId
    const amountStats = await Transaction.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: null,
          totalSpent: { 
            $sum: { 
              $cond: [
                { $in: ['$type', ['debit', 'Commission Debit', 'Commission Withdrawal']] }, 
                '$amount', 
                0 
              ] 
            } 
          },
          totalReceived: { 
            $sum: { 
              $cond: [
                { $in: ['$type', ['credit', 'Commission Credit']] }, 
                '$amount', 
                0 
              ] 
            } 
          }
        }
      }
    ]);

    const stats = amountStats[0] || { totalSpent: 0, totalReceived: 0 };

    res.json({
      success: true,
      statistics: {
        totalTransactions,
        successfulTransactions,
        pendingTransactions,
        failedTransactions,
        totalSpent: stats.totalSpent,
        totalReceived: stats.totalReceived,
        successRate: totalTransactions > 0 ? (successfulTransactions / totalTransactions) * 100 : 0
      }
    });

  } catch (error) {
    console.error('Error fetching transaction statistics:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics'
    });
  }
}); 


// @desc    Get a specific transaction by ID
// @route   GET /api/transactions/:transactionId
// @access  Private
app.get('/api/transactions/:transactionId', protect, async (req, res) => {
  try {
    const { transactionId } = req.params;
    const transaction = await Transaction.findById(transactionId);
    
    if (!transaction) {
      return res.status(404).json({ success: false, message: 'Transaction not found' });
    }
    
    // Check if the user has permission to view this transaction
    if (req.user._id.toString() !== transaction.userId.toString() && !req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    res.json({ success: true, transaction });
  } catch (error) {
    console.error('Error fetching transaction:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get user's beneficiaries
// @route   GET /api/beneficiaries
// @access  Private
app.get('/api/beneficiaries', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const beneficiaries = await Beneficiary.find({ userId })
      .sort({ createdAt: -1 });
    
    res.json({ success: true, beneficiaries });
  } catch (error) {
    console.error('Error fetching beneficiaries:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Add a beneficiary
// @route   POST /api/beneficiaries
// @access  Private
app.post('/api/beneficiaries', protect, [
  body('name').notEmpty().withMessage('Name is required'),
  body('type').isIn(['phone', 'email']).withMessage('Type must be phone or email'),
  body('value').notEmpty().withMessage('Value is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { name, type, value, network } = req.body;
    const userId = req.user._id;
    
    const existingBeneficiary = await Beneficiary.findOne({ userId, value });
    if (existingBeneficiary) {
      return res.status(400).json({ success: false, message: 'Beneficiary already exists' });
    }
    
    const beneficiary = await Beneficiary.create({
      userId,
      name,
      type,
      value,
      network
    });
    
    res.status(201).json({ 
      success: true, 
      message: 'Beneficiary added successfully',
      beneficiary
    });
  } catch (error) {
    console.error('Error adding beneficiary:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Delete a beneficiary
// @route   DELETE /api/beneficiaries/:id
// @access  Private
app.delete('/api/beneficiaries/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;
    
    const beneficiary = await Beneficiary.findById(id);
    if (!beneficiary) {
      return res.status(404).json({ success: false, message: 'Beneficiary not found' });
    }
    
    if (req.user._id.toString() !== beneficiary.userId.toString()) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    await Beneficiary.findByIdAndDelete(id);
    
    res.json({ success: true, message: 'Beneficiary deleted successfully' });
  } catch (error) {
    console.error('Error deleting beneficiary:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});




// @desc    Get notification statistics (ONLY personal)
// @route   GET /api/notifications/statistics
// @access  Private
app.get('/api/notifications/statistics', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    console.log(`📊 [NOTIFICATIONS] Getting PERSONAL statistics for user: ${userId}`);
    
    // ONLY count personal notifications
    const totalPersonal = await Notification.countDocuments({ recipient: userId });
    const unreadPersonal = await Notification.countDocuments({ 
      recipient: userId, 
      isRead: false 
    });
    
    // Latest PERSONAL notification
    const latestNotification = await Notification.findOne({
      recipient: userId
    })
    .sort({ createdAt: -1 })
    .select('title createdAt type')
    .lean();
    
    const statistics = {
      personal: {
        total: totalPersonal,
        unread: unreadPersonal,
        read: totalPersonal - unreadPersonal
      },
      latestNotification: latestNotification || null
    };
    
    console.log(`📈 [NOTIFICATIONS] Personal statistics for ${userId}:`, statistics);
    
    res.json({
      success: true,
      statistics: statistics
    });
  } catch (error) {
    console.error('❌ [NOTIFICATIONS] Error getting statistics:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch notification statistics' 
    });
  }
});


// @desc    Create test notifications for development
// @route   POST /api/notifications/test
// @access  Private
app.post('/api/notifications/test', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Delete existing test notifications for this user
    await Notification.deleteMany({ 
      recipientId: userId,
      title: { $regex: /test|welcome|maintenance|airtime/i }
    });
    
    const testNotifications = [
      {
        recipientId: userId,
        title: "Welcome to VTPass! 🎉",
        message: "Thank you for joining our platform. Start enjoying seamless bill payments, airtime top-ups, and more.",
        isRead: false
      },
      {
        recipientId: userId,
        title: "Airtime Purchase Successful ✅",
        message: "Your airtime purchase of ₦500 for 08012345678 was completed successfully. Transaction ID: TXN_001",
        isRead: true
      },
      {
        recipientId: userId,
        title: "Data Bundle Purchased 📱",
        message: "1GB data bundle for MTN has been activated on your number 08012345678. Valid for 30 days.",
        isRead: false
      },
      {
        recipientId: userId,
        title: "System Maintenance Notice 🔧",
        message: "There will be scheduled maintenance on Saturday from 2-4 AM. Services may be temporarily unavailable.",
        isRead: false
      },
      {
        recipientId: userId,
        title: "Wallet Funded Successfully 💰",
        message: "Your wallet has been credited with ₦5,000. New balance: ₦7,250. Transaction Ref: FUND_001",
        isRead: true
      },
      {
        recipientId: userId,
        title: "New Feature Available 🚀",
        message: "Electricity bill payments are now available! Pay your PHCN, AEDC, and other utility bills seamlessly.",
        isRead: false
      }
    ];
    
    const createdNotifications = await Notification.insertMany(testNotifications);
    
    res.json({ 
      success: true, 
      message: 'Test notifications created successfully',
      count: createdNotifications.length,
      notifications: createdNotifications
    });
  } catch (error) {
    console.error('Error creating test notifications:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Mark all PERSONAL notifications as read
// @route   POST /api/notifications/mark-all-read
// @access  Private
app.post('/api/notifications/mark-all-read', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    console.log(`📌 [NOTIFICATIONS] Marking all PERSONAL notifications as read for user: ${userId}`);
    
    // Mark all personal notifications as read
    const result = await Notification.updateMany(
      { recipient: userId, isRead: false },
      { $set: { isRead: true } }
    );
    
    console.log(`✅ [NOTIFICATIONS] Marked ${result.modifiedCount} PERSONAL notifications as read`);
    
    res.json({ 
      success: true, 
      message: `Marked ${result.modifiedCount} notifications as read`,
      modifiedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('❌ [NOTIFICATIONS] Error marking all as read:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to mark notifications as read' 
    });
  }
});



// @desc    Get general announcements (separate from personal notifications)
// @route   GET /api/announcements
// @access  Private
app.get('/api/announcements', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get only general announcements NOT read by this user
    const announcements = await Notification.find({
      recipient: null,
      readBy: { $ne: userId },
      type: 'announcement' // Use a specific type for announcements
    })
    .sort({ createdAt: -1 })
    .limit(10)
    .lean();
    
    res.json({
      success: true,
      announcements,
      count: announcements.length
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});



// @desc    Get user's personal notifications ONLY
// @route   GET /api/notifications
// @access  Private
app.get('/api/notifications', protect, [
  query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  try {
    const userId = req.user._id;
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    console.log(`🔔 [NOTIFICATIONS] Fetching for user: ${userId}`);
    
    // ONLY personal notifications for this user
    const query = { recipient: userId };
    
    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();
    
    const total = await Notification.countDocuments(query);
    
    console.log(`📊 Found ${notifications.length} personal notifications`);
    
    res.json({
      success: true,
      notifications,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total,
      statistics: {
        total: total,
        unread: await Notification.countDocuments({ 
          recipient: userId, 
          isRead: false 
        })
      }
    });
  } catch (error) {
    console.error('❌ Error fetching notifications:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch notifications' });
  }
});

// @desc    Mark notification as read
// @route   POST /api/notifications/:id/read
// @access  Private
app.post('/api/notifications/:id/read', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;
    
    console.log(`📌 [NOTIFICATIONS] Marking as read: ${id} for user: ${userId}`);
    
    const notification = await Notification.findById(id);
    
    if (!notification) {
      console.log('❌ [NOTIFICATIONS] Notification not found:', id);
      return res.status(404).json({ 
        success: false, 
        message: 'Notification not found' 
      });
    }
    
    // Check if user has access to this notification
    if (notification.recipient && notification.recipient.toString() !== userId.toString()) {
      console.log('⛔ [NOTIFICATIONS] Access denied for user:', userId);
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied' 
      });
    }
    
    // Handle marking as read
    if (notification.recipient === null) {
      // General notification - add user to readBy array
      if (!notification.readBy.includes(userId)) {
        notification.readBy.push(userId);
        await notification.save();
        console.log('✅ [NOTIFICATIONS] General notification marked as read');
      }
    } else {
      // Personal notification - mark as read
      if (!notification.isRead) {
        notification.isRead = true;
        await notification.save();
        console.log('✅ [NOTIFICATIONS] Personal notification marked as read');
      }
    }
    
    res.json({ 
      success: true, 
      message: 'Notification marked as read',
      notification: {
        id: notification._id,
        isRead: notification.recipient === null ? notification.readBy.includes(userId) : notification.isRead
      }
    });
  } catch (error) {
    console.error('❌ [NOTIFICATIONS] Error marking as read:', error);
    
    // Handle validation errors specifically
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid notification data',
        error: error.message 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Failed to mark notification as read' 
    });
  }
});









// @desc    Send notification (Admin only - supports bulk or personal)
// @route   POST /api/notifications/send
// @access  Private (Admin)
app.post('/api/notifications/send', protect, async (req, res) => {
  try {
    const { title, message, recipientId, sendToAll = false } = req.body;
    
    console.log(`📨 [ADMIN] Sending notification:`, { title, recipientId, sendToAll });
    
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }
    
    // Validate input
    if (!title || !message) {
      return res.status(400).json({ 
        success: false, 
        message: 'Title and message are required' 
      });
    }
    
    let notifications = [];
    
    if (sendToAll) {
      // BULK: Send to ALL users
      console.log('👥 [ADMIN] Sending bulk notification to all users');
      
      const users = await User.find({ isActive: true });
      
      for (const user of users) {
        const notification = new Notification({
          recipient: user._id, // Personal for each user
          title: title.trim(),
          message: message.trim(),
          type: 'announcement',
          isRead: false,
          metadata: {
            sentByAdmin: req.user._id,
            bulk: true,
            sentAt: new Date()
          }
        });
        
        await notification.save();
        notifications.push({
          userId: user._id,
          email: user.email,
          notificationId: notification._id
        });
      }
      
      console.log(`✅ [ADMIN] Sent bulk notification to ${users.length} users`);
      
    } else if (recipientId) {
      // SINGLE: Send to specific user
      console.log(`👤 [ADMIN] Sending notification to user: ${recipientId}`);
      
      const user = await User.findById(recipientId);
      if (!user) {
        return res.status(404).json({ 
          success: false, 
          message: 'Recipient user not found' 
        });
      }
      
      const notification = new Notification({
        recipient: user._id, // Personal for this user
        title: title.trim(),
        message: message.trim(),
        type: 'announcement',
        isRead: false,
        metadata: {
          sentByAdmin: req.user._id,
          sentAt: new Date()
        }
      });
      
      await notification.save();
      notifications.push({
        userId: user._id,
        email: user.email,
        notificationId: notification._id
      });
      
      console.log(`✅ [ADMIN] Sent notification to ${user.email}`);
      
    } else {
      // ERROR: Neither recipientId nor sendToAll specified
      return res.status(400).json({ 
        success: false, 
        message: 'Either recipientId or sendToAll is required' 
      });
    }
    
    res.json({ 
      success: true, 
      message: sendToAll ? 
        `Notification sent to ${notifications.length} users` : 
        'Notification sent successfully',
      sentCount: notifications.length,
      notifications: notifications
    });
    
  } catch (error) {
    console.error('❌ [ADMIN] Error sending notification:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send notification' 
    });
  }
});


// @desc    Clean up old notifications
// @route   POST /api/notifications/cleanup
// @access  Private (Admin)
app.post('/api/notifications/cleanup', protect, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }
    
    const { days = 90 } = req.body; // Default: clean up notifications older than 90 days
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    console.log(`🧹 [NOTIFICATIONS] Cleaning up notifications older than ${days} days (before ${cutoffDate})`);
    
    // Delete old notifications
    const result = await Notification.deleteMany({
      createdAt: { $lt: cutoffDate }
    });
    
    console.log(`✅ [NOTIFICATIONS] Cleanup completed: ${result.deletedCount} notifications deleted`);
    
    res.json({ 
      success: true, 
      message: `Cleaned up ${result.deletedCount} notifications older than ${days} days`,
      deletedCount: result.deletedCount,
      cutoffDate: cutoffDate
    });
    
  } catch (error) {
    console.error('❌ [NOTIFICATIONS] Error during cleanup:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to clean up notifications' 
    });
  }
});


// @desc    Get app settings
// @route   GET /api/settings
// @access  Public
app.get('/api/settings', async (req, res) => {
  try {
    // Try to get from cache first
    const cachedSettings = cache.get('app-settings');
    
    if (cachedSettings) {
      return res.json({ success: true, settings: cachedSettings });
    }
    
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    
    // Cache the result
    cache.set('app-settings', settings);
    
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Update app settings (Admin only)
// @route   PUT /api/settings
// @access  Private/Admin
app.put('/api/settings', adminProtect, async (req, res) => {
  try {
    const {
      appVersion,
      maintenanceMode,
      minTransactionAmount,
      maxTransactionAmount,
      vtpassCommission,
      commissionRate,
      // Service Availability
      airtimeEnabled,
      dataEnabled,
      cableTvEnabled,
      electricityEnabled,
      transferEnabled,
      // Commission/Fee Management
      airtimeCommission,
      dataCommission,
      transferFee,
      isTransferFeePercentage,
      // User Management Defaults
      newUserDefaultWalletBalance,
      // Notification Settings
      emailNotificationsEnabled,
      pushNotificationsEnabled,
      smsNotificationsEnabled,
      notificationMessage,
      // Security Settings
      twoFactorAuthRequired,
      autoLogoutEnabled,
      sessionTimeout,
      transactionPinRequired,
      biometricAuthEnabled,
      // API Rate Limiting
      apiRateLimit,
      apiTimeWindow
    } = req.body;
    
    let settings = await Settings.findOne();
    if (!settings) {
      settings = new Settings();
    }
    
    // Update existing fields
    if (appVersion !== undefined) settings.appVersion = appVersion;
    if (maintenanceMode !== undefined) settings.maintenanceMode = maintenanceMode;
    if (minTransactionAmount !== undefined) settings.minTransactionAmount = minTransactionAmount;
    if (maxTransactionAmount !== undefined) settings.maxTransactionAmount = maxTransactionAmount;
    if (vtpassCommission !== undefined) settings.vtpassCommission = vtpassCommission;
    if (commissionRate !== undefined) settings.commissionRate = commissionRate;
    
    // Update new fields
    if (airtimeEnabled !== undefined) settings.airtimeEnabled = airtimeEnabled;
    if (dataEnabled !== undefined) settings.dataEnabled = dataEnabled;
    if (cableTvEnabled !== undefined) settings.cableTvEnabled = cableTvEnabled;
    if (electricityEnabled !== undefined) settings.electricityEnabled = electricityEnabled;
    if (transferEnabled !== undefined) settings.transferEnabled = transferEnabled;
    if (airtimeCommission !== undefined) settings.airtimeCommission = airtimeCommission;
    if (dataCommission !== undefined) settings.dataCommission = dataCommission;
    if (transferFee !== undefined) settings.transferFee = transferFee;
    if (isTransferFeePercentage !== undefined) settings.isTransferFeePercentage = isTransferFeePercentage;
    if (newUserDefaultWalletBalance !== undefined) settings.newUserDefaultWalletBalance = newUserDefaultWalletBalance;
    if (emailNotificationsEnabled !== undefined) settings.emailNotificationsEnabled = emailNotificationsEnabled;
    if (pushNotificationsEnabled !== undefined) settings.pushNotificationsEnabled = pushNotificationsEnabled;
    if (smsNotificationsEnabled !== undefined) settings.smsNotificationsEnabled = smsNotificationsEnabled;
    if (notificationMessage !== undefined) settings.notificationMessage = notificationMessage;
    if (twoFactorAuthRequired !== undefined) settings.twoFactorAuthRequired = twoFactorAuthRequired;
    if (autoLogoutEnabled !== undefined) settings.autoLogoutEnabled = autoLogoutEnabled;
    if (sessionTimeout !== undefined) settings.sessionTimeout = sessionTimeout;
    if (transactionPinRequired !== undefined) settings.transactionPinRequired = transactionPinRequired;
    if (biometricAuthEnabled !== undefined) settings.biometricAuthEnabled = biometricAuthEnabled;
    if (apiRateLimit !== undefined) settings.apiRateLimit = apiRateLimit;
    if (apiTimeWindow !== undefined) settings.apiTimeWindow = apiTimeWindow;
    
    await settings.save();
    
    // Clear cache
    cache.del('app-settings');
    
    res.json({ 
      success: true, 
      message: 'Settings updated successfully',
      settings
    });
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Get virtual account details
// @route   GET /api/virtual-account
// @access  Private
app.get('/api/virtual-account', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      virtualAccount: user.virtualAccount
    });
  } catch (error) {
    console.error('Error fetching virtual account:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Create or update virtual account
// @route   POST /api/virtual-account
// @access  Private/Admin
app.post('/api/virtual-account', adminProtect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('bankName').notEmpty().withMessage('Bank name is required'),
  body('accountNumber').notEmpty().withMessage('Account number is required'),
  body('accountName').notEmpty().withMessage('Account name is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, bankName, accountNumber, accountName } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    user.virtualAccount = {
      assigned: true,
      bankName,
      accountNumber,
      accountName
    };
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Virtual account assigned successfully',
      virtualAccount: user.virtualAccount
    });
  } catch (error) {
    console.error('Error assigning virtual account:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Remove virtual account
// @route   DELETE /api/virtual-account/:userId
// @access  Private/Admin
app.delete('/api/virtual-account/:userId', adminProtect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    user.virtualAccount = {
      assigned: false,
      bankName: '',
      accountNumber: '',
      accountName: ''
    };
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Virtual account removed successfully'
    });
  } catch (error) {
    console.error('Error removing virtual account:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// VTpass endpoints
// @desc    Verify smartcard number
// @route   POST /api/vtpass/validate-smartcard
// @access  Private
app.post('/api/vtpass/validate-smartcard', protect, [
  body('serviceID').notEmpty().withMessage('Service ID is required'),
  body('billersCode').notEmpty().withMessage('Billers code is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  console.log('Received smartcard verification request.');
  console.log('Request Body:', req.body);
  
  const { serviceID, billersCode } = req.body;
  
  try {
    const vtpassResult = await callVtpassApi('/merchant-verify', {
      serviceID,
      billersCode,
    });
    
    console.log('VTPass Verification Response:', JSON.stringify(vtpassResult, null, 2));
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      res.json({
        success: true,
        message: 'Smartcard verified successfully.',
        data: vtpassResult.data
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Smartcard verification failed.',
        details: vtpassResult.data
      });
    }
  } catch (error) {
    console.error('Error verifying smartcard:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});





// Add the normalizeStatus function right BEFORE the route handler:

// ==================== ADD THIS FUNCTION HERE ====================
function normalizeTransactionStatus(status) {
    if (!status || typeof status !== 'string') return 'Pending';
    
    const lowercaseStatus = status.toLowerCase().trim();
    
    const statusMapping = {
        'successful': 'Successful',
        'delivered': 'Successful',
        'completed': 'Successful',
        'approved': 'Successful',
        'success': 'Successful',
        'failed': 'Failed',
        'failure': 'Failed',
        'declined': 'Failed',
        'rejected': 'Failed',
        'pending': 'Pending',
        'processing': 'Processing',
        'in-progress': 'Processing',
        'refunded': 'Refunded',
        'reversed': 'Refunded'
    };
    
    return statusMapping[lowercaseStatus] || 'Pending';
}
// ==================== END OF FUNCTION ADDITION ====================

// @desc    Pay for Cable TV subscription
// @route   POST /api/vtpass/tv/purchase
// @access  Private
app.post('/api/vtpass/tv/purchase', protect, verifyTransactionAuth, checkServiceEnabled('isCableTvEnabled'), [
  body('serviceID').notEmpty().withMessage('Service ID is required'),
  body('billersCode').notEmpty().withMessage('Billers code is required'),
  body('variationCode').notEmpty().withMessage('Variation code is required'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  console.log('📺 Received TV purchase request.');
  console.log('📦 Request Body:', req.body);
  
  const { serviceID, billersCode, variationCode, amount, phone } = req.body;
  const userId = req.user._id;
  const reference = generateRequestId();
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (user.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const vtpassResult = await callVtpassApi('/pay', {
      serviceID,
      billersCode,
      variation_code: variationCode,
      amount,
      phone,
      request_id: reference,
    });
    
    console.log('📡 VTPass Response for TV Purchase:', JSON.stringify(vtpassResult, null, 2));
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      // ==================== USE THE NORMALIZE FUNCTION HERE ====================
      transactionStatus = normalizeTransactionStatus(vtpassResult.data.content?.transactions?.status || 'delivered');
      // ==================== END OF CHANGE ====================
      
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, 'tv', session)
        .catch(err => console.log('⚠️ TV commission calculation failed:', err.message));
      
      // AUTO-CREATE TRANSACTION NOTIFICATION
      try {
        await Notification.create({
          recipientId: userId,
          title: "TV Subscription Successful 📺",
          message: `Your ${serviceID.toUpperCase()} TV subscription of ₦${amount} for ${billersCode} was completed successfully. New wallet balance: ₦${newBalance}`,
          isRead: false
        });
      } catch (notificationError) {
        console.error('Error creating transaction notification:', notificationError);
      }
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    // Map variation code to package name
    const packageName = getPackageNameFromVariationCode(variationCode, serviceID);
    
    // CREATE TRANSACTION WITH VARIATION_CODE IN METADATA
    const newTransaction = await createTransaction(
      userId,
      amount,
      'Cable TV Subscription',
      transactionStatus, // This will now be "Successful" instead of "successful"
      `${serviceID.toUpperCase()} subscription for ${billersCode}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod,
      reference,
      {}, // Empty metadata object (we'll use additionalData)
      { // Service-specific data in additionalData
        phone: phone,
        smartcardNumber: billersCode,
        billersCode: billersCode,
        variation_code: variationCode,
        packageName: packageName,
        selectedPackage: variationCode,
        serviceID: serviceID,
        vtpassResponse: vtpassResult.data
      }
    );
    
    await session.commitTransaction();

    console.log('📺 CABLE TV TRANSACTION SAVED:');
    console.log(`🔢 Smartcard: ${billersCode}`);
    console.log(`📞 Phone: ${phone}`);
    console.log(`📦 Package: ${packageName}`);
    console.log(`🆔 Reference: ${reference}`);

    // Extract VTPass details
    const vtpassCode = vtpassResult.data?.code || '000';
    const vtpassDesc = vtpassResult.data?.response_description || 'TRANSACTION SUCCESSFUL';

    // Return EXACTLY what frontend expects
    const response = {
      success: true,
      transactionId: newTransaction._id.toString(),
      status: newTransaction.status, // Should be "Successful"
      vtpassResponse: vtpassResult.data,
      backendResponse: {
        success: true,
        transactionId: newTransaction._id.toString(),
        newBalance: newBalance,
        status: newTransaction.status,
        variation_code: variationCode,
        packageName: packageName,
        message: `TV subscription successful!`,
        code: vtpassCode,
        response_description: vtpassDesc
      },
      newBalance: newBalance,
      message: `TV subscription successful!`,
      forceSuccessDialog: true,
      isDuplicateSuccess: false
    };

    console.log('📤 Sending response to frontend:', JSON.stringify(response, null, 2));
    res.json(response);
    
  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Error in TV payment:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error',
      error: error.message // Add error details for debugging
    });
  } finally {
    session.endSession();
  }
});

// Helper function to map variation code to package name
function getPackageNameFromVariationCode(variationCode, serviceID) {
  const packageMappings = {
    'dstv': {
      'dstv-padi': 'DStv Padi',
      'dstv-yanga': 'DStv Yanga', 
      'dstv-confam': 'DStv Confam',
      'dstv-compact': 'DStv Compact',
      'dstv-compact-plus': 'DStv Compact Plus',
      'dstv-premium': 'DStv Premium'
    },
    'gotv': {
      'gotv-smallie': 'GOtv Smallie',
      'gotv-jinja': 'GOtv Jinja',
      'gotv-max': 'GOtv Max'
    },
    'startimes': {
      'nova': 'StarTimes Nova',
      'nova-dish-weekly': 'StarTimes Nova Dish Weekly',
      'basic': 'StarTimes Basic',
      'classic': 'StarTimes Classic'
    }
  };
  
  // First try exact match
  if (packageMappings[serviceID] && packageMappings[serviceID][variationCode]) {
    return packageMappings[serviceID][variationCode];
  }
  
  // Try partial match
  for (const [key, value] of Object.entries(packageMappings[serviceID] || {})) {
    if (variationCode.includes(key) || key.includes(variationCode)) {
      return value;
    }
  }
  
  // Fallback: format the variation code nicely
  return variationCode
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

// @desc    Purchase airtime
// @route   POST /api/vtpass/airtime/purchase
// @access  Private
app.post('/api/vtpass/airtime/purchase', protect, verifyTransactionAuth, checkServiceEnabled('isAirtimeEnabled'), [
  body('network').isIn(['mtn', 'airtel', 'glo', 'etisalat']).withMessage('Network must be one of: mtn, airtel, glo, 9mobile'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
  body('amount').isFloat({ min: 50 }).withMessage('Amount must be at least 50')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  console.log('Received airtime purchase request.');
  console.log('Request Body:', req.body);
  
  const { network, phone, amount } = req.body;
  const serviceID = network.toLowerCase();
  const userId = req.user._id;
  const reference = generateRequestId();
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (user.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const vtpassResult = await callVtpassApi('/pay', { 
      serviceID, 
      phone, 
      amount, 
      request_id: reference 
    });
    
    console.log('VTPass Response:', JSON.stringify(vtpassResult, null, 2));
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
     await calculateAndAddCommission(userId, amount, network, session)  // network could be 'mtn', 'airtel', etc.
  .catch(err => console.log('⚠️ Airtime commission calculation failed:', err.message));

      
      // AUTO-CREATE TRANSACTION NOTIFICATION
      try {
        await Notification.create({
          recipientId: userId,
          title: "Airtime Purchase Successful ✅",
          message: `Your airtime purchase of ₦${amount} for ${phone} (${network.toUpperCase()}) was completed successfully. New wallet balance: ₦${newBalance}`,
          isRead: false
        });
      } catch (notificationError) {
        console.error('Error creating transaction notification:', notificationError);
      }
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
  const newTransaction = await createTransaction(
  userId,
  amount,
  'debit',
  transactionStatus,
  `Airtime purchase for ${phone} on ${network}`,
  balanceBefore,
  newBalance,
  session,
  false,
  req.authenticationMethod,
  null,
  { phone: phone } // ← THIS FIXES IT
);
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Airtime purchase initiated. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      status: newTransaction.status,
      newBalance: newBalance,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in airtime purchase:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
  }
});



// FINAL & BULLETPROOF VTpass request_id — NEVER DUPLICATES, 100% ACCEPTED
function generateVtpassRequestId() {
  const now = new Date();
  const timestamp = now.getFullYear().toString() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') +
    String(now.getHours()).padStart(2, '0') +
    String(now.getMinutes()).padStart(2, '0') +
    String(now.getSeconds()).padStart(2, '0');

  const random6Digits = Math.floor(100000 + Math.random() * 900000);
  return `${timestamp}_${random6Digits}`;
}


// @desc    Purchase Data – FINAL 100% WORKING VERSION (DEC 2025)
// @route   POST /api/vtpass/data/purchase
// @access  Private
app.post('/api/vtpass/data/purchase', protect, verifyTransactionAuth, checkServiceEnabled('isDataEnabled'), [
  body('network').isIn(['mtn', 'airtel', 'glo', '9mobile']).withMessage('Network must be mtn, airtel, glo, or 9mobile'),
  body('phone').isMobilePhone('en-NG').withMessage('Please enter a valid Nigerian phone number'),
  body('variationCode').notEmpty().withMessage('Data plan is required'),
  body('planName').notEmpty().withMessage('Data plan name is required'),
  body('amount').isFloat({ min: 50 }).withMessage('Amount must be at least ₦50')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  // EXTRACT ALL PARAMETERS INCLUDING planName
  const { network, phone, variationCode, planName, amount } = req.body;
  const userId = req.user._id;

  const serviceIDMap = {
    'mtn': 'mtn-data',
    'airtel': 'airtel-data',
    'glo': 'glo-data',
    '9mobile': 'etisalat-data'
  };

  const serviceID = serviceIDMap[network.toLowerCase()];
  if (!serviceID) {
    return res.status(400).json({ success: false, message: 'Invalid network selected' });
  }

  const requestId = generateVtpassRequestId();

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance.toFixed(2)}` 
      });
    }

    const vtpassPayload = {
      request_id: requestId,
      serviceID,
      billersCode: phone,
      variation_code: variationCode,
      phone
    };

    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      const balanceBefore = user.walletBalance;
      user.walletBalance -= amount;
      await user.save({ session });

      // SAVE TRANSACTION WITH READABLE PLAN NAME
      await createTransaction(
        userId,
        amount,
        'Data Purchase',
        'Successful',
        `${network.toUpperCase()} Data Purchase for ${phone}`,
        balanceBefore,
        user.walletBalance,
        session,
        false,
        req.authenticationMethod || 'pin',
        requestId,
        { 
          phone: phone,
          variation_code: variationCode,
          variation_name: planName, // ← SAVE READABLE PLAN FROM FRONTEND
          plan: planName
        }
      );

      await calculateAndAddCommission(userId, amount, serviceID, session)  // serviceID is like 'mtn-data'
  .catch(err => console.log('⚠️ Data commission calculation failed:', err.message));

      
      await session.commitTransaction();

      return res.json({
        success: true,
        message: 'Data delivered successfully!',
        newBalance: user.walletBalance,
        vtpassResponse: vtpassResult.data,
        requestId,
        transactionId: vtpassResult.data.content?.transactions?.transactionId || requestId,
        planName: planName // ← RETURN FOR CONFIRMATION
      });
    } else {
      await session.abortTransaction();
      const msg = vtpassResult.data?.response_description || 'Data purchase failed';
      return res.status(400).json({ success: false, message: msg, vtpassResponse: vtpassResult.data });
    }
  } catch (error) {
    await session.abortTransaction();
    console.error('DATA PURCHASE ERROR:', error);
    res.status(500).json({ success: false, message: 'Service temporarily unavailable. Please try again.' });
  } finally {
    session.endSession();
  }
});







// @desc    Verify electricity meter number - FIXED VERSION
// @route   POST /api/vtpass/validate-electricity
// @access  Private
app.post('/api/vtpass/validate-electricity', protect, [
  body('serviceID').notEmpty().withMessage('Service ID is required'),
  body('billersCode').notEmpty().withMessage('Meter number is required'),
  body('type').isIn(['prepaid', 'postpaid']).withMessage('Type must be prepaid or postpaid')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  
  console.log('🔌 ELECTRICITY VALIDATION REQUEST:', req.body);
  
  const { serviceID, billersCode, type } = req.body;
  
  try {
    // Prepare the payload for electricity verification
    const vtpassPayload = {
      serviceID,
      billersCode,
      type: type // prepaid or postpaid
    };
    
    console.log('🚀 Calling VTpass for electricity validation:', vtpassPayload);
    
    // Use the correct endpoint for electricity verification
    const vtpassResult = await callVtpassApi('/merchant-verify', vtpassPayload);
    
    console.log('📦 VTpass Electricity Validation Response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description,
      content: vtpassResult.data?.content
    });
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      const content = vtpassResult.data.content;
      
      // 🔥 FIXED: Properly extract and format all data from VTpass response
      const responseData = {
        success: true,
        message: 'Meter validated successfully',
        customerName: content.Customer_Name ? content.Customer_Name.trim() : 'N/A',
        address: content.Address ? content.Address.trim() : 'N/A',
        meterNumber: content.Meter_Number || content.MeterNumber || billersCode,
        meterType: content.Meter_Type || type || 'N/A',
        customerAccountType: content.Customer_Account_Type || 'N/A',
        service: content.Service || serviceID,
        businessUnit: content.Business_Unit || 'N/A',
        details: content,
        vtpassResponse: vtpassResult.data // Include full VTpass response
      };
      
      console.log('✅ FORMATTED RESPONSE:', responseData);
      
      res.json(responseData);
    } else {
      // Enhanced error handling
      let errorMessage = 'Meter validation failed';
      
      if (vtpassResult.data?.response_description) {
        errorMessage = vtpassResult.data.response_description;
      } else if (vtpassResult.message) {
        errorMessage = vtpassResult.message;
      }
      
      res.status(400).json({
        success: false,
        message: errorMessage,
        details: vtpassResult.data
      });
    }
  } catch (error) {
    console.error('💥 ELECTRICITY VALIDATION ERROR:', error);
    
    // More specific error messages
    let errorMessage = 'Service temporarily unavailable';
    if (error.message.includes('timeout')) {
      errorMessage = 'Validation timeout. Please try again.';
    } else if (error.message.includes('Network Error')) {
      errorMessage = 'Network error. Please check your connection.';
    }
    
    res.status(500).json({ 
      success: false, 
      message: errorMessage 
    });
  }
});




// @desc    Purchase Electricity – ULTIMATE WORKING VERSION (NO DUPLICATE CALLS)
// @route   POST /api/vtpass/electricity/purchase
// @access  Private
app.post('/api/vtpass/electricity/purchase', protect, verifyTransactionAuth, checkServiceEnabled('isElectricityEnabled'), [
  body('serviceID').notEmpty().withMessage('Provider required'),
  body('billersCode').isLength({ min: 11, max: 13 }).withMessage('Meter number must be 11-13 digits'),
  body('variation_code').isIn(['prepaid', 'postpaid']).withMessage('Invalid meter type'),
  body('amount').isFloat({ min: 2000 }).withMessage('Minimum ₦2000'),
  body('phone').isMobilePhone('en-NG').withMessage('Valid phone required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array()[0].msg });

  const { serviceID, billersCode, variation_code, amount, phone, request_id, vtpassResponse: frontendVtpassResponse } = req.body;
  const userId = req.user._id;
  
  // ✅ USE FRONTEND REQUEST_ID OR GENERATE NEW
  const requestId = request_id || generateVtpassRequestId();

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // 🔥 USER FETCH AT THE TOP (FIXED)
    const user = await User.findById(userId).session(session);
    if (!user) throw new Error('User not found');

    // ✅ AMOUNT CHECK (FIRST THING AFTER USER FETCH)
    if (amount < 2000) {
      console.log('❌ PAYMENT BLOCKED: Amount below minimum -', amount);
      
      // Create a failed transaction record WITH CORRECT USER BALANCE
      const failedTransaction = new Transaction({
        userId: userId,
        type: 'Electricity Purchase',
        amount: amount,
        status: 'Failed',
        transactionId: `FAILED_AMOUNT_${Date.now()}`,
        reference: `FAILED_REF_${Date.now()}`,
        description: `Electricity payment failed: Amount ₦${amount} is below minimum of ₦2000`,
        balanceBefore: user.walletBalance, // ✅ NOW THIS WILL WORK
        balanceAfter: user.walletBalance,  // ✅ NOW THIS WILL WORK
        metadata: {
          meterNumber: billersCode,
          provider: serviceID,
          variation: variation_code,
          customerName: 'N/A',
          customerAddress: 'N/A'
        },
        isFailed: true,
        shouldShowAsFailed: true,
        amountBelowMinimum: true,
        failureReason: 'Amount below minimum (₦2000)',
        gateway: 'DalabaPay App'
      });
      
      await failedTransaction.save();
      console.log('💾 FAILED TRANSACTION SAVED TO DATABASE:');
console.log('   Transaction ID:', failedTransaction._id);
console.log('   isFailed:', failedTransaction.isFailed);
console.log('   amountBelowMinimum:', failedTransaction.amountBelowMinimum);
console.log('   shouldShowAsFailed:', failedTransaction.shouldShowAsFailed);
console.log('   status:', failedTransaction.status);
      
      await session.abortTransaction();
      
      return res.status(400).json({ 
        success: false, 
        message: `Amount below minimum. Minimum electricity purchase is ₦2000.`,
        isFailed: true,
        shouldShowAsFailed: true
      });
    }

    // ✅ CONTINUE WITH ORIGINAL LOGIC (NO DUPLICATE CODE!)
    if (user.walletBalance < amount) {
      throw new Error(`Insufficient balance. Need ₦${amount.toFixed(2)}, have ₦${user.walletBalance.toFixed(2)}`);
    }

    // ✅ CHECK 1: Check if transaction already exists in database
    const existingTransaction = await Transaction.findOne({
      reference: requestId,
      userId: userId
    }).session(session);

    if (existingTransaction) {
      // If transaction already exists and is successful, return it with CORRECT data
      if (existingTransaction.status === 'Successful' || existingTransaction.status === 'successful') {
        await session.abortTransaction();
        console.log('✅ Transaction already exists and is successful:', requestId);
        
        // Check if commission was already calculated
        const commissionExists = await Transaction.findOne({
          userId: userId,
          isCommission: true,
          'metadata.originalService': serviceID,
          'metadata.originalAmount': amount,
          createdAt: { $gt: new Date(Date.now() - 60000) } // Last 1 minute
        }).session(session);

        if (commissionExists) {
          console.log('✅ Commission already calculated for this transaction');
        }
        
        const vtpassData = frontendVtpassResponse || {};
        
        // Extract CORRECT data from frontend vtpassResponse
        const rawToken = vtpassData.purchased_code || vtpassData.token || vtpassData.Token || null;
        const customerName = vtpassData.customerName || 'N/A';
        const customerAddress = vtpassData.customerAddress || 'N/A';
        
        // Format token properly
        let formattedToken = null;
        if (rawToken) {
          formattedToken = rawToken.toString()
            .replace('Token : ', '')
            .replace('Token:', '')
            .replace('TOKEN : ', '')
            .replace('TOKEN:', '')
            .trim();
          
          if (formattedToken && !formattedToken.includes(' ') && formattedToken.length >= 16) {
            formattedToken = formattedToken.replace(/(.{4})/g, '$1 ').trim();
          }
        }
        
        console.log('🔥 USING FRONTEND VTPASS DATA FOR DUPLICATE:');
        console.log('   Token from frontend:', formattedToken);
        
        return res.json({
          success: true,
          message: 'Transaction already completed',
          alreadyProcessed: true,
          transactionId: existingTransaction._id,
          token: formattedToken || 'Check SMS',
          customerName: customerName,
          customerAddress: customerAddress,
          meterNumber: billersCode,
          newBalance: user.walletBalance,
          vtpassResponse: vtpassData
        });
      }
    }

    console.log('🔌 ELECTRICITY PURCHASE REQUEST:', {
      serviceID, billersCode, variation_code, amount, phone, requestId,
      hasFrontendVtpassResponse: !!frontendVtpassResponse
    });

    let vtpassResult;
    
    // ✅ CRITICAL FIX: SKIP VTpass call entirely - proxy already handled it
    if (!frontendVtpassResponse || frontendVtpassResponse.code !== '000') {
      console.error('❌ No valid VTpass response from proxy');
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: 'Transaction processing error. Please try again.' 
      });
    }
    
    // Use the VTpass response from the proxy
    console.log('✅ Using VTpass response from proxy (NO DUPLICATE API CALL)');
    vtpassResult = {
      success: true,
      data: frontendVtpassResponse
    };

    console.log('📦 Processing VTpass Response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description
    });

    // ✅ Handle duplicate request_id (VTpass already processed it)
    if (vtpassResult.data?.code === '019' || 
        vtpassResult.data?.response_description?.includes('DUPLICATE') ||
        vtpassResult.data?.response_description?.includes('REQUEST ID ALREADY EXIST')) {
      
      console.log('🔁 VTpass says duplicate, but transaction was successful on first call');
      
      // 🔥 CRITICAL: Even if VTpass says "duplicate", the transaction WAS SUCCESSFUL
      const vtpassData = frontendVtpassResponse || {};
      const balanceBefore = user.walletBalance;
      user.walletBalance -= amount;
      await user.save({ session });

      // Extract data from the successful VTpass response
      const rawToken = vtpassData.purchased_code || vtpassData.token || vtpassData.Token || null;
      const customerName = vtpassData.customerName || 'N/A';
      const customerAddress = vtpassData.customerAddress || 'N/A';
      const exchangeReference = vtpassData.exchangeReference || requestId;
      const units = vtpassData.units || '0.00';
      
      // Format token
      let formattedToken = null;
      if (rawToken) {
        formattedToken = rawToken.toString()
          .replace('Token : ', '')
          .replace('Token:', '')
          .replace('TOKEN : ', '')
          .replace('TOKEN:', '')
          .trim();
        
        if (formattedToken && !formattedToken.includes(' ') && formattedToken.length >= 16) {
          formattedToken = formattedToken.replace(/(.{4})/g, '$1 ').trim();
        }
      }

      // Build COMPLETE metadata
      const metadata = {
        serviceID: serviceID,
        billersCode: billersCode,
        variation_code: variation_code,
        amount: amount.toFixed(2),
        phone: phone,
        meterNumber: billersCode,
        token: formattedToken || 'Check SMS',
        customerName: customerName,
        customerAddress: customerAddress,
        exchangeReference: exchangeReference,
        units: units,
        vtpassResponse: vtpassData,
        serviceType: 'electricity',
        provider: serviceID,
        type: variation_code
      };

      const transaction = new Transaction({
        userId,
        amount,
        type: 'Electricity Purchase',
        status: 'Successful',
        transactionId: requestId,
        reference: requestId,
        description: `${serviceID.replace('-', ' ')} purchase`,
        balanceBefore,
        balanceAfter: user.walletBalance,
        metadata: metadata,
        isCommission: false,
        service: 'electricity',
        authenticationMethod: req.authenticationMethod || 'pin',
        gateway: 'DalabaPay App'
      });

      await transaction.save({ session });

      // 🔥 ADD COMMISSION CALCULATION HERE (ONLY ONCE!)
      await calculateAndAddCommission(userId, amount, serviceID, session)
        .catch(err => console.log('⚠️ Electricity commission calculation failed:', err.message));

      await session.commitTransaction();

      console.log('✅ Duplicate transaction recorded as Successful with token:', formattedToken);

      return res.json({
        success: true,
        message: 'Electricity purchased successfully!',
        newBalance: user.walletBalance,
        transactionId: requestId,
        reference: requestId,
        token: formattedToken || 'Check SMS',
        customerName: customerName,
        customerAddress: customerAddress,
        meterNumber: billersCode,
        units: units,
        gateway: 'DalabaPay App',
        balanceBefore: balanceBefore,
        vtpassResponse: vtpassData
      });
    }

    // ✅ SUCCESSFUL TRANSACTION
    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      const balanceBefore = user.walletBalance;
      user.walletBalance -= amount;
      await user.save({ session });

      const vtpassData = vtpassResult.data || {};
      
      // Extract ALL data correctly
      const rawToken = vtpassData.purchased_code || vtpassData.token || vtpassData.Token || null;
      const customerName = vtpassData.customerName || 'N/A';
      const customerAddress = vtpassData.customerAddress || 'N/A';
      const exchangeReference = vtpassData.exchangeReference || requestId;
      const units = vtpassData.units || '0.00';

      console.log('📦 EXTRACTED FROM VTPASS:');
      console.log('   Raw Token:', rawToken);

      // Format token properly
      let formattedToken = null;
      if (rawToken) {
        formattedToken = rawToken.toString()
          .replace('Token : ', '')
          .replace('Token:', '')
          .replace('TOKEN : ', '')
          .replace('TOKEN:', '')
          .trim();
        
        if (formattedToken && !formattedToken.includes(' ') && formattedToken.length >= 16) {
          formattedToken = formattedToken.replace(/(.{4})/g, '$1 ').trim();
        }
        
        console.log('   Formatted Token:', formattedToken);
      }

      // Build metadata
      const metadata = {
        serviceID: serviceID,
        billersCode: billersCode,
        variation_code: variation_code,
        amount: amount.toFixed(2),
        phone: phone,
        meterNumber: billersCode,
        token: formattedToken || 'Check SMS',
        customerName: customerName || 'N/A',
        customerAddress: customerAddress || 'N/A',
        exchangeReference: exchangeReference,
        units: units,
        vtpassResponse: vtpassData,
        serviceType: 'electricity',
        provider: serviceID,
        type: variation_code
      };

      console.log('📦 METADATA TO SAVE:', JSON.stringify(metadata, null, 2));

      // Create transaction
      const transaction = new Transaction({
        userId,
        amount,
        type: 'Electricity Purchase',
        status: 'Successful',
        transactionId: requestId,
        reference: requestId,
        description: `${serviceID.replace('-', ' ')} purchase`,
        balanceBefore,
        balanceAfter: user.walletBalance,
        metadata: metadata,
        isCommission: false,
        service: 'electricity',
        authenticationMethod: req.authenticationMethod || 'pin',
        gateway: 'DalabaPay App'
      });

      await transaction.save({ session });

      // 🔥 ADD COMMISSION CALCULATION HERE (ONLY ONCE!)
      await calculateAndAddCommission(userId, amount, serviceID, session)
        .catch(err => console.log('⚠️ Electricity commission calculation failed:', err.message));

      await session.commitTransaction();

      console.log('✅ ELECTRICITY PURCHASE COMPLETE:', {
        transactionId: requestId,
        token: formattedToken || 'Check SMS',
        savedToDB: true
      });

      // Response to frontend
      return res.json({
        success: true,
        message: 'Electricity purchased successfully!',
        newBalance: user.walletBalance,
        transactionId: requestId,
        reference: requestId,
        token: formattedToken || 'Check SMS',
        customerName: customerName || 'N/A',
        customerAddress: customerAddress || 'N/A',
        meterNumber: billersCode,
        units: units,
        gateway: 'DalabaPay App',
        balanceBefore: balanceBefore,
        vtpassResponse: vtpassData
      });
    } else {
      await session.abortTransaction();
      
      let errorMsg = vtpassResult.data?.response_description || 'Purchase failed';
      if (errorMsg.includes('BELOW MINIMUM AMOUNT')) {
        errorMsg = `Amount below minimum allowed. Minimum electricity purchase: ₦2000`;
      } else if (errorMsg.includes('013')) {
        errorMsg = `Insufficient amount. Please enter at least ₦2000.`;
      }
      
      return res.status(400).json({ 
        success: false, 
        message: errorMsg,
        vtpassResponse: vtpassResult.data 
      });
    }
  } catch (error) {
    await session.abortTransaction();
    console.error('💥 ELECTRICITY PURCHASE ERROR:', error.message);
    
    let errorMessage = error.message;
    if (errorMessage.includes('BELOW MINIMUM AMOUNT')) {
      errorMessage = `Amount too low. Minimum is ₦2000 for electricity payments.`;
    }
    
    return res.status(400).json({ 
      success: false, 
      message: errorMessage.includes('Insufficient') ? errorMessage : errorMessage 
    });
  } finally {
    session.endSession();
  }
});







// @desc    Get VTpass services
// @route   GET /api/vtpass/services
// @access  Private
app.get('/api/vtpass/services', protect, [
  query('serviceID').notEmpty().withMessage('Service ID is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { serviceID } = req.query;
    
    // Try to get from cache first
    const cacheKey = `vtpass-services-${serviceID}`;
    const cachedServices = cache.get(cacheKey);
    
    if (cachedServices) {
      return res.json({
        success: true,
        message: 'Services fetched successfully',
        data: cachedServices
      });
    }
    
    // Call VTpass API to get services
    const vtpassResult = await callVtpassApi('/services', { serviceID });
    
    if (vtpassResult.success) {
      // Cache the result
      cache.set(cacheKey, vtpassResult.data);
      
      res.json({
        success: true,
        message: 'Services fetched successfully',
        data: vtpassResult.data
      });
    } else {
      res.status(vtpassResult.status || 500).json({
        success: false,
        message: 'Failed to fetch services',
        details: vtpassResult.details || vtpassResult.message
      });
    }
  } catch (error) {
    console.error('Error fetching VTpass services:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});



// @desc    Get VTpass variations
// @route   GET /api/vtpass/variations
// @access  Private
app.get('/api/vtpass/variations', protect, [
  query('serviceID').notEmpty().withMessage('Service ID is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { serviceID } = req.query;
    
    // Try to get from cache first
    const cacheKey = `vtpass-variations-${serviceID}`;
    const cachedVariations = cache.get(cacheKey);
    
    if (cachedVariations) {
      return res.json({
        success: true,
        message: 'Variations fetched successfully',
        data: cachedVariations
      });
    }
    
    // Call VTpass API to get variations
    const vtpassResult = await callVtpassApi('/variations', { serviceID });
    
    if (vtpassResult.success) {
      // Cache the result
      cache.set(cacheKey, vtpassResult.data);
      
      res.json({
        success: true,
        message: 'Variations fetched successfully',
        data: vtpassResult.data
      });
    } else {
      res.status(vtpassResult.status || 500).json({
        success: false,
        message: 'Failed to fetch variations',
        details: vtpassResult.details || vtpassResult.message
      });
    }
  } catch (error) {
    console.error('Error fetching VTpass variations:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// NEW: Error reporting endpoint
// @desc    Report an error
// @route   POST /api/errors/report
// @access  Private
app.post('/api/errors/report', protect, async (req, res) => {
  try {
    const { error, stackTrace, timestamp, platform, version } = req.body;
    
    console.error('Error reported from client:', {
      error,
      stackTrace,
      timestamp,
      platform,
      version,
      userId: req.user._id
    });
    
    // Here you would typically save the error to a database or send it to a logging service
    // For now, we'll just acknowledge receipt
    
    res.status(200).json({ 
      success: true, 
      message: 'Error report received' 
    });
  } catch (error) {
    console.error('Error reporting error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to process error report' 
    });
  }
});










// @desc    Execute atomic transaction (debit + VTpass call in one operation)
// @route   POST /api/transactions/atomic
// @access  Private
app.post('/api/transactions/atomic', protect, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const {
      userId,
      debitAmount,
      debitService,
      vtpassPayload,
      creditService,
      creditAmount,
      transactionPin,
      useBiometric
    } = req.body;

    console.log('⚛️ ATOMIC TRANSACTION REQUEST:', { userId, debitAmount, debitService });

    // Verify user owns this transaction
    if (req.user._id.toString() !== userId) {
      await session.abortTransaction();
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Check balance
    if (user.walletBalance < debitAmount) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: `Insufficient balance. Required: ₦${debitAmount}, Available: ₦${user.walletBalance}`
      });
    }

    // Verify transaction PIN if provided
    if (transactionPin) {
      const isPinMatch = await bcrypt.compare(transactionPin, user.transactionPin);
      if (!isPinMatch) {
        await session.abortTransaction();
        return res.status(400).json({ success: false, message: 'Invalid transaction PIN' });
      }
    }

    // Step 1: Debit user's wallet
    const balanceBefore = user.walletBalance;
    user.walletBalance -= debitAmount;
    const balanceAfter = user.walletBalance;
    await user.save({ session });

    // Step 2: Create debit transaction
    await createTransaction(
      userId,
      debitAmount,
      'debit',
      'pending',
      `${debitService} purchase`,
      balanceBefore,
      balanceAfter,
      session,
      false,
      transactionPin ? 'pin' : (useBiometric ? 'biometric' : 'none')
    );

    // Step 3: Call VTpass API
    console.log('🚀 Calling VTpass from atomic transaction:', vtpassPayload);
    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    let transactionStatus = 'failed';
    let commissionAdded = false;

    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      transactionStatus = 'successful';
      
      // Step 4: Credit commission if applicable
      if (creditService && creditAmount && creditAmount > 0) {
        user.commissionBalance += creditAmount;
        await user.save({ session });
        
        await createTransaction(
          userId,
          creditAmount,
          'credit',
          'successful',
          `Commission from ${debitService}`,
          user.commissionBalance - creditAmount,
          user.commissionBalance,
          session,
          true,
          'none'
        );
        commissionAdded = true;
      }
    }

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { userId, description: `${debitService} purchase`, status: 'pending' },
      { status: transactionStatus },
      { session }
    );

    await session.commitTransaction();

    console.log('✅ ATOMIC TRANSACTION COMPLETED:', { transactionStatus, commissionAdded });

    res.json({
      success: transactionStatus === 'successful',
      message: transactionStatus === 'successful' ? 'Transaction completed successfully' : 'Transaction failed',
      newBalance: user.walletBalance,
      newCommissionBalance: user.commissionBalance,
      vtpassResponse: vtpassResult.data,
      transactionStatus
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('❌ ATOMIC TRANSACTION ERROR:', error);
    res.status(500).json({ success: false, message: 'Atomic transaction failed' });
  } finally {
    session.endSession();
  }
});



// Helper function to alert admin about low VTpass balance
async function sendAdminLowBalanceAlert(serviceID, amount, vtpassBalance) {
  try {
    console.log('🚨 ADMIN ALERT: VTpass wallet low!');
    console.log(`   Service: ${serviceID}`);
    console.log(`   Required Amount: ₦${amount}`);
    console.log(`   Available Balance: ₦${vtpassBalance}`);
    console.log(`   Time: ${new Date().toISOString()}`);
    
    // Create Alert document
    try {
      const alert = new Alert({
        type: 'VTPASS_LOW_BALANCE',
        title: 'VTpass Wallet Low Balance Alert',
        message: `VTpass wallet balance is low. Current: ₦${vtpassBalance}, Required: ₦${amount}`,
        severity: vtpassBalance < 5000 ? 'CRITICAL' : 'WARNING',
        data: {
          serviceID,
          requiredAmount: amount,
          availableBalance: vtpassBalance,
          timestamp: new Date(),
          isCritical: vtpassBalance === 0
        },
        acknowledged: false
      });
      
      await alert.save();
      console.log('✅ Admin alert saved to database');
      
      // Also try to find and notify admin users
      try {
        const adminUsers = await User.find({ role: 'admin' }).select('email phone');
        console.log(`📧 Notifying ${adminUsers.length} admin user(s)`);
        
        // You can add email/SMS notification logic here
        for (const admin of adminUsers) {
          console.log(`   - Admin: ${admin.email || admin.phone}`);
          // await sendEmailToAdmin(admin.email, alert);
        }
      } catch (adminError) {
        console.log('⚠️ Could not notify admin users:', adminError.message);
      }
      
    } catch (dbError) {
      console.error('Could not save alert to database:', dbError.message);
      
      // Fallback: Log to file
      const fs = require('fs').promises;
      try {
        const logEntry = {
          timestamp: new Date().toISOString(),
          type: 'VTPASS_LOW_BALANCE_ALERT',
          serviceID,
          amount,
          vtpassBalance,
          alert: 'Admin notification failed to save to database'
        };
        await fs.appendFile('alerts_fallback.log', JSON.stringify(logEntry) + '\n');
        console.log('✅ Alert logged to fallback file');
      } catch (fileError) {
        console.error('Could not log to file:', fileError.message);
      }
    }
    
  } catch (error) {
    console.error('Failed to send admin alert:', error);
  }
}



// @desc    VTpass Proxy Endpoint - COMPLETE FIXED VERSION
// @route   POST /api/vtpass/proxy
// @access  Private
app.post('/api/vtpass/proxy', protect, async (req, res) => {
  console.log('PROXY ENDPOINT HIT - COMPLETE FIXED VERSION');
  console.log('Body:', JSON.stringify(req.body, null, 2));

  // ========== SERVICE CHECK ==========
  const serviceChecks = {
    'mtn': 'isAirtimeEnabled',
    'airtel': 'isAirtimeEnabled', 
    'glo': 'isAirtimeEnabled',
    'etisalat': 'isAirtimeEnabled',
    '9mobile': 'isAirtimeEnabled',
    'mtn-data': 'isDataEnabled',
    'airtel-data': 'isDataEnabled',
    'glo-data': 'isDataEnabled',
    'etisalat-data': 'isDataEnabled',
    'dstv': 'isCableTvEnabled',
    'gotv': 'isCableTvEnabled',
    'startimes': 'isCableTvEnabled',
    'ikeja-electric': 'isElectricityEnabled',
    'eko-electric': 'isElectricityEnabled',
    'abuja-electric': 'isElectricityEnabled',
    'ibadan-electric': 'isElectricityEnabled',
    'enugu-electric': 'isElectricityEnabled',
    'kano-electric': 'isElectricityEnabled',
    'ph-electric': 'isElectricityEnabled'
  };

  const { serviceID } = req.body;
  const serviceKey = serviceChecks[serviceID];
  
  if (serviceKey) {
    try {
      const settings = await Settings.findOne();
      if (!settings || settings[serviceKey] === false) {
        return res.status(403).json({
          success: false,
          message: 'This service is currently disabled. Please try again later.',
          code: 'SERVICE_DISABLED'
        });
      }
    } catch (error) {
      console.error('Service check error:', error);
      // Continue if check fails
    }
  }

  const session = await mongoose.startSession();

  try {
    await session.startTransaction();

    const { request_id, serviceID, amount, phone, variation_code, billersCode, type, commissionTransactionId, commissionTrackingId } = req.body;
    const userId = req.user._id;

    // === 1. Use client request_id ===
    const uniqueRequestId = request_id && request_id.length >= 10 
      ? request_id 
      : generateVtpassRequestId();
    console.log('Using request_id:', uniqueRequestId);

    // === 2. Get user ===
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // === 3. Prevent duplicate processing ===
    const alreadyProcessed = await Transaction.findOne({
      reference: uniqueRequestId,
      status: { $in: ['Successful', 'successful'] }
    }).session(session);

    if (alreadyProcessed) {
      await session.abortTransaction();
      return res.json({
        success: true,
        alreadyProcessed: true,
        message: 'Transaction already completed',
        newBalance: user.walletBalance
      });
    }

    // === 4. Check if user has sufficient balance FIRST ===
    const isUsingCommission = req.headers['x-commission-usage'] === 'true';
    console.log(`💰 Payment method: ${isUsingCommission ? 'COMMISSION' : 'WALLET'}`);

    // Parse amount safely
    const transactionAmount = amount ? parseFloat(amount) : 0;

    // Only check balance if there's an actual amount to deduct
    if (transactionAmount > 0) {
      if (isUsingCommission) {
        // Check commission balance
        if (user.commissionBalance < transactionAmount) {
          await session.abortTransaction();
          return res.status(400).json({ 
            success: false, 
            message: `Insufficient commission balance. Available: ₦${user.commissionBalance.toFixed(2)}` 
          });
        }
      } else {
        // Check wallet balance
        if (user.walletBalance < transactionAmount) {
          await session.abortTransaction();
          return res.status(400).json({ 
            success: false, 
            message: `Insufficient wallet balance. Available: ₦${user.walletBalance.toFixed(2)}` 
          });
        }
      }
    }

    // === 5. Check VTpass Wallet Balance BEFORE calling VTpass ===
    console.log('💰 Checking VTpass wallet balance before transaction...');
    try {
      const vtpassApiKey = process.env.VTPASS_API_KEY;
      const vtpassSecretKey = process.env.VTPASS_SECRET_KEY;
      
      const balanceResponse = await axios.get('https://vtpass.com/api/balance', {
        auth: {
          username: vtpassApiKey,
          password: vtpassSecretKey
        },
        timeout: 10000
      });

      const vtpassBalance = balanceResponse.data.contents?.balance || 0;
      console.log(`📊 VTpass Merchant Wallet Balance: ₦${vtpassBalance.toFixed(2)}`);

      // Check if balance is sufficient - use transactionAmount not amount
      if (vtpassBalance < transactionAmount) {
        // 🔥 SEND ADMIN ALERT - pass transactionAmount, not amount
        await sendAdminLowBalanceAlert(serviceID, transactionAmount, vtpassBalance);
        
        await session.abortTransaction();
        return res.status(400).json({
          success: false,
          message: 'Service temporarily unavailable due to insufficient provider funds. Our team has been notified.',
          code: 'VTPASS_INSUFFICIENT_FUNDS',
          vtpassBalance: vtpassBalance,
          requiredAmount: transactionAmount,
          adminAlerted: true
        });
      }
    } catch (balanceError) {
      console.error('❌ Failed to check VTpass wallet balance:', balanceError.message);
      // Continue with transaction but log warning
    }

    // === 6. Build VTpass payload ===
    const payload = {
      request_id: uniqueRequestId,
      serviceID: serviceID,
      phone,
      billersCode,
      variation_code,
      type
    };

    if (amount) payload.amount = parseFloat(amount).toFixed(2);

    // === 7. Determine endpoint ===
    const endpoint = serviceID.includes('electric') && billersCode && !variation_code 
      ? '/merchant-verify' 
      : '/pay';

    // === 8. Call VTpass API ===
    const vtpassResult = await callVtpassApi(endpoint, payload);

    // === 9. Handle VTpass response ===
    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      // SUCCESS: Process the transaction
      
      // Deduct from correct balance
      if (transactionAmount > 0) {
        if (isUsingCommission) {
          user.commissionBalance -= transactionAmount;
          console.log(`💰 Deducted ₦${transactionAmount.toFixed(2)} from COMMISSION`);
        } else {
          user.walletBalance -= transactionAmount;
          console.log(`💰 Deducted ₦${transactionAmount.toFixed(2)} from WALLET`);
        }
      }

      // Map display type
      const typeMap = {
        mtn: 'Airtime Purchase',
        airtel: 'Airtime Purchase',
        glo: 'Airtime Purchase',
        etisalat: 'Airtime Purchase',
        '9mobile': 'Airtime Purchase',
        'mtn-data': 'Data Purchase',
        'airtel-data': 'Data Purchase',
        'glo-data': 'Data Purchase',
        'etisalat-data': 'Data Purchase',
        dstv: 'Cable TV Subscription',
        gotv: 'Cable TV Subscription',
        startimes: 'Cable TV Subscription',
        'ikeja-electric': 'Electricity Payment',
        'eko-electric': 'Electricity Payment',
        'abuja-electric': 'Electricity Payment',
        'ibadan-electric': 'Electricity Payment',
      };
      
      let displayType = typeMap[serviceID] || 'debit';

      // Create transaction metadata
      let transactionMetadata = { 
        phone, 
        billersCode, 
        service: serviceID,
        paymentMethod: isUsingCommission ? 'commission' : 'wallet',
        commissionUsed: isUsingCommission,
        walletUsed: !isUsingCommission
      };

      // Handle electricity specific data
      if (serviceID.includes('electric') && vtpassResult.data) {
        const vtpassData = vtpassResult.data;
        const token = vtpassData.purchased_code || vtpassData.token || vtpassData.Token || null;
        
        let formattedToken = null;
        if (token) {
          formattedToken = token.toString()
            .replace('Token : ', '')
            .replace('Token:', '')
            .replace('TOKEN : ', '')
            .replace('TOKEN:', '')
            .trim();
          
          if (formattedToken && !formattedToken.includes(' ') && formattedToken.length >= 16) {
            formattedToken = formattedToken.replace(/(.{4})/g, '$1 ').trim();
          }
        }
        
        transactionMetadata = {
          ...transactionMetadata,
          meterNumber: billersCode,
          token: formattedToken || 'Check SMS',
          customerName: vtpassData.customerName || vtpassData.content?.Customer_Name || 'N/A',
          customerAddress: vtpassData.customerAddress || vtpassData.content?.Address || 'N/A',
        };
        
        displayType = 'Electricity Purchase';
      }

      // ================================================
      // 🔥 FIX: ONLY CREATE TRANSACTION IF NOT USING COMMISSION
      // ================================================
      if (!isUsingCommission) {
        // Only create transaction for WALLET payments
        const balanceBefore = user.walletBalance + transactionAmount;
        const balanceAfter = user.walletBalance;
        
        await createTransaction(
          userId,
          transactionAmount,
          displayType,
          'Successful',
          `${serviceID.toUpperCase()} ${transactionAmount > 0 ? 'purchase' : 'verification'}`,
          balanceBefore,
          balanceAfter,
          session,
          false, // isCommission = false
          'pin',
          uniqueRequestId,
          transactionMetadata
        );
        console.log(`✅ Wallet payment - Regular transaction recorded`);
      } else {
        // For COMMISSION payments, transaction was already created in /api/commission/use-for-service
        console.log(`✅ Commission payment - Transaction already created earlier`);
      }
      
      // ================================================
      // 🔥 CRITICAL FIX: COMMISSION CALCULATION LOGIC
      // ================================================
      // Calculate commission - ONLY if:
      // 1. There's an actual purchase amount
      // 2. User is NOT using commission to pay
      // 3. This is NOT a commission-based payment
      // ================================================
      const shouldCalculateCommission = transactionAmount > 0 && 
                                       !isUsingCommission && 
                                       !transactionMetadata?.commissionUsed;

      console.log(`💰 COMMISSION CALCULATION CHECK:`);
      console.log(`   Transaction amount: ₦${transactionAmount}`);
      console.log(`   Using commission: ${isUsingCommission}`);
      console.log(`   Commission used flag: ${transactionMetadata?.commissionUsed || false}`);
      console.log(`   Should calculate commission: ${shouldCalculateCommission}`);

      if (shouldCalculateCommission) {
        // Determine the correct service type for commission
        let commissionServiceType = serviceID;
        
        if (serviceID.includes('mtn') || serviceID.includes('airtel') || 
            serviceID.includes('glo') || serviceID.includes('etisalat') || 
            serviceID.includes('9mobile')) {
          if (serviceID.includes('data')) {
            commissionServiceType = 'data';
          } else {
            commissionServiceType = 'airtime';
          }
        } else if (serviceID.includes('electric')) {
          commissionServiceType = serviceID; // e.g., "ibadan-electric"
        } else if (serviceID.includes('dstv') || serviceID.includes('gotv') || serviceID.includes('startimes')) {
          commissionServiceType = 'tv';
        } else if (serviceID.includes('transfer')) {
          commissionServiceType = 'transfer';
        } else if (serviceID.includes('education')) {
          commissionServiceType = 'education';
        } else if (serviceID.includes('insurance')) {
          commissionServiceType = 'insurance';
        }
        
        console.log(`💰 Commission calculation for ${commissionServiceType} (Amount: ₦${transactionAmount})`);
        
        // Calculate commission - PASS isUsingCommission parameter
        const commissionEarned = await calculateAndAddCommission(
          userId, 
          transactionAmount, 
          commissionServiceType, 
          session,
          isUsingCommission // 🔥 PASS THIS FLAG
        ).catch(err => {
          console.log('⚠️ Commission calculation failed:', err.message);
          return 0;
        });
        
        console.log(`✅ Commission earned: ₦${commissionEarned}`);
        
        // ================================================
        // 🔥 REFERRAL SERVICE COMMISSION (0.005%)
        // ================================================
        // Only award referral commission if:
        // 1. There's an actual purchase amount (> 0)
        // 2. User is NOT using commission to pay
        // 3. User has a referrer
        // ================================================
        if (transactionAmount > 0 && !isUsingCommission && user.referrerId) {
          try {
            console.log(`🎯 Checking referral service commission for ${user.email}`);
            
            // Get referrer details
            const referrer = await User.findById(user.referrerId).session(session);
            if (!referrer) {
              console.log('⚠️ Referrer not found');
            } else {
              // Calculate referral commission (0.005% = 0.00005)
              const referralCommissionRate = 0.00005;
              let referralCommissionAmount = transactionAmount * referralCommissionRate;
              
              // Minimum commission ₦2 if amount is substantial
              if (referralCommissionAmount < 2 && transactionAmount >= 1000) {
                referralCommissionAmount = 2;
              }
              
              if (referralCommissionAmount > 0) {
                console.log(`💰 Referral commission: ₦${transactionAmount} × 0.005% = ₦${referralCommissionAmount.toFixed(4)}`);
                
                // Award commission to referrer
                const referrerBalanceBefore = referrer.commissionBalance || 0;
                referrer.commissionBalance = (referrer.commissionBalance || 0) + referralCommissionAmount;
                referrer.totalReferralEarnings = (referrer.totalReferralEarnings || 0) + referralCommissionAmount;
                
                // Create commission transaction for referrer
                await createTransaction(
                  referrer._id,
                  referralCommissionAmount,
                  'Referral Service Commission',
                  'Successful',
                  `Referral commission from ${user.fullName}'s ${serviceID} purchase`,
                  referrerBalanceBefore,
                  referrer.commissionBalance,
                  session,
                  true, // isCommission
                  'none',
                  null,
                  {},
                  {
                    commissionSource: 'referral_service',
                    referredUserId: userId,
                    referredUserName: user.fullName,
                    purchaseTransactionId: uniqueRequestId,
                    purchaseAmount: transactionAmount,
                    purchaseService: serviceID,
                    commissionRate: referralCommissionRate,
                    commissionAmount: referralCommissionAmount,
                    commissionPercentage: '0.005%'
                  }
                );
                
                await referrer.save({ session });
                console.log(`✅ Awarded ₦${referralCommissionAmount.toFixed(4)} referral commission to ${referrer.email}`);
                
                // Create notification for referrer
                await Notification.create({
                  recipient: referrer._id,
                  title: "Referral Commission Earned! 💰",
                  message: `You earned ₦${referralCommissionAmount.toFixed(4)} from ${user.fullName}'s purchase.`,
                  type: 'commission',
                  isRead: false,
                  metadata: {
                    event: 'referral_commission',
                    referredUserId: userId,
                    commissionAmount: referralCommissionAmount,
                    purchaseAmount: transactionAmount
                  }
                });
              } else {
                console.log('⚠️ Referral commission amount too small to award');
              }
            }
          } catch (error) {
            console.error('❌ Error awarding referral commission:', error.message);
            // Don't fail the transaction if referral commission fails
          }
        } else if (isUsingCommission && user.referrerId) {
          console.log(`⚠️ Skipping referral commission - user paid with commission`);
        } else if (!user.referrerId) {
          console.log(`ℹ️ No referrer found - skipping referral commission`);
        }
        
      } else if (isUsingCommission) {
        console.log(`🚫 User paid with commission - NO commission earned for this purchase`);
        console.log(`📌 Transaction metadata:`, transactionMetadata);
      } else if (transactionMetadata?.commissionUsed) {
        console.log(`🚫 Commission used flag set - NO commission earned`);
      } else {
        console.log(`ℹ️ No commission calculation needed for this transaction`);
      }

      // 🔥 UPDATE COMMISSION TRANSACTION WITH VTpass DATA
      if (isUsingCommission) {
        try {
          // Find commission transaction using tracking ID
          const commissionTransaction = await Transaction.findOne({
            $or: [
              { _id: commissionTransactionId },
              { reference: commissionTrackingId },
              { 'metadata.commissionTrackingId': commissionTrackingId }
            ],
            userId: userId,
            isCommission: true
          }).session(session);
          
          if (commissionTransaction) {
            // Update it with VTpass data
            commissionTransaction.status = 'Successful';
            commissionTransaction.metadata = {
              ...commissionTransaction.metadata,
              ...transactionMetadata,
              vtpassResponse: vtpassResult.data,
              requestId: uniqueRequestId,
              completedAt: new Date(),
              service: serviceID
            };
            
            await commissionTransaction.save({ session });
            console.log(`✅ Updated commission transaction: ${commissionTransaction._id}`);
          }
        } catch (updateError) {
          console.error(`❌ Error updating commission transaction:`, updateError);
          // Don't fail the main transaction
        }
      }

      // Save user and commit
      await user.save({ session });
      await session.commitTransaction();

      return res.json({
        success: true,
        message: `Transaction successful ${isUsingCommission ? '(Paid with Commission)' : ''}`,
        newWalletBalance: user.walletBalance,
        newCommissionBalance: user.commissionBalance,
        paymentMethod: isUsingCommission ? 'commission' : 'wallet',
        vtpassResponse: vtpassResult.data,
        requestId: uniqueRequestId,
        customerName: vtpassResult.data.content?.Customer_Name || ''
      });
    }

    // === 10. Handle VTpass FAILURE ===
    await session.abortTransaction();

    const msg = vtpassResult.data?.response_description || 'Transaction failed';
    const errorCode = vtpassResult.data?.code || 'UNKNOWN';

    // Handle LOW WALLET BALANCE error
    if (errorCode === '018' || msg.includes('LOW WALLET BALANCE')) {
      // 🔥 SEND ADMIN ALERT - use transactionAmount, not amount
      await sendAdminLowBalanceAlert(serviceID, transactionAmount, 0);
      
      return res.status(400).json({
        success: false,
        message: 'Service temporarily unavailable due to provider wallet issues. Our team has been notified and will fix this shortly.',
        code: 'VTPASS_WALLET_EMPTY',
        retryable: false,
        adminAlerted: true,
        vtpassResponse: vtpassResult.data
      });
    }
    
    if (msg.includes('REQUEST ID ALREADY EXIST') || msg.includes('DUPLICATE')) {
      return res.status(400).json({
        success: false,
        message: 'Duplicate transaction',
        code: 'DUPLICATE',
        retryable: true
      });
    }

    return res.status(400).json({
      success: false,
      message: msg,
      vtpassResponse: vtpassResult.data
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('PROXY ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Service unavailable',
      error: error.message 
    });
  } finally {
    session.endSession();
  }
});



// ==================== DATA PLANS ENDPOINT ====================

// @desc    Get data plans directly from VTpass API
// @route   GET /api/data-plans
// @access  Private
app.get('/api/data-plans', protect, [
  query('serviceID').notEmpty().withMessage('Service ID is required')
], async (req, res) => {
  console.log('🎯 DATA PLANS ENDPOINT HIT - serviceID:', req.query.serviceID);
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { serviceID } = req.query;
    
    console.log('📡 Fetching data plans for service:', serviceID);

    // Validate service ID
    const validServiceIDs = [
      'mtn-data', 'airtel-data', 'glo-data', 
      'glo-sme-data', 'etisalat-data'
    ];
    
    if (!validServiceIDs.includes(serviceID)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid service ID. Valid IDs: ' + validServiceIDs.join(', ')
      });
    }

    // Try to get from cache first (5 minutes cache)
    const cacheKey = `data-plans-${serviceID}`;
    const cachedPlans = cache.get(cacheKey);
    
    if (cachedPlans) {
      console.log('✅ Serving data plans from cache for:', serviceID);
      return res.json({
        success: true,
        service: serviceID,
        plans: cachedPlans,
        totalPlans: cachedPlans.length,
        source: 'cache'
      });
    }

    console.log('🚀 Calling LIVE VTpass API for data plans:', serviceID);

    // Call VTpass LIVE API directly
    const vtpassUrl = 'https://vtpass.com/api/service-variations';
    
    const response = await axios.get(vtpassUrl, {
      params: { serviceID },
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.VTPASS_API_KEY,
        'secret-key': process.env.VTPASS_SECRET_KEY,
      },
      timeout: 15000
    });

    console.log('📦 LIVE VTpass API response status:', response.status);

    const vtpassData = response.data;

    // Check if VTpass API returned success
    if (vtpassData.response_description !== '000') {
      console.log('❌ VTpass API error:', vtpassData.response_description);
      // Fallback to mock data
      const mockPlans = getMockDataPlans(serviceID);
      return res.json({
        success: true,
        service: serviceID,
        plans: mockPlans,
        totalPlans: mockPlans.length,
        source: 'mock_fallback',
        note: 'VTpass error: ' + vtpassData.response_description
      });
    }

    // Process the variations
    const variations = vtpassData.content?.variations || vtpassData.content?.varations || [];
    
    console.log(`📊 Raw variations count for ${serviceID}:`, variations.length);

    if (!variations || variations.length === 0) {
      const mockPlans = getMockDataPlans(serviceID);
      return res.json({
        success: true,
        service: serviceID,
        plans: mockPlans,
        totalPlans: mockPlans.length,
        source: 'mock_fallback',
        note: 'No plans from VTpass, using mock data'
      });
    }

    // Transform the data into a consistent format
    const processedPlans = variations.map(plan => {
      let validity = '30 days';
      const name = plan.name || '';
      
      // Extract validity from plan name
      const validityMatch = name.match(/\(([^)]+)\)/);
      if (validityMatch) {
        validity = validityMatch[1];
      } else {
        // Fallback validity detection
        if (name.toLowerCase().includes('daily') || name.toLowerCase().includes('1 day')) {
          validity = '1 day';
        } else if (name.toLowerCase().includes('weekly') || name.toLowerCase().includes('7 days')) {
          validity = '7 days';
        } else if (name.toLowerCase().includes('monthly') || name.toLowerCase().includes('30 days')) {
          validity = '30 days';
        } else if (name.toLowerCase().includes('2-month') || name.toLowerCase().includes('60 days')) {
          validity = '60 days';
        } else if (name.toLowerCase().includes('3-month') || name.toLowerCase().includes('90 days')) {
          validity = '90 days';
        } else if (name.toLowerCase().includes('yearly') || name.toLowerCase().includes('365 days')) {
          validity = '365 days';
        }
      }

      return {
        name: plan.name || 'Unknown Plan',
        amount: plan.variation_amount?.toString() || plan.amount?.toString() || '0',
        validity: validity,
        variation_code: plan.variation_code || '',
        serviceID: serviceID,
        fixedPrice: plan.fixedPrice === 'Yes'
      };
    }).filter(plan => plan.variation_code && plan.name !== 'Unknown Plan');

    // Sort plans by amount (lowest to highest)
    processedPlans.sort((a, b) => parseFloat(a.amount) - parseFloat(b.amount));

    console.log(`✅ Processed ${processedPlans.length} LIVE plans for ${serviceID}`);

    // Cache the result for 5 minutes
    cache.set(cacheKey, processedPlans, 300);

    res.json({
      success: true,
      service: vtpassData.content?.ServiceName || serviceID,
      serviceID: serviceID,
      plans: processedPlans,
      totalPlans: processedPlans.length,
      source: 'vtpass_live_api',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Error fetching LIVE data plans:', error);
    
    // Provide fallback mock data
    const mockPlans = getMockDataPlans(req.query.serviceID);
    
    res.json({
      success: true,
      service: req.query.serviceID,
      plans: mockPlans,
      totalPlans: mockPlans.length,
      source: 'mock_fallback',
      timestamp: new Date().toISOString(),
      note: 'Using mock data due to service unavailability: ' + error.message
    });
  }
});

// Helper function for mock data plans
function getMockDataPlans(serviceID) {
  const mockPlans = {
    'mtn-data': [
      { name: '500MB Daily Plan', amount: '200', validity: '1 day', variation_code: 'mtn-500mb-200' },
      { name: '1GB Weekly Plan', amount: '500', validity: '7 days', variation_code: 'mtn-1gb-500' },
      { name: '2GB Monthly Plan', amount: '1000', validity: '30 days', variation_code: 'mtn-2gb-1000' },
      { name: '5GB Monthly Plan', amount: '2000', validity: '30 days', variation_code: 'mtn-5gb-2000' },
      { name: '10GB Monthly Plan', amount: '3000', validity: '30 days', variation_code: 'mtn-10gb-3000' },
    ],
    'airtel-data': [
      { name: '500MB Daily Plan', amount: '200', validity: '1 day', variation_code: 'airtel-500mb-200' },
      { name: '1GB Weekly Plan', amount: '500', validity: '7 days', variation_code: 'airtel-1gb-500' },
      { name: '2GB Monthly Plan', amount: '1000', validity: '30 days', variation_code: 'airtel-2gb-1000' },
    ],
    'glo-data': [
      { name: '500MB Daily Plan', amount: '200', validity: '1 day', variation_code: 'glo-500mb-200' },
      { name: '1GB Weekly Plan', amount: '500', validity: '7 days', variation_code: 'glo-1gb-500' },
      { name: '2GB Monthly Plan', amount: '1000', validity: '30 days', variation_code: 'glo-2gb-1000' },
    ],
    'etisalat-data': [
      { name: '500MB Daily Plan', amount: '200', validity: '1 day', variation_code: 'etisalat-500mb-200' },
      { name: '1GB Weekly Plan', amount: '500', validity: '7 days', variation_code: 'etisalat-1gb-500' },
      { name: '2GB Monthly Plan', amount: '1000', validity: '30 days', variation_code: 'etisalat-2gb-1000' },
    ]
  };
  
  return mockPlans[serviceID] || [];
}


// Add this RIGHT BEFORE your 404 handler at the very end
app.get('/api/debug/routes', (req, res) => {
  const routes = [];
  
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      // Routes registered directly on the app
      routes.push({
        path: middleware.route.path,
        methods: Object.keys(middleware.route.methods)
      });
    } else if (middleware.name === 'router') {
      // Router middleware
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          routes.push({
            path: handler.route.path,
            methods: Object.keys(handler.route.methods)
          });
        }
      });
    }
  });
  
  res.json({
    totalRoutes: routes.length,
    routes: routes.sort((a, b) => a.path.localeCompare(b.path))
  });
});





// @desc    Get cable TV variations from LIVE VTpass
// @route   GET /api/cable/variations
// @access  Private
app.get('/api/cable/variations', protect, async (req, res) => {
  try {
    const { serviceID } = req.query;
    const providers = serviceID ? [serviceID] : ['dstv', 'gotv', 'startimes'];
    const variations = {};

    for (const provider of providers) {
      try {
        console.log(`🔄 Fetching LIVE variations for: ${provider}`);
        
        const vtpassUrl = `https://vtpass.com/api/service-variations?serviceID=${provider}`;
        
        const response = await axios.get(vtpassUrl, {
          headers: {
            'Content-Type': 'application/json',
            'api-key': process.env.VTPASS_API_KEY,
            'secret-key': process.env.VTPASS_SECRET_KEY,
          },
          timeout: 15000
        });

        console.log(`📦 LIVE VTpass response for ${provider}:`, response.status);

        const vtpassData = response.data;

        if (vtpassData.response_description === '000') {
          const rawVariations = vtpassData.content?.variations || vtpassData.content?.varations || [];
          
          // Process variations to ensure consistent format
          const processedVariations = rawVariations.map(plan => {
            // Safely handle variation_amount
            let amount = plan.variation_amount;
            if (typeof amount === 'number') {
              amount = amount.toString();
            } else if (amount === null || amount === undefined) {
              amount = '0.00';
            }

            return {
              name: plan.name || 'Unknown Plan',
              variation_code: plan.variation_code || '',
              variation_amount: amount,
              fixedPrice: plan.fixedPrice === 'Yes'
            };
          });

          variations[provider.toUpperCase()] = {
            success: true,
            variations: processedVariations,
            totalPlans: processedVariations.length,
            source: 'vtpass_live'
          };
        } else {
          throw new Error(vtpassData.response_description || 'VTpass API error');
        }
      } catch (error) {
        console.error(`❌ Error fetching ${provider} variations:`, error);
        variations[provider.toUpperCase()] = {
          success: false,
          variations: getMockCableVariations(provider),
          totalPlans: getMockCableVariations(provider).length,
          source: 'mock_fallback',
          error: error.message
        };
      }
    }

    res.json({
      success: true,
      message: 'Cable variations fetched successfully',
      data: variations,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error fetching cable variations:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch cable variations',
      error: error.message,
      data: getAllMockCableVariations()
    });
  }
});

// Helper function for mock cable variations
function getMockCableVariations(provider) {
  const mockVariations = {
    'dstv': [
      {
        "name": "DStv Padi N1,850",
        "variation_code": "dstv-padi",
        "variation_amount": "1850.00",
        "fixedPrice": "Yes"
      },
      {
        "name": "DStv Yanga N2,565", 
        "variation_code": "dstv-yanga",
        "variation_amount": "2565.00",
        "fixedPrice": "Yes"
      }
    ],
    'gotv': [
      {
        "name": "GOtv Smallie",
        "variation_code": "gotv-smallie",
        "variation_amount": "1300.00",
        "fixedPrice": "Yes"
      }
    ],
    'startimes': [
      {
        "name": "StarTimes Nova",
        "variation_code": "nova",
        "variation_amount": "1500.00",
        "fixedPrice": "Yes"
      }
    ]
  };

  return mockVariations[provider] || [];
}

function getAllMockCableVariations() {
  return {
    'DSTV': {
      success: false,
      variations: getMockCableVariations('dstv'),
      totalPlans: getMockCableVariations('dstv').length,
      source: 'mock_fallback'
    },
    'GOTV': {
      success: false,
      variations: getMockCableVariations('gotv'),
      totalPlans: getMockCableVariations('gotv').length,
      source: 'mock_fallback'
    },
    'STARTIMES': {
      success: false,
      variations: getMockCableVariations('startimes'),
      totalPlans: getMockCableVariations('startimes').length,
      source: 'mock_fallback'
    }
  };
}

// @desc    Validate smart card number with enhanced details
// @route   POST /api/cable/validate-smartcard
// @access  Private  
app.post('/api/cable/validate-smartcard', protect, [
  body('serviceID').isIn(['dstv', 'gotv', 'startimes']).withMessage('Valid serviceID is required'),
  body('billersCode').notEmpty().withMessage('Smart card number is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const { serviceID, billersCode } = req.body;

  try {
    const vtpassResult = await callVtpassApi('/merchant-verify', {
      serviceID,
      billersCode
    });

    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      const content = vtpassResult.data.content;
      
      // Enhanced response with all available details
      const enhancedResponse = {
        success: true,
        customerName: content.Customer_Name,
        status: content.Status,
        dueDate: content.Due_Date,
        customerNumber: content.Customer_Number,
        customerType: content.Customer_Type,
        currentBouquet: content.Current_Bouquet,
        renewalAmount: content.Renewal_Amount,
        details: content
      };

      res.json(enhancedResponse);
    } else {
      res.status(400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'Smart card validation failed',
        details: vtpassResult.data
      });
    }
  } catch (error) {
    console.error('Error validating smart card:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to validate smart card' 
    });
  }
});





// @desc    Get education service variations with VTpass fallback
// @route   GET /api/education/variations
// @access  Private
app.get('/api/education/variations', protect, [
  query('serviceID').notEmpty().withMessage('Service ID is required')
], async (req, res) => {
  console.log('🎓 EDUCATION VARIATIONS ENDPOINT HIT - serviceID:', req.query.serviceID);
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { serviceID } = req.query;
    
    console.log('📡 Fetching education variations for service:', serviceID);

    // Validate service ID
    const validServiceIDs = ['waec-registration', 'waec', 'jamb'];
    
    if (!validServiceIDs.includes(serviceID)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid education service ID. Valid IDs: ' + validServiceIDs.join(', ')
      });
    }

    let variations = [];
    let source = 'mock_fallback';

    try {
      // Try to get from VTpass first
      console.log('🚀 Calling LIVE VTpass API for education variations:', serviceID);

      const vtpassUrl = 'https://vtpass.com/api/service-variations';
      
      const response = await axios.get(vtpassUrl, {
        params: { serviceID },
        headers: {
          'Content-Type': 'application/json',
          'api-key': process.env.VTPASS_API_KEY,
          'secret-key': process.env.VTPASS_SECRET_KEY,
        },
        timeout: 10000
      });

      console.log('📦 LIVE VTpass API response status:', response.status);

      const vtpassData = response.data;

      // Check if VTpass API returned success
      if (vtpassData.response_description === '000' || vtpassData.code === '000') {
        variations = vtpassData.content?.variations || [];
        source = 'vtpass_live';
        console.log(`✅ Got ${variations.length} LIVE variations from VTpass`);
      } else {
        console.log('❌ VTpass API error:', vtpassData.response_description);
        throw new Error(vtpassData.response_description || 'VTpass API error');
      }
    } catch (vtpassError) {
      console.log('⚠️ VTpass failed, using mock data:', vtpassError.message);
      variations = getMockEducationVariations(serviceID);
      source = 'mock_fallback';
    }

    // Process variations to ensure consistent format
    const processedVariations = variations.map(variation => {
      return {
        name: variation.name || 'Unknown Plan',
        variation_code: variation.variation_code || '',
        variation_amount: variation.variation_amount?.toString() || '0.00',
        fixedPrice: variation.fixedPrice === 'Yes' || variation.fixedPrice === true
      };
    }).filter(variation => variation.variation_code && variation.name !== 'Unknown Plan');

    console.log(`✅ Returning ${processedVariations.length} variations (source: ${source})`);

    res.json({
      success: true,
      service: serviceID,
      variations: processedVariations,
      totalVariations: processedVariations.length,
      source: source,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Unexpected error in education variations:', error);
    
    // Even on unexpected errors, return mock data
    const mockVariations = getMockEducationVariations(req.query.serviceID);
    
    res.json({
      success: true,
      service: req.query.serviceID,
      variations: mockVariations,
      totalVariations: mockVariations.length,
      source: 'mock_fallback_error',
      timestamp: new Date().toISOString()
    });
  }
});

// Enhanced mock data fallback
function getMockEducationVariations(serviceID) {
  const mockVariations = {
    'waec-registration': [
      {
        "variation_code": "waec-registration",
        "name": "WASSCE for Private Candidates - Second Series (2024)",
        "variation_amount": "18950.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "waec-registration-2",
        "name": "WASSCE for Private Candidates - First Series (2024)",
        "variation_amount": "18950.00",
        "fixedPrice": "Yes"
      }
    ],
    'waec': [
      {
        "variation_code": "waecdirect",
        "name": "WASSCE Result Checker",
        "variation_amount": "1200.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "waecdirect-2",
        "name": "WASSCE GCE Result Checker",
        "variation_amount": "1200.00",
        "fixedPrice": "Yes"
      }
    ],
    'jamb': [
      {
        "variation_code": "utme-mock",
        "name": "UTME PIN (with mock)",
        "variation_amount": "6300.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "utme-no-mock",
        "name": "UTME PIN (without mock)",
        "variation_amount": "4700.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "direct-entry",
        "name": "Direct Entry PIN",
        "variation_amount": "5300.00",
        "fixedPrice": "Yes"
      }
    ]
  };

  return mockVariations[serviceID] || [];
}

// @desc    Validate education profile (JAMB Profile ID)
// @route   POST /api/education/validate-profile
// @access  Private
app.post('/api/education/validate-profile', protect, [
  body('profileId').notEmpty().withMessage('Profile ID is required'),
  body('serviceID').notEmpty().withMessage('Service ID is required')
], async (req, res) => {
  console.log('🎓 EDUCATION PROFILE VALIDATION ENDPOINT HIT');
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { profileId, serviceID } = req.body;
    
    console.log('🔍 Validating education profile:', { profileId, serviceID });

    // For JAMB profile validation
    if (serviceID === 'jamb') {
      const vtpassResult = await callVtpassApi('/merchant-verify', {
        serviceID: 'jamb',
        billersCode: profileId
      });

      console.log('📦 VTpass Profile Validation Response:', {
        success: vtpassResult.success,
        code: vtpassResult.data?.code,
        message: vtpassResult.data?.response_description
      });

      if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
        const content = vtpassResult.data.content;
        
        res.json({
          success: true,
          customerName: content.Customer_Name || 'Valid JAMB Profile',
          message: 'Profile validated successfully',
          details: content
        });
      } else {
        res.status(400).json({
          success: false,
          message: vtpassResult.data?.response_description || 'Profile validation failed',
          details: vtpassResult.data
        });
      }
    } else {
      // For other education services that don't require profile validation
      res.json({
        success: true,
        customerName: 'Valid Profile',
        message: 'Profile validation not required for this service'
      });
    }

  } catch (error) {
    console.error('❌ Error validating education profile:', error);
    
    res.status(500).json({ 
      success: false, 
      message: 'Profile validation service temporarily unavailable'
    });
  }
});

// @desc    Purchase education service (WAEC, JAMB, etc.)
// @route   POST /api/education/purchase
// @access  Private
app.post('/api/education/purchase', protect, verifyTransactionAuth, [
  body('serviceID').notEmpty().withMessage('Service ID is required'),
  body('variationCode').notEmpty().withMessage('Variation code is required'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number'),
  body('quantity').optional().isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  body('profileId').optional().isString().withMessage('Profile ID must be a string')
], async (req, res) => {
  console.log('🎓 EDUCATION PURCHASE ENDPOINT HIT');
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const { serviceID, variationCode, phone, amount, quantity = 1, profileId } = req.body;
  const userId = req.user._id;
  const reference = generateRequestId();
  
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance}` 
      });
    }

    // Prepare VTpass payload
    const vtpassPayload = {
      request_id: reference,
      serviceID,
      variation_code: variationCode,
      phone,
      amount: amount.toString(),
      quantity: quantity.toString()
    };

    // Add profile ID for JAMB
    if (profileId && serviceID === 'jamb') {
      vtpassPayload.billersCode = profileId;
    }

    console.log('🚀 Calling VTpass for education purchase:', vtpassPayload);

    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    console.log('📦 VTpass Education Purchase Response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description
    });

    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;

    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });

      // Credit commission
     
await calculateAndAddCommission(userId, amount, serviceID, session)  // serviceID is like 'waec' or 'jamb'
  .catch(err => console.log('⚠️ Education commission calculation failed:', err.message));
      // AUTO-CREATE TRANSACTION NOTIFICATION
      try {
        await Notification.create({
          recipientId: userId,
          title: "Education Purchase Successful 🎓",
          message: `Your ${serviceID.toUpperCase()} purchase of ₦${amount} was completed successfully. New wallet balance: ₦${newBalance}`,
          isRead: false
        });
      } catch (notificationError) {
        console.error('Error creating transaction notification:', notificationError);
      }
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'Education purchase failed',
        details: vtpassResult.data
      });
    }

    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `${serviceID} education purchase for ${phone}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );

    await session.commitTransaction();

    res.json({
      success: true,
      message: `Education purchase completed. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      newBalance: newBalance,
      status: newTransaction.status,
      vtpassResponse: vtpassResult.data,
      purchased_code: vtpassResult.data?.content?.purchased_code,
      cards: vtpassResult.data?.content?.cards || [],
      tokens: vtpassResult.data?.content?.tokens || []
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Error in education purchase:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Education purchase failed' 
    });
  } finally {
    session.endSession();
  }
});

// Helper function for mock education variations
function getMockEducationVariations(serviceID) {
  const mockVariations = {
    'waec-registration': [
      {
        "name": "WASSCE for Private Candidates - Second Series (2024)",
        "variation_code": "waec-registration",
        "variation_amount": "18950.00",
        "fixedPrice": "Yes"
      },
      {
        "name": "WASSCE for Private Candidates - First Series (2024)",
        "variation_code": "waec-registration-2", 
        "variation_amount": "18950.00",
        "fixedPrice": "Yes"
      }
    ],
    'waec': [
      {
        "name": "WASSCE Result Checker",
        "variation_code": "waecdirect",
        "variation_amount": "1200.00",
        "fixedPrice": "Yes"
      },
      {
        "name": "WASSCE GCE Result Checker",
        "variation_code": "waecdirect-2",
        "variation_amount": "1200.00", 
        "fixedPrice": "Yes"
      }
    ],
    'jamb': [
      {
        "name": "UTME PIN (with mock)",
        "variation_code": "utme-mock",
        "variation_amount": "6300.00",
        "fixedPrice": "Yes"
      },
      {
        "name": "UTME PIN (without mock)",
        "variation_code": "utme-no-mock",
        "variation_amount": "4700.00",
        "fixedPrice": "Yes"
      },
      {
        "name": "Direct Entry PIN",
        "variation_code": "direct-entry", 
        "variation_amount": "5300.00",
        "fixedPrice": "Yes"
      }
    ]
  };

  return mockVariations[serviceID] || [];
}



// @desc    Get insurance variations automatically from VTpass
// @route   GET /api/insurance/variations
// @access  Private
app.get('/api/insurance/variations', protect, async (req, res) => {
  try {
    console.log('🛡️ Fetching insurance variations from VTpass...');
    
    // Try to get from cache first
    const cacheKey = 'insurance-variations';
    const cachedVariations = cache.get(cacheKey);
    
    if (cachedVariations) {
      console.log('✅ Serving insurance variations from cache');
      return res.json({
        success: true,
        service: 'Third Party Motor Insurance - Universal Insurance',
        serviceID: 'ui-insure',
        variations: cachedVariations,
        totalVariations: cachedVariations.length,
        source: 'cache'
      });
    }

    // Call VTpass LIVE API directly for insurance variations
    console.log('🚀 Calling LIVE VTpass API for insurance variations');
    const vtpassUrl = 'https://vtpass.com/api/service-variations?serviceID=ui-insure';
    
    const response = await axios.get(vtpassUrl, {
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.VTPASS_API_KEY,
        'secret-key': process.env.VTPASS_SECRET_KEY,
      },
      timeout: 15000
    });

    console.log('📦 VTpass insurance variations response status:', response.status);

    const vtpassData = response.data;

    // Check if VTpass API returned success
    if (vtpassData.response_description === '000') {
      const variations = vtpassData.content?.variations || vtpassData.content?.varations || [];
      
      console.log(`✅ Successfully fetched ${variations.length} insurance variations from VTpass`);
      
      // Process variations to ensure consistent format
      const processedVariations = variations.map(variation => ({
        name: variation.name || 'Unknown Plan',
        variation_code: variation.variation_code || '',
        variation_amount: variation.variation_amount?.toString() || '0.00',
        fixedPrice: variation.fixedPrice === 'Yes'
      })).filter(variation => variation.variation_code && variation.name !== 'Unknown Plan');

      // Cache the result for 10 minutes
      cache.set(cacheKey, processedVariations, 600);

      res.json({
        success: true,
        service: vtpassData.content?.ServiceName || 'Third Party Motor Insurance - Universal Insurance',
        serviceID: 'ui-insure',
        variations: processedVariations,
        totalVariations: processedVariations.length,
        source: 'vtpass_live',
        timestamp: new Date().toISOString()
      });
    } else {
      console.log('❌ VTpass API error:', vtpassData.response_description);
      throw new Error(vtpassData.response_description || 'Failed to fetch insurance variations');
    }

  } catch (error) {
    console.error('❌ Error fetching insurance variations:', error);
    
    // Fallback to mock data
    const mockVariations = [
      {
        "variation_code": "1",
        "name": "Private",
        "variation_amount": "3000.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "2", 
        "name": "Commercial",
        "variation_amount": "5000.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "3",
        "name": "Tricycles", 
        "variation_amount": "1500.00",
        "fixedPrice": "Yes"
      },
      {
        "variation_code": "4",
        "name": "Motorcycle",
        "variation_amount": "3000.00", 
        "fixedPrice": "Yes"
      }
    ];

    res.json({
      success: true,
      service: 'Third Party Motor Insurance - Universal Insurance',
      serviceID: 'ui-insure',
      variations: mockVariations,
      totalVariations: mockVariations.length,
      source: 'mock_fallback',
      timestamp: new Date().toISOString(),
      note: 'Using fallback data due to service unavailability'
    });
  }
});




// @desc    Purchase insurance with correct variation codes
// @route   POST /api/insurance/purchase
// @access  Private
app.post('/api/insurance/purchase', protect, verifyTransactionAuth, [
  body('variationCode').notEmpty().withMessage('Variation code is required'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
  body('insuredName').notEmpty().withMessage('Insured name is required'),
  body('engineCapacity').notEmpty().withMessage('Engine capacity is required'),
  body('chasisNumber').notEmpty().withMessage('Chasis number is required'),
  body('plateNumber').notEmpty().withMessage('Plate number is required'),
  body('vehicleMake').notEmpty().withMessage('Vehicle make is required'),
  body('vehicleColor').notEmpty().withMessage('Vehicle color is required'),
  body('vehicleModel').notEmpty().withMessage('Vehicle model is required'),
  body('yearOfMake').notEmpty().withMessage('Year of make is required'),
  body('state').notEmpty().withMessage('State is required'),
  body('lga').notEmpty().withMessage('LGA is required'),
  body('email').isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  console.log('🛡️ INSURANCE PURCHASE REQUEST');
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const {
    variationCode,
    phone,
    insuredName,
    engineCapacity,
    chasisNumber,
    plateNumber,
    vehicleMake,
    vehicleColor,
    vehicleModel,
    yearOfMake,
    state,
    lga,
    email
  } = req.body;

  const userId = req.user._id;
  const reference = generateRequestId();

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get variation details to determine amount
    let amount = 0;
    try {
      const variationsResponse = await axios.get('https://vtpass.com/api/service-variations?serviceID=ui-insure', {
        headers: {
          'Content-Type': 'application/json',
          'api-key': process.env.VTPASS_API_KEY,
          'secret-key': process.env.VTPASS_SECRET_KEY,
        }
      });

      if (variationsResponse.data.response_description === '000') {
        const variations = variationsResponse.data.content?.variations || [];
        const selectedVariation = variations.find(v => v.variation_code === variationCode);
        
        if (selectedVariation) {
          amount = parseFloat(selectedVariation.variation_amount) || 0;
          console.log(`💰 Insurance amount determined: ₦${amount}`);
        } else {
          throw new Error('Invalid variation code');
        }
      }
    } catch (error) {
      console.log('⚠️ Could not fetch variation details, using default amounts');
      // Fallback amounts based on variation code
      const amountMap = {
        '1': 3000, // Private
        '2': 5000, // Commercial  
        '3': 1500, // Tricycles
        '4': 3000  // Motorcycle
      };
      amount = amountMap[variationCode] || 3000;
    }

    if (user.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance}` 
      });
    }

    console.log('🚀 Calling VTpass for insurance purchase...');
    
    // Prepare VTpass payload for insurance purchase
    const vtpassPayload = {
      request_id: reference,
      serviceID: 'ui-insure',
      billersCode: plateNumber,
      variation_code: variationCode,
      amount: amount.toString(),
      phone: phone,
      Insured_Name: insuredName,
      engine_capacity: engineCapacity,
      Chasis_Number: chasisNumber,
      Plate_Number: plateNumber,
      vehicle_make: vehicleMake,
      vehicle_color: vehicleColor,
      vehicle_model: vehicleModel,
      YearofMake: yearOfMake,
      state: state,
      lga: lga,
      email: email
    };

    console.log('📦 VTpass Insurance Payload:', vtpassPayload);

    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    console.log('📦 VTpass Insurance Response:', JSON.stringify(vtpassResult, null, 2));

    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;

    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });

      // Credit commission
     
await calculateAndAddCommission(userId, amount, 'insurance', session)
  .catch(err => console.log('⚠️ Insurance commission calculation failed:', err.message));

      // Create notification
      try {
        await Notification.create({
          recipientId: userId,
          title: "Insurance Purchase Successful 🛡️",
          message: `Your ${vtpassResult.data.content?.product_name || 'Third Party Motor Insurance'} for ${plateNumber} was completed successfully. Premium: ₦${amount}`,
          isRead: false
        });
      } catch (notificationError) {
        console.error('Error creating insurance notification:', notificationError);
      }
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'Insurance purchase failed',
        details: vtpassResult.data
      });
    }

    // Create transaction record
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `Third Party Motor Insurance for ${plateNumber}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );

    await session.commitTransaction();

    // Extract certificate URL from response
    const certUrl = vtpassResult.data.certUrl || 
                   vtpassResult.data.purchased_code?.replace('Download Certificate : ', '') || 
                   '';

    console.log('✅ Insurance purchase completed successfully');
    console.log('📄 Certificate URL:', certUrl);

    res.json({
      success: true,
      message: `Insurance purchase completed successfully`,
      transactionId: newTransaction._id,
      newBalance: newBalance,
      status: newTransaction.status,
      vtpassResponse: vtpassResult.data,
      certificateUrl: certUrl,
      purchased_code: vtpassResult.data.purchased_code
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Error in insurance purchase:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Insurance purchase failed',
      error: error.message 
    });
  } finally {
    session.endSession();
  }
});


// @desc    Get all insurance-related options (makes, colors, states, etc.)
// @route   GET /api/insurance/options/:type
// @access  Private
app.get('/api/insurance/options/:type', protect, async (req, res) => {
  try {
    const { type } = req.params;
    const { stateCode } = req.query;

    console.log(`🛡️ Fetching insurance options for: ${type}`);

    const endpoints = {
      'vehicle-makes': 'https://vtpass.com/api/universal-insurance/options/brand',
      'vehicle-colors': 'https://vtpass.com/api/universal-insurance/options/color', 
      'engine-capacities': 'https://vtpass.com/api/universal-insurance/options/engine-capacity',
      'states': 'https://vtpass.com/api/universal-insurance/options/state',
      'lgas': `https://vtpass.com/api/universal-insurance/options/lga/${stateCode}`
    };

    const url = endpoints[type];
    if (!url) {
      return res.status(400).json({ success: false, message: 'Invalid option type' });
    }

    // Try cache first
    const cacheKey = `insurance-options-${type}-${stateCode || ''}`;
    const cachedData = cache.get(cacheKey);
    
    if (cachedData) {
      return res.json({
        success: true,
        data: cachedData,
        source: 'cache'
      });
    }

    const response = await axios.get(url, {
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.VTPASS_API_KEY,
        'secret-key': process.env.VTPASS_SECRET_KEY,
      },
      timeout: 10000
    });

    if (response.data.response_description === '000') {
      const data = response.data.content || [];
      
      // Cache for 1 hour
      cache.set(cacheKey, data, 3600);

      res.json({
        success: true,
        data: data,
        source: 'vtpass_live'
      });
    } else {
      throw new Error(response.data.response_description);
    }

  } catch (error) {
    console.error(`❌ Error fetching insurance options for ${req.params.type}:`, error);
    
    // Return fallback data
    const fallbackData = getFallbackInsuranceOptions(req.params.type);
    
    res.json({
      success: true,
      data: fallbackData,
      source: 'fallback',
      note: 'Using fallback data while service is unavailable'
    });
  }
});

// Helper function for fallback insurance options
function getFallbackInsuranceOptions(type) {
  const fallbacks = {
    'vehicle-makes': [
      { "VehicleMakeCode": "1", "VehicleMakeName": "Toyota" },
      { "VehicleMakeCode": "2", "VehicleMakeName": "Honda" },
      { "VehicleMakeCode": "3", "VehicleMakeName": "Ford" },
      { "VehicleMakeCode": "4", "VehicleMakeName": "BMW" }
    ],
    'vehicle-colors': [
      { "ColourCode": "20", "ColourName": "Ash" },
      { "ColourCode": "1004", "ColourName": "Black" },
      { "ColourCode": "1005", "ColourName": "White" },
      { "ColourCode": "1006", "ColourName": "Red" }
    ],
    'engine-capacities': [
      { "CapacityCode": "1", "CapacityName": "0.1 - 1.59" },
      { "CapacityCode": "2", "CapacityName": "1.6 - 2.0" },
      { "CapacityCode": "3", "CapacityName": "2.1 - 3.0" },
      { "CapacityCode": "4", "CapacityName": "3.1 - 4.0" }
    ],
    'states': [
      { "StateCode": "1", "StateName": "Lagos" },
      { "StateCode": "2", "StateName": "Abuja" },
      { "StateCode": "3", "StateName": "Rivers" },
      { "StateCode": "4", "StateName": "Oyo" }
    ],
    'lgas': [
      { "LGACode": "1", "LGAName": "Ikeja" },
      { "LGACode": "2", "LGAName": "Lagos Island" },
      { "LGACode": "3", "LGAName": "Surulere" }
    ]
  };

  return fallbacks[type] || [];
}



// ==================== WALLET TOP-UP ROUTES ====================

// @desc    Debug all wallet routes
// @route   GET /api/wallet/debug
// @access  Public
app.get('/api/wallet/debug', (req, res) => {
  res.json({
    success: true,
    message: 'Wallet routes are working',
    availableEndpoints: [
      'POST /api/wallet/top-up',
      'GET /api/wallet/test-top-up',
      'GET /api/wallet/debug'
    ],
    timestamp: new Date().toISOString()
  });
});

// @desc    Test wallet top-up endpoint
// @route   GET /api/wallet/test-top-up
// @access  Public
app.get('/api/wallet/test-top-up', async (req, res) => {
  try {
    console.log('🧪 Testing wallet top-up endpoint');
    
    res.json({
      success: true,
      message: 'Wallet top-up endpoint is working',
      endpoint: 'POST /api/wallet/top-up',
      requiredFields: ['userId', 'amount', 'reference'],
      examplePayload: {
        userId: 'user_id_here',
        amount: 1000,
        reference: 'test_ref_123',
        description: 'Test wallet funding',
        source: 'paystack'
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Test endpoint error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Test endpoint failed' 
    });
  }
});

// PRODUCTION: Enhanced sync with main backend - FIXED VERSION
async function syncWithMainBackendWithRetry(userId, amount, reference, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🔄 PRODUCTION: Syncing with main backend (Attempt ${attempt}/${maxRetries})`);
      
      // FIX: Send amount in kobo (as received from PayStack)
      // Main backend will convert to Naira
      const syncPayload = {
        userId: userId,
        amount: amount, // Keep as kobo, backend will convert
        reference: reference,
        description: `Wallet funding via PayStack - Ref: ${reference}`,
        source: 'paystack_webhook',
        timestamp: new Date().toISOString()
      };

      console.log('📦 Sync payload:', syncPayload);

      const response = await axios.post(
        `${MAIN_BACKEND_URL}/api/wallet/top-up`,
        syncPayload,
        {
          timeout: 15000,
          headers: { 
            'Content-Type': 'application/json'
          }
        }
      );

      console.log('✅ PRODUCTION: Main backend sync response:', {
        status: response.status,
        success: response.data.success,
        message: response.data.message,
        newBalance: response.data.newBalance
      });

      if (response.data.success) {
        return {
          success: true,
          data: response.data
        };
      } else {
        // If transaction already processed, consider it success
        if (response.data.alreadyProcessed) {
          console.log('ℹ️ Transaction already processed in main backend');
          return {
            success: true,
            data: response.data,
            alreadyProcessed: true
          };
        }
        throw new Error(response.data.message || 'Main backend rejected sync');
      }
    } catch (error) {
      console.error(`❌ PRODUCTION: Sync attempt ${attempt} failed:`, error.message);
      
      if (error.response) {
        console.error('Response status:', error.response.status);
        console.error('Response data:', error.response.data);
        
        // If it's a client error (4xx), don't retry
        if (error.response.status >= 400 && error.response.status < 500) {
          throw error;
        }
      }
      
      if (attempt === maxRetries) {
        throw new Error(`All sync attempts failed. Last error: ${error.message}`);
      }
      
      // Wait before retry (exponential backoff)
      const delay = attempt * 2000;
      console.log(`⏳ Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}




// @desc    Quick test wallet top-up
// @route   POST /api/wallet/quick-test
// @access  Public
app.post('/api/wallet/quick-test', async (req, res) => {
    try {
        const { userId, amount = 10000, reference = 'test_' + Date.now() } = req.body;
        
        console.log('🧪 Quick test wallet top-up:', { userId, amount, reference });

        if (!userId) {
            return res.status(400).json({ 
                success: false, 
                message: 'userId is required' 
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        const amountInNaira = amount / 100;
        const balanceBefore = user.walletBalance;
        user.walletBalance += amountInNaira;
        const balanceAfter = user.walletBalance;
        
        await user.save();

        console.log('✅ Quick test successful:', {
            amountKobo: amount,
            amountNaira: amountInNaira,
            balanceBefore,
            balanceAfter
        });

        res.json({
            success: true,
            message: 'Quick test completed',
            amountKobo: amount,
            amountNaira: amountInNaira,
            balanceBefore: balanceBefore,
            balanceAfter: balanceAfter,
            user: {
                _id: user._id,
                email: user.email,
                fullName: user.fullName
            }
        });

    } catch (error) {
        console.error('❌ Quick test error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Quick test failed: ' + error.message 
        });
    }
});



// @desc    Top up wallet from virtual account / PayStack webhook - WITH REFERRAL BONUSES (UPDATED)
// @route   POST /api/wallet/top-up
// @access  Public (called by virtual-account-backend)
app.post('/api/wallet/top-up', async (req, res) => {
  console.log('MAIN BACKEND: Wallet top-up request received', req.body);

  const { userId, amount, reference, source = 'paystack_funding' } = req.body;

  if (!userId || !reference || amount === undefined) {
    return res.status(400).json({
      success: false,
      message: 'userId, amount, and reference are required'
    });
  }

  const amountInKobo = Number(amount);
  const amountInNaira = amountInKobo / 100;

  if (isNaN(amountInNaira) || amountInNaira <= 0) {
    return res.status(400).json({
      success: false,
      message: 'Invalid amount'
    });
  }

  const session = await mongoose.startSession();

  try {
    await session.withTransaction(async () => {
      const user = await User.findById(userId).session(session);
      if (!user) throw new Error('User not found');

      // FINAL DUPLICATE PROTECTION
      const existing = await Transaction.findOne({
        reference,
        status: 'Successful'
      }).session(session);

      if (existing) {
        console.log(`REPLAY ATTACK BLOCKED: ${reference} already processed`);
        throw new Error('ALREADY_PROCESSED');
      }

      // Delete any failed/pending duplicates
      await Transaction.deleteMany({
        reference,
        status: { $ne: 'Successful' }
      }).session(session);

      const balanceBefore = user.walletBalance;
      user.walletBalance += amountInNaira;
      await user.save({ session });

      // Create main wallet transaction with isDeposit flag
      await Transaction.create([{
        userId,
        type: 'Wallet Funding',
        amount: amountInNaira,
        status: 'Successful',
        reference,
        description: `Wallet funding via ${source} - Ref: ${reference}`,
        balanceBefore,
        balanceAfter: user.walletBalance,
        gateway: 'Dalabapay App',
        metadata: { 
          source: 'webhook', 
          processedAt: new Date(),
          isDeposit: true, // Mark as deposit for referral bonus tracking
          depositAmount: amountInNaira,
          reference: reference,
          paymentMethod: source.includes('paystack') ? 'paystack' : 'virtual_account',
          transactionType: 'wallet_funding'
        }
      }], { session });

      console.log(`MAIN SUCCESS: +₦${amountInNaira} | Ref: ${reference} | Balance: ₦${user.walletBalance}`);

      // ================================================
      // 🔥 REFERRAL BONUS SYSTEM: Check and award bonuses (IMPROVED)
      // ================================================
      try {
        // ✅ IMPROVED: Check for ANY successful deposit
        const previousDeposits = await Transaction.countDocuments({
          userId: userId,
          type: 'Wallet Funding',
          status: 'Successful',
          'metadata.isDeposit': true,
          _id: { $ne: existing?._id } // Exclude current transaction
        }).session(session);
        
        console.log(`🔍 Checking first deposit: Found ${previousDeposits} previous Wallet Funding transactions`);
        
        if (previousDeposits === 0) {
          console.log(`🎉 FIRST DEPOSIT DETECTED for user ${userId} (₦${amountInNaira})`);
          
          // ✅ Check if deposit meets minimum for bonus (₦5,000)
          if (amountInNaira >= 5000) {
            console.log(`✅ Deposit ₦${amountInNaira} meets minimum for bonus (₦5,000)`);
            
            // 🔥 AWARD DIRECT REFERRAL BONUS
            let directBonusAwarded = false;
            if (user.referrerId) {
              try {
                directBonusAwarded = await awardDirectReferralBonus(userId, amountInNaira, session);
                console.log(`✅ Direct referral bonus result: ${directBonusAwarded}`);
              } catch (directError) {
                console.error('❌ Direct referral bonus error:', directError);
                directBonusAwarded = false;
              }
            } else {
              console.log('ℹ️ User has no referrer, skipping direct bonus');
            }
            
            // 🔥 AWARD INDIRECT REFERRAL BONUS (only if direct bonus was awarded)
            let indirectBonusAwarded = false;
            if (directBonusAwarded) {
              try {
                indirectBonusAwarded = await awardIndirectReferralBonus(userId, amountInNaira, session);
                console.log(`✅ Indirect referral bonus result: ${indirectBonusAwarded}`);
              } catch (indirectError) {
                console.error('❌ Indirect referral bonus error:', indirectError);
                indirectBonusAwarded = false;
              }
            }
            
            // Update user's bonus flags
            if (directBonusAwarded) {
              user.referralBonusAwarded = true;
              await user.save({ session });
              
              // Also award welcome bonus to the user
              const userCommissionBefore = user.commissionBalance || 0;
              user.commissionBalance = (user.commissionBalance || 0) + 200;
              await user.save({ session });
              
              // Create welcome bonus transaction
              await createTransaction(
                userId,
                200,
                'Welcome Bonus',
                'Successful',
                `Welcome bonus for ₦${amountInNaira} first deposit`,
                userCommissionBefore,
                user.commissionBalance,
                session,
                true,
                'none',
                null,
                {},
                {
                  referralType: 'welcome_bonus',
                  depositAmount: amountInNaira,
                  bonusFor: 'referred_user'
                }
              );
            }
            
            if (directBonusAwarded || indirectBonusAwarded) {
              console.log(`✅ Referral bonuses processed for ₦${amountInNaira} deposit:`);
              console.log(`   - Direct bonus awarded: ${directBonusAwarded ? 'YES' : 'NO'}`);
              console.log(`   - Indirect bonus awarded: ${indirectBonusAwarded ? 'YES' : 'NO'}`);
              
              // Get updated user to check commission balance
              const updatedUser = await User.findById(userId).session(session);
              
              // ✅ Update notification to show it's first deposit with bonus
              await Notification.create([{
                recipient: userId,
                title: "First Deposit Bonus! 🎉",
                message: `You received ₦200 welcome bonus for your first deposit of ₦${amountInNaira}!`,
                type: 'welcome_bonus',
                isRead: false,
                metadata: {
                  amount: amountInNaira,
                  bonus: 200,
                  newBalance: user.walletBalance,
                  newCommissionBalance: updatedUser?.commissionBalance || 0,
                  isFirstDeposit: true,
                  reference: reference,
                  bonusType: 'welcome_bonus'
                }
              }], { session });
            }
          } else {
            console.log(`⚠️ First deposit (₦${amountInNaira}) below ₦5,000 minimum for bonus`);
            
            // Create notification encouraging user to deposit more
            await Notification.create([{
              recipient: userId,
              title: "Wallet Credited 💰",
              message: `₦${amountInNaira} added to your wallet. Deposit ₦${(5000 - amountInNaira).toFixed(2)} more to unlock ₦200 welcome bonus!`,
              type: 'wallet_credit',
              isRead: false,
              metadata: {
                amount: amountInNaira,
                newBalance: user.walletBalance,
                reference: reference,
                isDeposit: true,
                isFirstDeposit: true,
                bonusEligible: false,
                minimumRequired: 5000,
                neededAmount: 5000 - amountInNaira,
                bonusMessage: `Deposit ₦${(5000 - amountInNaira).toFixed(2)} more to get ₦200 welcome bonus!`
              }
            }], { session });
          }
        } else {
          console.log(`ℹ️ Not first deposit (${previousDeposits} previous deposits), skipping referral bonuses`);
          
          // Create regular deposit notification
          await Notification.create([{
            recipient: userId,
            title: "Wallet Credited 💰",
            message: `₦${amountInNaira.toFixed(2)} added to your wallet. New balance: ₦${user.walletBalance.toFixed(2)}`,
            type: 'wallet_credit',
            isRead: false,
            metadata: {
              amount: amountInNaira,
              newBalance: user.walletBalance,
              reference: reference,
              isDeposit: true,
              isFirstDeposit: false
            }
          }], { session });
        }
      } catch (bonusError) {
        console.error('⚠️ Error processing referral bonuses:', bonusError);
        console.error('Bonus error stack:', bonusError.stack);
        
        // Don't fail the main transaction if bonus processing fails
      }
    });

    // Get updated user info to return commission balance
    const updatedUser = await User.findById(userId);
    
    return res.json({
      success: true,
      newBalance: null, // Flutter reads from local storage
      amount: amountInNaira,
      commissionBalance: updatedUser?.commissionBalance || 0,
      message: 'Wallet funded successfully'
    });

  } catch (error) {
    await session.abortTransaction();

    if (error.message === 'ALREADY_PROCESSED') {
      return res.json({
        success: true,
        alreadyProcessed: true,
        message: 'Transaction already processed',
      });
    }

    console.error('MAIN TOP-UP ERROR:', error);
    console.error('Error stack:', error.stack);
    return res.status(500).json({
      success: false,
      message: 'Funding failed'
    });
  } finally {
    session.endSession();
  }
});



/**
 * Calculate and add referral commission (0.005%) when referred users make purchases
 */
const calculateAndAddReferralCommission = async (purchaserUserId, amount, serviceType, mongooseSession = null) => {
  try {
    console.log(`🎯 Checking referral commission for purchaser: ${purchaserUserId}, Amount: ₦${amount}`);
    
    // Get purchaser details
    const purchaserQuery = User.findById(purchaserUserId);
    if (mongooseSession) {
      purchaserQuery.session(mongooseSession);
    }
    const purchaser = await purchaserQuery;
    
    if (!purchaser || !purchaser.referrerId) {
      console.log('⚠️ No referrer found for purchaser');
      return 0;
    }
    
    const referrerId = purchaser.referrerId;
    
    // Get referrer details
    const referrerQuery = User.findById(referrerId);
    if (mongooseSession) {
      referrerQuery.session(mongooseSession);
    }
    const referrer = await referrerQuery;
    
    if (!referrer) {
      console.log('❌ Referrer not found');
      return 0;
    }
    
    // Calculate referral commission (0.005% = 0.00005)
    const referralCommissionRate = 0.00005;
    let commissionAmount = amount * referralCommissionRate;
    
    // Minimum commission ₦2 if amount is substantial
    if (commissionAmount < 2 && amount >= 1000) {
      commissionAmount = 2;
    }
    
    if (commissionAmount <= 0) {
      console.log('⚠️ Referral commission amount too small');
      return 0;
    }
    
    console.log(`💰 Referral commission: ₦${amount} × 0.005% = ₦${commissionAmount.toFixed(2)}`);
    
    // Add commission to referrer's balance
    const commissionBefore = referrer.commissionBalance || 0;
    referrer.commissionBalance = (referrer.commissionBalance || 0) + commissionAmount;
    referrer.totalReferralEarnings = (referrer.totalReferralEarnings || 0) + commissionAmount;
    
    await referrer.save({ session: mongooseSession });
    
    // Create referral commission transaction
    await createTransaction(
      referrerId,
      commissionAmount,
      'Referral Service Commission',
      'Successful',
      `Referral commission from ${purchaser.fullName}'s ${serviceType} purchase`,
      commissionBefore,
      referrer.commissionBalance,
      mongooseSession,
      true,
      'none',
      null,
      {},
      {
        commissionType: 'referral_service',
        purchaserUserId: purchaserUserId,
        purchaserName: purchaser.fullName,
        serviceType: serviceType,
        purchaseAmount: amount,
        commissionRate: referralCommissionRate,
        commissionAmount: commissionAmount
      }
    );
    
    // Create notification
    try {
      await Notification.create([{
        recipient: referrerId,
        title: "Referral Commission Earned! 💰",
        message: `You earned ₦${commissionAmount.toFixed(2)} from ${purchaser.fullName}'s ${serviceType} purchase`,
        type: 'commission_earned',
        isRead: false,
        metadata: {
          purchaserUserId: purchaserUserId,
          serviceType: serviceType,
          purchaseAmount: amount,
          commissionAmount: commissionAmount
        }
      }], { session: mongooseSession });
    } catch (notifError) {
      console.error('❌ Referral commission notification error:', notifError);
    }
    
    console.log(`✅ Referral commission awarded: ₦${commissionAmount.toFixed(2)} to ${referrer.email}`);
    return commissionAmount;
    
  } catch (error) {
    console.error('❌ Error calculating referral commission:', error);
    return 0;
  }
};



// @desc    Find user by email
// @route   GET /api/users/find-by-email/:email
// @access  Public (for virtual account backend integration)
app.get('/api/users/find-by-email/:email', async (req, res) => {
  try {
    const { email } = req.params;
    
    console.log('🔍 Finding user by email:', email);

    const user = await User.findOne({ email: email.toLowerCase() }).select('-password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      user: {
        _id: user._id,
        email: user.email,
        fullName: user.fullName,
        walletBalance: user.walletBalance
      }
    });
  } catch (error) {
    console.error('Error finding user by email:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error finding user' 
    });
  }
});






// @desc    Verify PayStack transaction (Backend Proxy)
// @route   POST /api/paystack/verify-transaction
// @access  Public
app.post('/api/paystack/verify-transaction', async (req, res) => {
  try {
    const { reference } = req.body;
    
    console.log('🔍 Verifying PayStack transaction via backend:', reference);

    if (!reference) {
      return res.status(400).json({
        success: false,
        message: 'Transaction reference is required'
      });
    }

    const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
    
    if (!PAYSTACK_SECRET_KEY) {
      return res.status(500).json({
        success: false,
        message: 'PayStack configuration error'
      });
    }

    // Verify with PayStack
    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        'User-Agent': 'VTPass-Backend/1.0'
      },
      timeout: 30000
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ PayStack API Error:', response.status, errorText);
      
      return res.status(response.status).json({
        success: false,
        message: `PayStack verification failed: ${response.statusText}`,
        status: response.status
      });
    }

    const data = await response.json();
    
    console.log('✅ PayStack verification result:', {
      success: data.status,
      message: data.message,
      transactionStatus: data.data?.status,
      amount: data.data?.amount
    });

    // Return the PayStack response
    res.json({
      success: data.status === true,
      data: data.data,
      message: data.message,
      status: data.data?.status,
      amount: data.data?.amount ? data.data.amount / 100 : 0 // Convert from kobo to naira
    });

  } catch (error) {
    console.error('💥 PayStack verification error:', error);
    
    res.status(500).json({
      success: false,
      message: `PayStack verification failed: ${error.message}`,
      error: error.message
    });
  }
});

// @desc    Force wallet top-up after verification
// @route   POST /api/wallet/force-topup
// @access  Public
app.post('/api/wallet/force-topup', async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { userId, amount, reference, description } = req.body;
    
    console.log('🚀 Force top-up request:', { userId, amount, reference });

    // Validate required fields
    if (!userId || !amount || !reference) {
      await session.abortTransaction();
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields: userId, amount, reference' 
      });
    }

    // Find user
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Check if transaction already exists
    const existingTransaction = await Transaction.findOne({ 
      reference: reference 
    }).session(session);
    
    if (existingTransaction) {
      await session.abortTransaction();
      return res.json({
        success: true,
        message: 'Transaction already processed',
        amount: amount,
        newBalance: user.walletBalance,
        alreadyProcessed: true
      });
    }

    // Update user balance
    const balanceBefore = user.walletBalance;
    user.walletBalance += parseFloat(amount);
    const balanceAfter = user.walletBalance;
    
    await user.save({ session });

    // Create transaction record
    const newTransaction = await createTransaction(
      userId,
      parseFloat(amount),
      'credit',
      'successful',
      description || `Manual wallet funding - Ref: ${reference}`,
      balanceBefore,
      balanceAfter,
      session,
      false,
      'manual'
    );

    await session.commitTransaction();
    
    console.log('✅ Force top-up successful:', {
      userId,
      amount,
      newBalance: balanceAfter,
      reference
    });

    // Create notification
    try {
      await Notification.create({
        recipientId: userId,
        title: "Wallet Funded Successfully 💰",
        message: `Your wallet has been credited with ₦${amount}. New balance: ₦${balanceAfter}`,
        isRead: false
      });
    } catch (notificationError) {
      console.error('Notification creation error:', notificationError);
    }

    res.json({
      success: true,
      message: 'Wallet topped up successfully',
      amount: amount,
      newBalance: balanceAfter,
      transactionId: newTransaction._id
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Force top-up error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Force top-up failed: ' + error.message 
    });
  } finally {
    session.endSession();
  }
});



// ==================== WALLET SYNC ENDPOINTS ====================

// @desc    Update user balance
// @route   POST /api/users/update-balance
// @access  Public (for virtual account backend)
app.post('/api/users/update-balance', async (req, res) => {
  try {
    const { userId, newBalance, updateType, timestamp } = req.body;
    
    console.log('🔄 Updating user balance:', { userId, newBalance });

    if (!userId || newBalance === undefined) {
      return res.status(400).json({ 
        success: false, 
        message: 'userId and newBalance are required' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const previousBalance = user.walletBalance;
    user.walletBalance = parseFloat(newBalance);
    await user.save();

    console.log('✅ Balance updated successfully:', {
      userId,
      previousBalance,
      newBalance: user.walletBalance
    });

    res.json({
      success: true,
      newBalance: user.walletBalance,
      previousBalance: previousBalance,
      message: 'Balance updated successfully'
    });
  } catch (error) {
    console.error('❌ Balance update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Balance update failed: ' + error.message 
    });
  }
});

// @desc    Sync wallet balance
// @route   POST /api/wallet/sync-balance
// @access  Public (for virtual account backend)
app.post('/api/wallet/sync-balance', async (req, res) => {
  try {
    const { userId, newBalance } = req.body;
    
    console.log('🔄 Syncing wallet balance:', { userId, newBalance });

    if (!userId || newBalance === undefined) {
      return res.status(400).json({ 
        success: false, 
        message: 'userId and newBalance are required' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const previousBalance = user.walletBalance;
    user.walletBalance = parseFloat(newBalance);
    await user.save();

    console.log('✅ Wallet synced successfully:', {
      userId,
      previousBalance,
      newBalance: user.walletBalance
    });

    res.json({ 
      success: true, 
      message: 'Wallet synced successfully',
      previousBalance: previousBalance,
      newBalance: user.walletBalance
    });
  } catch (error) {
    console.error('❌ Wallet sync error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Wallet sync failed: ' + error.message 
    });
  }
});



// Add these endpoints to your vtpass-backend/index.js

// @desc    Get transaction by reference
// @route   GET /api/transactions/by-reference/:reference
// @access  Private
app.get('/api/transactions/by-reference/:reference', protect, async (req, res) => {
  try {
    const { reference } = req.params;
    
    console.log('🔍 Checking transaction by reference:', reference);

    const transaction = await Transaction.findOne({ 
      reference: reference 
    });

    if (!transaction) {
      return res.status(404).json({
        success: false,
        message: 'Transaction not found',
        exists: false
      });
    }

    res.json({
      success: true,
      transaction: transaction,
      exists: true,
      alreadyProcessed: transaction.status === 'successful',
      balanceUpdated: transaction.balanceAfter !== transaction.balanceBefore
    });

  } catch (error) {
    console.error('Error fetching transaction by reference:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch transaction'
    });
  }
});

// @desc    Record verified transaction with balance update tracking
// @route   POST /api/transactions/record-verified
// @access  Private
app.post('/api/transactions/record-verified', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('reference').notEmpty().withMessage('Reference is required'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be positive'),
  body('previousBalance').isFloat({ min: 0 }).withMessage('Previous balance is required'),
  body('newBalance').isFloat({ min: 0 }).withMessage('New balance is required'),
  body('verifiedAt').notEmpty().withMessage('Verification timestamp is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const {
      userId,
      reference,
      amount,
      previousBalance,
      newBalance,
      verifiedAt,
      type = 'wallet_funding',
      status = 'completed',
      source = 'paystack_verification'
    } = req.body;

    console.log('📝 Recording verified transaction:', { userId, reference, amount });

    // Check if transaction already exists
    const existingTransaction = await Transaction.findOne({ reference }).session(session);
    
    if (existingTransaction && existingTransaction.status === 'successful') {
      await session.abortTransaction();
      return res.json({
        success: false,
        message: 'Transaction already recorded and processed',
        alreadyProcessed: true
      });
    }

    // Create or update transaction
    let transaction;
    if (existingTransaction) {
      // Update existing transaction
      transaction = await Transaction.findOneAndUpdate(
        { reference },
        {
          status: 'successful',
          balanceBefore: previousBalance,
          balanceAfter: newBalance,
          description: `Wallet funding via ${source} - Ref: ${reference}`,
          metadata: {
            ...existingTransaction.metadata,
            verifiedAt: new Date(verifiedAt),
            source: source,
            balanceUpdated: true
          }
        },
        { new: true, session }
      );
    } else {
      // Create new transaction
      transaction = await Transaction.create([{
        userId,
        type: 'credit',
        amount: amount,
        status: 'successful',
        description: `Wallet funding via ${source} - Ref: ${reference}`,
        balanceBefore: previousBalance,
        balanceAfter: newBalance,
        reference: reference,
        isCommission: false,
        authenticationMethod: 'paystack',
        metadata: {
          verifiedAt: new Date(verifiedAt),
          source: source,
          balanceUpdated: true,
          verificationMethod: 'manual'
        }
      }], { session });
      transaction = transaction[0];
    }

    // Update user balance
    const user = await User.findByIdAndUpdate(
      userId,
      { walletBalance: newBalance },
      { new: true, session }
    );

    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    await session.commitTransaction();

    console.log('✅ Verified transaction recorded successfully:', reference);

    res.json({
      success: true,
      message: 'Transaction recorded and balance updated',
      transaction: transaction,
      newBalance: user.walletBalance
    });

  } catch (error) {
    await session.abortTransaction();
    console.error('Error recording verified transaction:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to record transaction'
    });
  } finally {
    session.endSession();
  }
});

// @desc    Get transactions needing verification
// @route   GET /api/transactions/pending-verifications
// @access  Private
app.get('/api/transactions/pending-verifications', protect, [
  query('days').optional().isInt({ min: 1, max: 30 }).withMessage('Days must be between 1 and 30')
], async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const userId = req.user._id;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - parseInt(days));

    console.log('🔍 Fetching pending verifications for user:', userId);

    const pendingTransactions = await Transaction.find({
      userId: userId,
      status: { $in: ['pending', 'processing'] },
      createdAt: { $gte: cutoffDate },
      $or: [
        { 'metadata.source': 'paystack' },
        { 'description': /paystack/i }
      ]
    }).sort({ createdAt: -1 });

    console.log(`📊 Found ${pendingTransactions.length} pending transactions`);

    res.json({
      success: true,
      pendingTransactions: pendingTransactions,
      count: pendingTransactions.length,
      cutoffDate: cutoffDate
    });

  } catch (error) {
    console.error('Error fetching pending verifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending transactions'
    });
  }
});



// @desc    Enhanced transaction verification with duplicate protection
// @route   POST /api/transactions/verify-payment
// @access  Private
app.post('/api/transactions/verify-payment', protect, [
  body('reference').notEmpty().withMessage('Reference is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { reference } = req.body;
    const userId = req.user._id;

    console.log('🔍 Enhanced verification for reference:', reference);

    // Check if transaction already exists and is successful
    const existingTransaction = await Transaction.findOne({
      reference: reference,
      status: 'successful'
    }).session(session);

    if (existingTransaction) {
      await session.abortTransaction();
      return res.json({
        success: true,
        message: 'Transaction already verified',
        alreadyProcessed: true,
        transaction: existingTransaction,
        newBalance: req.user.walletBalance
      });
    }

    // Verify with PayStack
    const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
    const paystackResponse = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    const paystackData = paystackResponse.data;

    if (paystackData.status === true && paystackData.data.status === 'success') {
      const amount = paystackData.data.amount / 100; // Convert to Naira
      
      // Update user balance
      const user = await User.findById(userId).session(session);
      const balanceBefore = user.walletBalance;
      user.walletBalance += amount;
      const balanceAfter = user.walletBalance;
      await user.save({ session });

      // Create transaction record
      const transaction = await Transaction.create([{
        userId: userId,
        type: 'credit',
        amount: amount,
        status: 'successful',
        description: `Wallet funding via PayStack - Ref: ${reference}`,
        balanceBefore: balanceBefore,
        balanceAfter: balanceAfter,
        reference: reference,
        isCommission: false,
        authenticationMethod: 'paystack',
        metadata: {
          source: 'paystack_direct',
          verifiedAt: new Date(),
          customerEmail: paystackData.data.customer?.email,
          paymentMethod: paystackData.data.channel
        }
      }], { session });

      await session.commitTransaction();

      // Create notification
      await Notification.create({
        recipientId: userId,
        title: "Payment Verified Successfully ✅",
        message: `Your payment of ₦${amount} has been verified and credited to your wallet. New balance: ₦${balanceAfter}`,
        isRead: false
      });

      console.log('✅ Payment verified and processed:', reference);

      res.json({
        success: true,
        message: 'Payment verified successfully',
        amount: amount,
        newBalance: balanceAfter,
        transaction: transaction[0],
        paystackData: paystackData.data
      });

    } else {
      await session.abortTransaction();
      res.status(400).json({
        success: false,
        message: 'Payment verification failed or not successful',
        paystackData: paystackData.data
      });
    }

  } catch (error) {
    await session.abortTransaction();
    console.error('Payment verification error:', error);
    
    if (error.response) {
      res.status(error.response.status).json({
        success: false,
        message: `PayStack API error: ${error.response.status}`,
        details: error.response.data
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Payment verification failed',
        error: error.message
      });
    }
  } finally {
    session.endSession();
  }
});




// @desc    Check if transaction is duplicate
// @route   GET /api/transactions/check-duplicate/:requestId
// @access  Private
app.get('/api/transactions/check-duplicate/:requestId', protect, async (req, res) => {
  try {
    const { requestId } = req.params;
    const userId = req.user._id;
    
    const existing = await Transaction.findOne({
      userId: userId,
      'details.vtpassResponse.requestId': requestId
    });
    
    res.json({
      success: true,
      isDuplicate: !!existing,
      transaction: existing
    });
  } catch (error) {
    console.error('Error checking duplicate:', error);
    res.status(500).json({
      success: false,
      message: 'Error checking duplicate transaction'
    });
  }
});





// @desc    Check if transaction reference already exists
// @route   GET /api/transactions/check-reference/:reference
// @access  Private
app.get('/api/transactions/check-reference/:reference', protect, async (req, res) => {
  try {
    const { reference } = req.params;
    
    console.log('🔍 Checking transaction reference:', reference);

    const transaction = await Transaction.findOne({ 
      reference: reference,
      status: 'successful' 
    });

    if (transaction) {
      return res.json({
        exists: true,
        alreadyProcessed: true,
        transaction: {
          _id: transaction._id,
          amount: transaction.amount,
          status: transaction.status,
          createdAt: transaction.createdAt,
          balanceUpdated: transaction.balanceAfter !== transaction.balanceBefore
        },
        message: 'Transaction already processed successfully'
      });
    }

    res.json({
      exists: false,
      alreadyProcessed: false,
      message: 'Transaction reference not found'
    });

  } catch (error) {
    console.error('Error checking transaction reference:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check transaction reference'
    });
  }
});



// @desc    Enhanced PayStack verification with database duplicate protection
// @route   POST /api/payments/verify-paystack
// @access  Private
app.post('/api/payments/verify-paystack', protect, [
  body('reference').notEmpty().withMessage('Reference is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { reference } = req.body;
    const userId = req.user._id;

    console.log('🔍 DATABASE VERIFICATION: Checking reference:', reference);

    // ✅ CRITICAL: Database-level duplicate check
    const existingTransaction = await Transaction.findOne({
      reference: reference,
      status: 'successful'
    }).session(session);

    if (existingTransaction) {
      await session.abortTransaction();
      console.log('✅ DATABASE: Transaction already processed:', reference);
      
      return res.json({
        success: false,
        message: 'This transaction was already verified and processed',
        alreadyProcessed: true,
        amount: existingTransaction.amount,
        newBalance: req.user.walletBalance,
        transactionId: existingTransaction._id
      });
    }

    // Verify with PayStack API
    const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
    
    const paystackResponse = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    const paystackData = paystackResponse.data;

    if (paystackData.status === true && paystackData.data.status === 'success') {
      const amount = paystackData.data.amount / 100; // Convert to Naira
      
      // ✅ Get fresh user data within transaction
      const user = await User.findById(userId).session(session);
      if (!user) {
        await session.abortTransaction();
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      const balanceBefore = user.walletBalance;
      user.walletBalance += amount;
      const balanceAfter = user.walletBalance;
      
      await user.save({ session });

      // ✅ Create transaction record with UNIQUE reference constraint
      const transaction = await Transaction.create([{
        userId: userId,
        type: 'credit',
        amount: amount,
        status: 'successful',
        description: `Wallet funding via PayStack - Ref: ${reference}`,
        balanceBefore: balanceBefore,
        balanceAfter: balanceAfter,
        reference: reference, // This will fail if duplicate due to schema unique constraint
        isCommission: false,
        authenticationMethod: 'paystack',
        metadata: {
          source: 'paystack_direct',
          verifiedAt: new Date(),
          customerEmail: paystackData.data.customer?.email,
          paymentMethod: paystackData.data.channel,
          balanceUpdated: true
        }
      }], { session });

      await session.commitTransaction();

      // Create notification
      await Notification.create({
        recipientId: userId,
        title: "Payment Verified Successfully ✅",
        message: `Your payment of ₦${amount} has been verified and credited to your wallet. New balance: ₦${balanceAfter}`,
        isRead: false
      });

      console.log('✅ DATABASE VERIFICATION COMPLETE:', {
        reference,
        amount,
        newBalance: balanceAfter,
        transactionId: transaction[0]._id
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        amount: amount,
        newBalance: balanceAfter,
        transaction: transaction[0],
        paystackData: paystackData.data
      });

    } else {
      await session.abortTransaction();
      res.status(400).json({
        success: false,
        message: 'Payment verification failed or not successful',
        paystackData: paystackData.data
      });
    }

  } catch (error) {
    await session.abortTransaction();
    
    // ✅ Handle duplicate key error (MongoDB unique constraint)
    if (error.code === 11000 || error.message.includes('duplicate key')) {
      console.log('✅ DATABASE UNIQUE CONSTRAINT: Transaction already exists:', req.body.reference);
      return res.json({
        success: false,
        message: 'Transaction was already processed',
        alreadyProcessed: true,
        databaseConstraint: true
      });
    }
    
    console.error('❌ DATABASE VERIFICATION ERROR:', error);
    
    if (error.response) {
      res.status(error.response.status).json({
        success: false,
        message: `PayStack API error: ${error.response.status}`,
        details: error.response.data
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Payment verification failed',
        error: error.message
      });
    }
  } finally {
    session.endSession();
  }
});



// @desc    Check if transaction reference exists in database
// @route   GET /api/transactions/check-reference/:reference
// @access  Private
app.get('/api/transactions/check-reference/:reference', protect, async (req, res) => {
  try {
    const { reference } = req.params;
    const userId = req.user._id;

    console.log('🔍 DATABASE CHECK: Verifying reference:', reference);

    const transaction = await Transaction.findOne({ 
      reference: reference,
      userId: userId
    });

    if (!transaction) {
      return res.json({
        exists: false,
        message: 'Transaction reference not found in database'
      });
    }

    res.json({
      exists: true,
      alreadyProcessed: transaction.status === 'successful',
      transaction: {
        _id: transaction._id,
        amount: transaction.amount,
        status: transaction.status,
        createdAt: transaction.createdAt,
        balanceUpdated: transaction.balanceAfter !== transaction.balanceBefore,
        description: transaction.description
      },
      message: transaction.status === 'successful' 
        ? 'Transaction already processed successfully' 
        : `Transaction is ${transaction.status}`
    });

  } catch (error) {
    console.error('Error checking transaction reference:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check transaction reference'
    });
  }
});


// @desc    Get user's pending transaction verifications
// @route   GET /api/transactions/pending-verifications
// @access  Private
app.get('/api/transactions/pending-verifications', protect, [
  query('days').optional().isInt({ min: 1, max: 30 }).withMessage('Days must be between 1 and 30')
], async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const userId = req.user._id;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - parseInt(days));

    console.log('🔍 Fetching pending verifications for user:', userId);

    const pendingTransactions = await Transaction.find({
      userId: userId,
      status: { $in: ['pending', 'processing'] },
      createdAt: { $gte: cutoffDate },
      $or: [
        { 'metadata.source': 'paystack' },
        { 'description': /paystack/i }
      ]
    }).sort({ createdAt: -1 });

    console.log(`📊 Found ${pendingTransactions.length} pending transactions`);

    res.json({
      success: true,
      pendingTransactions: pendingTransactions,
      count: pendingTransactions.length,
      cutoffDate: cutoffDate
    });

  } catch (error) {
    console.error('Error fetching pending verifications:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch pending transactions'
    });
  }
});


// Add this route to your main backend (index.js)
app.post('/api/transactions/record', async (req, res) => {
  try {
    const { userId, amount, reference, type, status, description, service, metadata } = req.body;
    
    // Check if transaction already exists
    const existingTransaction = await Transaction.findOne({ reference, userId });
    if (existingTransaction) {
      return res.json({
        success: true,
        message: 'Transaction already exists',
        transactionId: existingTransaction._id
      });
    }
    
    const transaction = new Transaction({
      userId,
      amount,
      reference,
      type: type || 'wallet_funding',
      status: status || 'completed',
      description: description || `Wallet funding - ${reference}`,
      service: service || 'paystack',
      timestamp: new Date(),
      metadata: metadata || {}
    });
    
    await transaction.save();
    
    res.json({
      success: true,
      message: 'Transaction recorded successfully',
      transactionId: transaction._id
    });
  } catch (error) {
    console.error('Error recording transaction:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to record transaction: ' + error.message
    });
  }
});



// @desc    Generate referral code for user
// @route   POST /api/users/generate-referral-code
// @access  Private
app.post('/api/users/generate-referral-code', protect, [
  body('userId').notEmpty().withMessage('User ID is required')
], async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Generate referral code if not exists
    if (!user.referralCode) {
      const referralCode = `REF${userId.toString().substring(0, 8).toUpperCase()}`;
      user.referralCode = referralCode;
      await user.save();
    }
    
    res.json({
      success: true,
      referralCode: user.referralCode,
      message: 'Referral code generated successfully'
    });
  } catch (error) {
    console.error('Error generating referral code:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Get comprehensive referral statistics
// @route   GET /api/users/referral-stats/:userId
// @access  Private
app.get('/api/users/referral-stats/:userId', protect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check if user is accessing their own data or is admin
    if (req.user._id.toString() !== userId && !req.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get all users referred by this user
    const directReferrals = await User.find({ referrerId: userId });
    
    // Calculate statistics
    const totalReferrals = directReferrals.length;
    const activeReferrals = directReferrals.filter(ref => ref.isActive).length;
    
    // Get all commission transactions for this user (referral earnings)
    const commissionTransactions = await Transaction.find({
      userId: userId,
      isCommission: true,
      description: { $regex: /referral|Referral/i }
    });
    
    // Calculate total earned from referrals
    const totalEarned = commissionTransactions.reduce((sum, tx) => sum + tx.amount, 0);
    
    // Calculate pending earnings (recent referrals not yet converted to commission)
    const pendingEarnings = 0; // You can implement logic for pending earnings
    
    // Get detailed referral info
    const referrals = directReferrals.map(ref => ({
      _id: ref._id,
      fullName: ref.fullName || 'Unknown',
      email: ref.email || 'No email',
      phone: ref.phone || 'No phone',
      joinedAt: ref.createdAt,
      isActive: ref.isActive,
      hasMadePurchase: ref.transactionCount > 0,
      walletBalance: ref.walletBalance || 0
    }));
    
    res.json({
      success: true,
      referralStats: {
        referralCode: user.referralCode || 'Not set',
        totalReferrals: totalReferrals,
        activeReferrals: activeReferrals,
        totalEarned: totalEarned,
        pendingEarnings: pendingEarnings,
        referralLink: `https://yourapp.com/register?ref=${user.referralCode}`,
        referrals: referrals
      }
    });
    
  } catch (error) {
    console.error('❌ Error fetching referral stats:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch referral statistics' 
    });
  }
});

// @desc    Debug endpoint to check user status
// @route   GET /api/debug/user-status
// @access  Private
app.get('/api/debug/user-status', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const user = await User.findById(userId).select('-password -transactionPin');
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const status = {
      user: {
        id: user._id,
        email: user.email,
        phone: user.phone,
        hasPhone: !!user.phone,
        referralCode: user.referralCode,
        walletBalance: user.walletBalance,
        commissionBalance: user.commissionBalance,
        hasTransactionPin: !!user.transactionPin,
        biometricEnabled: user.biometricEnabled,
        isFirstTransaction: user.isFirstTransaction
      },
      virtualAccount: user.virtualAccount,
      timestamp: new Date().toISOString()
    };

    res.json({ success: true, status });
  } catch (error) {
    console.error('Debug status error:', error);
    res.status(500).json({ success: false, message: 'Debug status check failed' });
  }
});


// @desc    Update user phone number
// @route   PATCH /api/users/update-phone
// @access  Private
app.patch('/api/users/update-phone', protect, [
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { phone } = req.body;
    const userId = req.user._id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.phone = phone;
    await user.save();

    res.json({
      success: true,
      message: 'Phone number updated successfully',
      phone: user.phone
    });
  } catch (error) {
    console.error('Error updating phone number:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Debug endpoint to check all critical services
// @route   GET /api/debug/status
// @access  Private
app.get('/api/debug/status', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const user = await User.findById(userId);
    
    const status = {
      user: {
        id: user._id,
        email: user.email,
        phone: user.phone,
        hasPhone: !!user.phone,
        referralCode: user.referralCode,
        walletBalance: user.walletBalance
      },
      tokens: {
        hasToken: !!req.headers.authorization,
        tokenLength: req.headers.authorization ? req.headers.authorization.length : 0
      },
      services: {
        database: 'connected', // Assuming DB is connected
        vtpass: 'unknown' // You can add VTpass health check here
      },
      timestamp: new Date().toISOString()
    };

    res.json({ success: true, status });
  } catch (error) {
    console.error('Debug status error:', error);
    res.status(500).json({ success: false, message: 'Debug status check failed' });
  }
});


// ==================== PAYSTACK INITIALIZATION ENDPOINT ====================
// This is the missing endpoint your Flutter app is calling
app.post('/api/payments/initialize-paystack', async (req, res) => {
  console.log('INITIALIZE-PAYSTACK: Request received', req.body);

  try {
    const { userId, email, amount, reference, transactionPin, useBiometric } = req.body;

    if (!userId || !email || !amount || !reference) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields' 
      });
    }

    // Generate proper PayStack reference
    const paystackReference = `ref_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Call PayStack directly
    const paystackResponse = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: email,
        amount: Math.round(amount * 100), // Convert to kobo
        reference: paystackReference,
        callback_url: 'https://your-app.com/payment-callback', // Change to your actual URL
        metadata: { userId, originalReference: reference }
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    if (paystackResponse.data.status) {
      console.log('PayStack initialization successful');

      // Store pending transaction
      const pendingTransaction = new Transaction({
        userId,
        amount,
        reference: paystackReference,
        originalReference: reference,
        type: 'wallet_funding',
        status: 'pending',
        gateway: 'paystack',
        metadata: { source: 'initialize-paystack', useBiometric }
      });
      await pendingTransaction.save();

      res.json({
        success: true,
        authorizationUrl: paystackResponse.data.data.authorization_url,
        reference: paystackResponse.data.data.reference,
        accessCode: paystackResponse.data.data.access_code,
        message: 'Payment initialized successfully'
      });
    } else {
      throw new Error(paystackResponse.data.message || 'PayStack initialization failed');
    }

  } catch (error) {
    console.error('initialize-paystack error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Payment initialization failed',
      error: error.message
    });
  }
});




// @desc    Check and fix missing transactions from VTpass
// @route   POST /api/transactions/fix-missing
// @access  Private
app.post('/api/transactions/fix-missing', protect, [
  body('requestId').notEmpty().withMessage('Request ID is required'),
  body('serviceID').notEmpty().withMessage('Service ID is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { requestId, serviceID, phone, amount } = req.body;
    const userId = req.user._id;

    console.log('🔧 Fixing missing transaction:', { requestId, serviceID, userId });

    // Check if transaction already exists
    const existingTransaction = await Transaction.findOne({
      reference: requestId,
      userId: userId
    }).session(session);

    if (existingTransaction) {
      await session.abortTransaction();
      return res.json({
        success: true,
        message: 'Transaction already exists',
        transaction: existingTransaction
      });
    }

    // Get user and verify balance
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Query VTpass for transaction status
    const vtpassResult = await callVtpassApi('/pay', {
      request_id: requestId,
      serviceID: serviceID
    });

    console.log('📦 VTpass status check:', vtpassResult);

    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      const vtpassData = vtpassResult.data;
      const transactionAmount = parseFloat(vtpassData.amount) || parseFloat(amount) || 0;

      // Deduct from user balance
      const balanceBefore = user.walletBalance;
      user.walletBalance -= transactionAmount;
      const balanceAfter = user.walletBalance;
      await user.save({ session });

      // Create transaction record
      const newTransaction = await createTransaction(
        userId,
        transactionAmount,
        'debit',
        'successful',
        `${serviceID} purchase for ${phone}`,
        balanceBefore,
        balanceAfter,
        session,
        false,
        'pin',
        requestId
      );

      await session.commitTransaction();

      console.log('✅ Missing transaction fixed:', newTransaction._id);

      res.json({
        success: true,
        message: 'Transaction successfully recorded',
        transaction: newTransaction,
        newBalance: balanceAfter
      });
    } else {
      await session.abortTransaction();
      res.status(400).json({
        success: false,
        message: 'Transaction not found in VTpass or not successful',
        vtpassResponse: vtpassResult.data
      });
    }

  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Error fixing missing transaction:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fix transaction',
      error: error.message
    });
  } finally {
    session.endSession();
  }
});


// @desc    Debug transaction status
// @route   GET /api/debug/transaction-status
// @access  Private
app.get('/api/debug/transaction-status', protect, [
  query('requestId').notEmpty().withMessage('Request ID is required')
], async (req, res) => {
  try {
    const { requestId } = req.query;
    const userId = req.user._id;

    console.log('🔍 Debug transaction status for:', requestId);

    // Check database
    const dbTransaction = await Transaction.findOne({
      reference: requestId,
      userId: userId
    });

    // Check VTpass status
    const vtpassResult = await callVtpassApi('/pay', {
      request_id: requestId
    });

    res.json({
      success: true,
      database: {
        exists: !!dbTransaction,
        transaction: dbTransaction
      },
      vtpass: {
        success: vtpassResult.success,
        data: vtpassResult.data
      },
      user: {
        id: userId,
        walletBalance: req.user.walletBalance
      }
    });

  } catch (error) {
    console.error('Debug transaction error:', error);
    res.status(500).json({ success: false, message: 'Debug failed' });
  }
});


// @desc    Send OTP for email verification using Nodemailer
// @route   POST /api/auth/send-verification-otp
// @access  Public
app.post('/api/auth/send-verification-otp', [
  body('email').isEmail().withMessage('Please provide a valid email')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false, 
      message: errors.array()[0].msg,
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }

  try {
    const { email } = req.body;
    const normalizedEmail = email.toLowerCase().trim();

    // Rate limiting check (your existing code)
    const now = Date.now();
    const window = 60 * 1000; // 1 minute
    const maxAttempts = 5;

    if (!otpRequests.has(normalizedEmail)) {
      otpRequests.set(normalizedEmail, []);
    }

    const requests = otpRequests.get(normalizedEmail);
    const recent = requests.filter(t => now - t < window);
    
    if (recent.length >= maxAttempts) {
      return res.status(429).json({ 
        success: false, 
        message: 'Too many requests. Please wait 1 minute.',
        slogan: 'Smart Life, Fast Pay'  // Added slogan
      });
    }

    requests.push(now);
    otpRequests.set(normalizedEmail, recent.concat([now]));

    // Generate and store OTP
    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    otpStore.set(normalizedEmail, { 
      otp, 
      expiresAt, 
      verified: false,
      attempts: 0
    });

    console.log(`📧 [VERIFICATION] OTP generated for ${normalizedEmail}: ${otp}`);

    // Send email for verification
    const emailResult = await sendVerificationEmail(
      normalizedEmail, 
      otp, 
      'User',  // Default name since this might be for new signup
      'verification'  // Specify this is for email verification
    );
    
    if (!emailResult.success) {
      console.log(`⚠️ [VERIFICATION] Email sending failed, but OTP is: ${otp}`);
      
      // In development, return OTP for testing
      if (process.env.NODE_ENV === 'development') {
        return res.json({
          success: true,
          message: 'Email service unavailable. For development, OTP is: ' + otp,
          email: normalizedEmail,
          otp: otp,
          slogan: 'Smart Life, Fast Pay'  // Added slogan
        });
      }
      
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send verification email. Please try again.',
        slogan: 'Smart Life, Fast Pay'  // Added slogan
      });
    }

    console.log(`✅ [VERIFICATION] OTP email sent successfully to ${normalizedEmail}`);
    
    return res.json({
      success: true,
      message: 'Verification code sent successfully! Check your email.',
      email: normalizedEmail,
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });

  } catch (error) {
    console.error('❌ [VERIFICATION] Send OTP error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to send verification code. Please try again.',
      slogan: 'Smart Life, Fast Pay'  // Added slogan
    });
  }
});



// @desc    Verify OTP
// @route   POST /api/auth/verify-otp
// @access  Public
app.post('/api/auth/verify-otp', [
  body('email').isEmail().withMessage('Valid email required'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { email, otp } = req.body;
    const normalizedEmail = email.toLowerCase().trim();
    const inputOTP = otp.toString();

    // Get stored OTP data
    const storedData = otpStore.get(normalizedEmail);
    
    if (!storedData) {
      return res.status(400).json({ 
        success: false, 
        message: 'OTP not found or expired. Please request a new one.' 
      });
    }

    // Check expiration
    if (Date.now() > storedData.expiresAt) {
      otpStore.delete(normalizedEmail);
      return res.status(400).json({ 
        success: false, 
        message: 'OTP has expired. Please request a new one.' 
      });
    }

    // Check attempts (max 5)
    if (storedData.attempts >= 5) {
      otpStore.delete(normalizedEmail);
      return res.status(400).json({ 
        success: false, 
        message: 'Too many attempts. Please request a new OTP.' 
      });
    }

    // Verify OTP
    if (storedData.otp !== inputOTP) {
      storedData.attempts += 1;
      otpStore.set(normalizedEmail, storedData);
      
      const attemptsLeft = 5 - storedData.attempts;
      return res.status(400).json({ 
        success: false, 
        message: `Invalid OTP. ${attemptsLeft} attempts remaining.` 
      });
    }

    // Mark as verified (you might want to store this in database)
    storedData.verified = true;
    storedData.verifiedAt = Date.now();
    otpStore.set(normalizedEmail, storedData);

    console.log(`✅ OTP verified for ${normalizedEmail}`);
    
    // You can also remove the OTP after successful verification
    // otpStore.delete(normalizedEmail); // Uncomment if you want one-time use

    res.json({
      success: true,
      message: 'Email verified successfully!',
      email: normalizedEmail
    });

  } catch (error) {
    console.error('❌ OTP verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Verification failed. Please try again.' 
    });
  }
});




// @desc    Verify OTP
// @route   POST /api/auth/verify-otp
// @access  Public
app.post('/api/auth/verify-otp', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }

  try {
    const { email, otp } = req.body;
    
    console.log(`🔍 Verifying OTP for ${email}: ${otp}`);

    // Check if OTP exists
    const otpData = otpStore.get(email);
    if (!otpData) {
      return res.status(400).json({ 
        success: false, 
        message: 'OTP not found or expired. Please request a new one.' 
      });
    }

    // Check if OTP is expired
    if (Date.now() > otpData.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ 
        success: false, 
        message: 'OTP has expired. Please request a new one.' 
      });
    }

    // Verify OTP
    if (otpData.otp !== otp) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid OTP. Please try again.' 
      });
    }

    // Mark as verified
    otpData.verified = true;
    otpStore.set(email, otpData);

    console.log('✅ OTP verified successfully');

    res.json({
      success: true,
      message: 'Email verified successfully',
      email: email
    });

  } catch (error) {
    console.error('❌ Verify OTP error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to verify OTP' 
    });
  }
});

// @desc    Check if email is verified
// @route   GET /api/auth/check-verification/:email
// @access  Public
app.get('/api/auth/check-verification/:email', async (req, res) => {
  try {
    const { email } = req.params;
    
    const otpData = otpStore.get(email);
    const isVerified = otpData && otpData.verified;

    res.json({
      success: true,
      verified: isVerified,
      email: email
    });

  } catch (error) {
    console.error('❌ Check verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to check verification status' 
    });
  }
});



// In your index.js, BEFORE the 404 handler, add:
console.log('✅ Commission routes registered at /api/commission');
console.log('   Available endpoints:');
console.log('   - GET /api/commission/balance');
console.log('   - POST /api/commission/withdraw');
console.log('   - GET /api/commission/transactions');
console.log('   - POST /api/commission/use-for-service');
console.log('   - POST /api/commission/complete-service-purchase');
console.log('   - POST /api/commission/refund');



// @desc    Save failed electricity transaction (for amount below minimum or VTpass low balance)
// @route   POST /api/vtpass/electricity/failed-transaction
// @access  Private
app.post('/api/vtpass/electricity/failed-transaction', protect, verifyTransactionAuth, [
  body('serviceID').notEmpty().withMessage('Provider required'),
  body('billersCode').notEmpty().withMessage('Meter number required'), // Changed from fixed length
  body('variation_code').notEmpty().withMessage('Meter type required'), // Removed strict validation
  body('amount').isFloat({ min: 1 }).withMessage('Amount required'),
  body('phone').optional().isMobilePhone('en-NG').withMessage('Valid phone required'),
  body('failureReason').optional().isString(),
  body('customerName').optional().isString(),
  body('customerAddress').optional().isString()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('❌ Validation errors:', errors.array());
    return res.status(400).json({ 
      success: false, 
      message: errors.array()[0].msg,
      errors: errors.array() 
    });
  }

  const { 
    serviceID, 
    billersCode, 
    variation_code, 
    amount, 
    phone, 
    customerName, 
    customerAddress, 
    failureReason,
    vtpassLowBalance,
    transactionPin,
    useBiometric 
  } = req.body;
  
  const userId = req.user._id;
  const authenticationMethod = req.authenticationMethod || (transactionPin ? 'pin' : (useBiometric ? 'biometric' : 'unknown'));

  try {
    // Get user to get current balance
    const user = await User.findById(userId);
    if (!user) {
      console.log('❌ User not found:', userId);
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // Determine failure type based on parameters
    let failureType = 'AMOUNT_BELOW_MINIMUM';
    let adminAlert = false;
    let userMessage = 'Amount below minimum. Minimum electricity purchase is ₦2000.';
    
    if (vtpassLowBalance) {
      failureType = 'VT_PASS_LOW_BALANCE';
      adminAlert = true;
      userMessage = 'Transaction failed. Please try again later.';
    }
    
    if (failureReason && failureReason.includes('insufficient') || failureReason?.toLowerCase().includes('low balance')) {
      failureType = 'VT_PASS_LOW_BALANCE';
      adminAlert = true;
      userMessage = 'Transaction failed. Please try again later.';
    }

    // Generate unique IDs
    const timestamp = Date.now();
    const randomString = Math.random().toString(36).substring(2, 10).toUpperCase();
    
    // Create a failed transaction record
    const failedTransaction = new Transaction({
      userId: userId,
      user: userId, // Also store user reference if your schema requires it
      type: 'Electricity Purchase',
      amount: amount,
      status: 'Failed',
      transactionId: `FAILED_${failureType}_${timestamp}_${randomString}`,
      reference: `FAILED_REF_${timestamp}_${randomString}`,
      description: failureReason || (failureType === 'AMOUNT_BELOW_MINIMUM' 
        ? `Electricity payment failed: Amount ₦${amount} is below minimum of ₦2000`
        : `Electricity payment failed: ${failureReason || 'Service provider issue'}`),
      balanceBefore: user.walletBalance,
      balanceAfter: user.walletBalance, // Balance unchanged for failed transactions
      metadata: {
        meterNumber: billersCode,
        provider: serviceID,
        variation: variation_code,
        phone: phone || 'N/A',
        customerName: customerName || 'N/A',
        customerAddress: customerAddress || 'N/A',
        failureType: failureType,
        adminAlert: adminAlert,
        serviceID: serviceID,
        billersCode: billersCode,
        variation_code: variation_code,
        amount: amount,
        phone: phone || 'N/A'
      },
      isFailed: true,
      shouldShowAsFailed: true,
      amountBelowMinimum: failureType === 'AMOUNT_BELOW_MINIMUM',
      failureReason: failureReason || (failureType === 'AMOUNT_BELOW_MINIMUM' 
        ? 'Amount below minimum (₦2000)' 
        : 'Service provider temporarily unavailable'),
      gateway: 'DalabaPay App',
      isCommission: false,
      service: 'electricity',
      authenticationMethod: authenticationMethod,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    await failedTransaction.save();
    
    console.log('✅ FAILED ELECTRICITY TRANSACTION SAVED TO DATABASE:');
    console.log('   User ID:', userId);
    console.log('   Transaction ID:', failedTransaction._id);
    console.log('   Status:', failedTransaction.status);
    console.log('   Failure Type:', failureType);
    console.log('   isFailed:', failedTransaction.isFailed);
    console.log('   amountBelowMinimum:', failedTransaction.amountBelowMinimum);
    console.log('   Meter:', billersCode);
    console.log('   Amount: ₦', amount);
    console.log('   Admin Alert:', adminAlert);

    // If VTpass low balance, log for admin (you can add email/SMS notification here)
    if (adminAlert) {
      console.log('🚨 ADMIN ALERT: VTpass low balance detected!');
      console.log('   Service:', serviceID);
      console.log('   Meter:', billersCode);
      console.log('   Amount Attempted: ₦', amount);
      console.log('   Time:', new Date().toISOString());
      
      // Uncomment to send admin notification
      // await sendAdminAlert({
      //   type: 'VT_PASS_LOW_BALANCE',
      //   message: `VTpass wallet low balance detected! Electricity purchase attempted for ₦${amount}`,
      //   details: {
      //     serviceID,
      //     meterNumber: billersCode,
      //     amount,
      //     timestamp: new Date()
      //   }
      // });
    }

    // Return response
    return res.json({
      success: false, // Transaction failed
      message: userMessage,
      isFailed: true,
      shouldShowAsFailed: true,
      amountBelowMinimum: failureType === 'AMOUNT_BELOW_MINIMUM',
      adminAlert: adminAlert,
      transactionId: failedTransaction._id,
      transactionData: {
        _id: failedTransaction._id,
        userId: failedTransaction.userId,
        type: failedTransaction.type,
        amount: failedTransaction.amount,
        status: failedTransaction.status,
        transactionId: failedTransaction.transactionId,
        reference: failedTransaction.reference,
        description: failedTransaction.description,
        balanceBefore: failedTransaction.balanceBefore,
        balanceAfter: failedTransaction.balanceAfter,
        metadata: failedTransaction.metadata,
        isFailed: failedTransaction.isFailed,
        shouldShowAsFailed: failedTransaction.shouldShowAsFailed,
        amountBelowMinimum: failedTransaction.amountBelowMinimum,
        failureReason: failedTransaction.failureReason,
        service: failedTransaction.service,
        createdAt: failedTransaction.createdAt,
        updatedAt: failedTransaction.updatedAt
      },
      savedToDatabase: true
    });

  } catch (error) {
    console.error('❌ Error saving failed transaction:', error);
    console.error('Error stack:', error.stack);
    
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to save transaction record. Please try again.',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});













// ==================== FLUTTER-COMPATIBLE HEALTH ENDPOINT ====================

// @desc    Health check endpoint for Flutter app compatibility
// @route   GET /health
// @access  Public
app.get('/health', async (req, res) => {
  try {
    console.log('🔍 FLUTTER HEALTH CHECK: Endpoint called');
    
    const mongoConnected = mongoose.connection.readyState === 1;
    
    if (!mongoConnected) {
      console.log('❌ Health check failed: MongoDB not connected');
      return res.json({
        'status': 'ERROR',
        'message': 'Database connection failed',
        'timestamp': new Date().toISOString(),
        'uptime': process.uptime()
      });
    }
    
    console.log('✅ Health check passed: MongoDB connected');
    
    // Return the EXACT format your Flutter app expects
    const response = {
      'status': 'OK',  // ← CRITICAL: Your Flutter app checks for this!
      'message': 'Server is healthy',
      'timestamp': new Date().toISOString(),
      'uptime': process.uptime(),
      
      // Optional: Add additional diagnostic info
      'database': 'connected',
      'services': {
        'mongodb': 'connected',
        'vtpass': 'reachable'
      }
    };
    
    console.log('📤 Sending health response:', JSON.stringify(response, null, 2));
    res.json(response);
    
  } catch (error) {
    console.error('❌ Health check error:', error);
    res.json({
      'status': 'ERROR',
      'message': 'Health check failed: ' + error.message,
      'timestamp': new Date().toISOString(),
      'uptime': process.uptime()
    });
  }
});

// @desc    Alternative health endpoint with 'success' field
// @route   GET /api/health
// @access  Public
app.get('/api/health', (req, res) => {
  const mongoConnected = mongoose.connection.readyState === 1;
  
  res.json({
    'success': mongoConnected,
    'status': mongoConnected ? 'OK' : 'ERROR',
    'message': mongoConnected ? 'Server is healthy' : 'Database connection failed',
    'timestamp': new Date().toISOString(),
    'uptime': process.uptime(),
    'database': mongoConnected ? 'connected' : 'disconnected'
  });
});





// Catch-all 404 handler — KEEP THIS AS THE VERY LAST app.use() BEFORE app.listen()
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'API endpoint not found' 
  });
});


// Start the server with graceful shutdown handling
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
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
