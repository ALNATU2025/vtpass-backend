
// --- File: index.js ---
const express = require('express');
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
// Standard middleware
app.use(express.json());
app.use(cors());
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
// Mongoose Models
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  transactionPin: { type: String },
  biometricEnabled: { type: Boolean, default: false },
  biometricKey: { type: String },
  biometricCredentialId: { type: String },
  walletBalance: { type: Number, default: 0 },
  commissionBalance: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  failedPinAttempts: { type: Number, default: 0 },
  pinLockedUntil: { type: Date },
  lastLoginAt: { type: Date },
  profileImage: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpire: { type: Date },
  virtualAccount: {
    assigned: { type: Boolean, default: false },
    bankName: { type: String },
    accountNumber: { type: String },
    accountName: { type: String },
  },
  refreshToken: { type: String },
}, { timestamps: true });
// Add indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ isActive: 1 });
// Authentication log schema
const authLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  action: { type: String, required: true },
  ipAddress: { type: String, required: true },
  userAgent: { type: String },
  success: { type: Boolean, required: true },
  details: { type: String },
  timestamp: { type: Date, default: Date.now }
});
// Transaction schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true, enum: ['credit', 'debit'] },
  amount: { type: Number, required: true },
  status: { type: String, required: true, enum: ['pending', 'successful', 'failed'] },
  description: { type: String, required: true },
  balanceBefore: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  reference: { type: String, required: true, unique: true },
  isCommission: { type: Boolean, default: false },
  authenticationMethod: { type: String, enum: ['pin', 'biometric', 'none'], default: 'none' },
}, { timestamps: true });
// Add indexes for performance
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ status: 1 });
// Notification schema
const notificationSchema = new mongoose.Schema({
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
}, { timestamps: true });
// Beneficiary schema
const beneficiarySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  type: { type: String, required: true, enum: ['phone', 'email'] },
  value: { type: String, required: true },
  network: { type: String },
}, { timestamps: true });
// Settings schema
const settingsSchema = new mongoose.Schema({
  appVersion: { type: String, default: '1.0.0' },
  maintenanceMode: { type: Boolean, default: false },
  minTransactionAmount: { type: Number, default: 100 },
  maxTransactionAmount: { type: Number, default: 1000000 },
  vtpassCommission: { type: Number, default: 0.05 },
  commissionRate: { type: Number, default: 0.02 },
  
  // Service Availability
  airtimeEnabled: { type: Boolean, default: true },
  dataEnabled: { type: Boolean, default: true },
  cableTvEnabled: { type: Boolean, default: true },
  electricityEnabled: { type: Boolean, default: true },
  transferEnabled: { type: Boolean, default: true },
  
  // Commission/Fee Management
  airtimeCommission: { type: Number, default: 1.5 },
  dataCommission: { type: Number, default: 1.0 },
  transferFee: { type: Number, default: 50.0 },
  isTransferFeePercentage: { type: Boolean, default: false },
  
  // User Management Defaults
  newUserDefaultWalletBalance: { type: Number, default: 0.0 },
  
  // Notification Settings
  emailNotificationsEnabled: { type: Boolean, default: true },
  pushNotificationsEnabled: { type: Boolean, default: true },
  smsNotificationsEnabled: { type: Boolean, default: false },
  notificationMessage: { type: String, default: 'System maintenance scheduled' },
  
  // Security Settings
  twoFactorAuthRequired: { type: Boolean, default: false },
  autoLogoutEnabled: { type: Boolean, default: true },
  sessionTimeout: { type: Number, default: 30 },
  transactionPinRequired: { type: Boolean, default: true },
  biometricAuthEnabled: { type: Boolean, default: true },
  
  // API Rate Limiting
  apiRateLimit: { type: Number, default: 100 },
  apiTimeWindow: { type: Number, default: 60 }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Beneficiary = mongoose.model('Beneficiary', beneficiarySchema);
const Settings = mongoose.model('Settings', settingsSchema);
const AuthLog = mongoose.model('AuthLog', authLogSchema);
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
// JWT Token Generation
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};
// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};
// Middleware to protect routes with JWT
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      if (!req.user) {
        return res.status(401).json({ success: false, message: 'Not authorized, user for token not found' });
      }
      if (!req.user.isActive) {
        return res.status(403).json({ success: false, message: 'Account has been deactivated. Please contact support.' });
      }
      next();
    } catch (error) {
      console.error('JWT verification error:', error.message);
      return res.status(401).json({ success: false, message: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized, no token' });
  }
};
// Middleware to protect routes for administrators only
const adminProtect = async (req, res, next) => {
  await protect(req, res, async () => {
    if (req.user.isAdmin) {
      return next();
    }
    
    const specificAdminUserId = process.env.SPECIFIC_ADMIN_USER_ID || "689945d4fb65f8f9179e661b";
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
// Transaction Helper Function
const createTransaction = async (userId, amount, type, status, description, balanceBefore, balanceAfter, session, isCommission = false, authenticationMethod = 'none') => {
  const newTransaction = new Transaction({
    userId,
    type,
    amount,
    status,
    description,
    balanceBefore,
    balanceAfter,
    reference: uuidv4(),
    isCommission,
    authenticationMethod
  });
  await newTransaction.save({ session });
  return newTransaction;
};
// Commission Helper Function
const calculateAndAddCommission = async (userId, amount, session) => {
  try {
    const settings = await Settings.findOne().session(session);
    const commissionRate = settings ? settings.commissionRate : 0.02;
    
    const commissionAmount = amount * commissionRate;
    
    const user = await User.findById(userId).session(session);
    if (user) {
      user.commissionBalance += commissionAmount;
      await user.save({ session });
      
      await createTransaction(
        userId,
        commissionAmount,
        'credit',
        'successful',
        `Commission earned from transaction`,
        user.commissionBalance - commissionAmount,
        user.commissionBalance,
        session,
        true,
        'none'
      );
      
      return commissionAmount;
    }
    
    return 0;
  } catch (error) {
    console.error('Error calculating commission:', error);
    return 0;
  }
};
// Helper function to log authentication attempts
const logAuthAttempt = async (userId, action, ipAddress, userAgent, success, details) => {
  try {
    await AuthLog.create({
      userId,
      action,
      ipAddress,
      userAgent,
      success,
      details
    });
  } catch (error) {
    console.error('Error logging auth attempt:', error);
  }
};
// Create default settings if they don't exist
const initializeSettings = async () => {
  try {
    const settingsCount = await Settings.countDocuments();
    if (settingsCount === 0) {
      await Settings.create({});
      console.log('Default settings created');
    }
  } catch (error) {
    console.error('Error initializing settings:', error);
  }
};
initializeSettings();
// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File size is too large. Maximum size is 2MB.' });
    }
    return res.status(400).json({ success: false, message: err.message });
  } else if (err) {
    return res.status(400).json({ success: false, message: err.message });
  }
  
  res.status(500).json({ success: false, message: 'Internal Server Error' });
});
// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});
// --- API Routes ---
// @desc    Register a new user
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
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { fullName, email, phone, password } = req.body;
  
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.create({
      fullName,
      email,
      phone,
      password: hashedPassword,
    });
    
    if (user) {
      const token = generateToken(user._id);
      const refreshToken = generateRefreshToken(user._id);
      
      // Store refresh token
      user.refreshToken = refreshToken;
      await user.save();
      
      res.status(201).json({
        success: true,
        message: 'Registration successful!',
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
    } else {
      res.status(400).json({ success: false, message: 'Invalid user data' });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Authenticate a user
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
    console.log(`Login attempt for email: ${email}`);
    
    const user = await User.findOne({ email });
    
    if (!user) {
      console.log(`User not found for email: ${email}`);
      await logAuthAttempt(null, 'login', ipAddress, userAgent, false, `Invalid email: ${email}`);
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    console.log(`User found, comparing passwords for: ${email}`);
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    
    if (!isPasswordMatch) {
      console.log(`Password mismatch for email: ${email}`);
      await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, 'Invalid password');
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      console.log(`Account deactivated for email: ${email}`);
      await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, 'Account deactivated');
      return res.status(403).json({ success: false, message: 'Your account has been deactivated. Please contact support.' });
    }
    
    console.log(`Generating tokens for user: ${email}`);
    // Update last login time
    user.lastLoginAt = getLagosTime();
    
    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    
    // Store refresh token
    user.refreshToken = refreshToken;
    await user.save();
    
    console.log(`Login successful for user: ${email}`);
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
    console.error('Login error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Refresh access token
// @route   POST /api/users/refresh-token
// @access  Public
app.post('/api/users/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ success: false, message: 'Refresh token is required' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }
    
    const token = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);
    
    // Update refresh token
    user.refreshToken = newRefreshToken;
    await user.save();
    
    res.json({
      success: true,
      token,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ success: false, message: 'Invalid refresh token' });
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
// @desc    Request password reset
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
    
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Generate reset token
    const resetToken = uuidv4();
    
    // Set token and expire time
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = new Date(getLagosTime().getTime() + 10 * 60 * 1000); // 10 minutes
    
    await user.save();
    
    // In a real implementation, you would send an email with the reset token
    // For this example, we'll just return the token in the response
    
    res.json({
      success: true,
      message: 'Password reset token generated',
      resetToken
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Reset password
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
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { resetToken, newPassword } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpire: { $gt: getLagosTime() }
    });
    
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
    }
    
    // Hash the new password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update user password and clear reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    
    await user.save();
    
    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Set up transaction PIN
// @route   POST /api/users/set-transaction-pin
// @access  Private
app.post('/api/users/set-transaction-pin', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('pin').isLength({ min: 6, max: 8 }).withMessage('PIN must be 6-8 digits').matches(/^\d+$/).withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, pin } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.get('User-Agent');
    
    if (req.user._id.toString() !== userId) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Unauthorized access');
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    // Check for common PINs
    const commonPins = ['123456', '111111', '000000', '121212', '777777', '100400', '200000', '444444', '222222', '333333', '12345678', '11111111', '00000000'];
    if (commonPins.includes(pin)) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Common PIN used');
      return res.status(400).json({ 
        success: false, 
        message: 'PIN is too common. Please choose a more secure PIN' 
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'User not found');
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Hash the PIN
    const salt = await bcrypt.genSalt(12);
    const hashedPin = await bcrypt.hash(pin, salt);
    
    user.transactionPin = hashedPin;
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    await user.save();
    
    await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, true, 'PIN set successfully');
    
    res.json({ 
      success: true, 
      message: 'Transaction PIN set successfully',
    });
  } catch (error) {
    console.error('Error setting transaction PIN:', error);
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
// @desc    Verify transaction PIN (standalone endpoint)
// @route   POST /api/users/verify-transaction-pin
// @access  Private
app.post('/api/users/verify-transaction-pin', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('transactionPin').isLength({ min: 6, max: 8 }).withMessage('PIN must be 6-8 digits').matches(/^\d+$/).withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, transactionPin } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if PIN is locked
    if (user.pinLockedUntil && user.pinLockedUntil > getLagosTime()) {
      const remainingTime = Math.ceil((user.pinLockedUntil - getLagosTime()) / 60000);
      return res.status(429).json({ 
        success: false, 
        message: `Too many failed attempts. Account locked for ${remainingTime} minutes.` 
      });
    }
    
    // Verify PIN
    const isPinMatch = await bcrypt.compare(transactionPin, user.transactionPin);
    
    if (isPinMatch) {
      // Reset failed attempts on successful PIN
      user.failedPinAttempts = 0;
      user.pinLockedUntil = null;
      await user.save();
      
      return res.json({ success: true, message: 'PIN verified successfully' });
    } else {
      // Increment failed attempts
      user.failedPinAttempts += 1;
      
      // Lock account if too many failed attempts
      if (user.failedPinAttempts >= 3) {
        user.pinLockedUntil = new Date(getLagosTime().getTime() + 15 * 60000); // Lock for 15 minutes
        await user.save();
        
        return res.status(429).json({ 
          success: false, 
          message: 'Too many failed attempts. Account locked for 15 minutes.' 
        });
      } else {
        await user.save();
        
        const remainingAttempts = 3 - user.failedPinAttempts;
        return res.status(400).json({ 
          success: false, 
          message: `Invalid transaction PIN. ${remainingAttempts} attempts remaining before lockout.` 
        });
      }
    }
  } catch (error) {
    console.error('Error verifying transaction PIN:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
// @desc    Withdraw commission to wallet
// @route   POST /api/users/withdraw-commission
// @access  Private
app.post('/api/users/withdraw-commission', protect, verifyTransactionAuth, [
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { amount } = req.body;
  const userId = req.user._id;
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (user.commissionBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Insufficient commission balance' });
    }
    
    const commissionBalanceBefore = user.commissionBalance;
    user.commissionBalance -= amount;
    const commissionBalanceAfter = user.commissionBalance;
    
    const walletBalanceBefore = user.walletBalance;
    user.walletBalance += amount;
    const walletBalanceAfter = user.walletBalance;
    
    await user.save({ session });
    
    await createTransaction(
      userId,
      amount,
      'debit',
      'successful',
      `Commission withdrawal to wallet`,
      commissionBalanceBefore,
      commissionBalanceAfter,
      session,
      true,
      req.authenticationMethod
    );
    
    await createTransaction(
      userId,
      amount,
      'credit',
      'successful',
      `Commission withdrawal from commission balance`,
      walletBalanceBefore,
      walletBalanceAfter,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({ 
      success: true, 
      message: `Commission withdrawal of ${amount} to wallet successful`,
      newCommissionBalance: commissionBalanceAfter,
      newWalletBalance: walletBalanceAfter
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error withdrawing commission:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
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
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const balanceBefore = user.walletBalance;
    user.walletBalance += amount;
    const balanceAfter = user.walletBalance;
    await user.save({ session });
    
    await createTransaction(
      userId,
      amount,
      'credit',
      'successful',
      `Admin funding of ${amount}`,
      balanceBefore,
      balanceAfter,
      session,
      false,
      'none'
    );
    
    await session.commitTransaction();
    
    res.json({ 
      success: true, 
      message: `Successfully funded user ${user.email} with ${amount}`, 
      newBalance: balanceAfter 
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error funding user:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
app.post('/api/transfer', protect, verifyTransactionAuth, [
  body('receiverEmail').isEmail().withMessage('Please provide a valid email'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { receiverEmail, amount } = req.body;
  const senderId = req.user._id;
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const sender = await User.findById(senderId).session(session);
    if (!sender) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'Sender not found' });
    }
    
    if (sender.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const receiver = await User.findOne({ email: receiverEmail }).session(session);
    if (!receiver) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'Receiver not found' });
    }
    
    if (sender._id.toString() === receiver._id.toString()) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Cannot transfer to yourself' });
    }
    
    const settings = await Settings.findOne().session(session);
    const minAmount = settings ? settings.minTransactionAmount : 100;
    const maxAmount = settings ? settings.maxTransactionAmount : 1000000;
    
    if (amount < minAmount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: `Transfer amount must be at least ${minAmount}` });
    }
    
    if (amount > maxAmount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: `Transfer amount cannot exceed ${maxAmount}` });
    }
    
    const senderBalanceBefore = sender.walletBalance;
    sender.walletBalance -= amount;
    const senderBalanceAfter = sender.walletBalance;
    await sender.save({ session });
    
    const receiverBalanceBefore = receiver.walletBalance;
    receiver.walletBalance += amount;
    const receiverBalanceAfter = receiver.walletBalance;
    await receiver.save({ session });
    
    await createTransaction(
      senderId,
      amount,
      'debit',
      'successful',
      `Transfer to ${receiverEmail}`,
      senderBalanceBefore,
      senderBalanceAfter,
      session,
      false,
      req.authenticationMethod
    );
    
    await createTransaction(
      receiver._id,
      amount,
      'credit',
      'successful',
      `Transfer from ${sender.email}`,
      receiverBalanceBefore,
      receiverBalanceAfter,
      session,
      false,
      req.authenticationMethod
    );
    
    if (sender._id.toString() !== receiver._id.toString()) {
      await calculateAndAddCommission(receiver._id, amount, session);
    }
    
    await session.commitTransaction();
    
    res.json({ 
      success: true, 
      message: `Transfer of ${amount} to ${receiverEmail} successful`,
      newSenderBalance: senderBalanceAfter
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in transfer:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
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
// @desc    Get all transactions (Admin only)
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
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({})
      .sort({ createdAt: -1 })
      .populate('userId', 'fullName email')
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments();
    
    res.json({ 
      success: true, 
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching all transactions:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
// @desc    Get user's notifications
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
    
    const notifications = await Notification.find({ recipientId: userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Notification.countDocuments({ recipientId: userId });
    
    res.json({
      success: true,
      notifications,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Mark notification as read
// @route   POST /api/notifications/:id/read
// @access  Private
app.post('/api/notifications/:id/read', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;
    
    const notification = await Notification.findById(id);
    if (!notification) {
      return res.status(404).json({ success: false, message: 'Notification not found' });
    }
    
    if (notification.recipientId.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    notification.isRead = true;
    await notification.save();
    
    res.json({ success: true, message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Send notification (Admin only)
// @route   POST /api/notifications/send
// @access  Private/Admin
app.post('/api/notifications/send', adminProtect, [
  body('title').notEmpty().withMessage('Title is required'),
  body('message').notEmpty().withMessage('Message is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { title, message, recipientId } = req.body;
    
    if (recipientId) {
      const recipient = await User.findById(recipientId);
      if (!recipient) {
        return res.status(404).json({ success: false, message: 'Recipient not found' });
      }
      
      await Notification.create({
        recipientId,
        title,
        message
      });
    } else {
      const users = await User.find({ isActive: true });
      
      const notifications = users.map(user => ({
        recipientId: user._id,
        title,
        message
      }));
      
      await Notification.insertMany(notifications);
    }
    
    res.json({ 
      success: true, 
      message: recipientId 
        ? 'Notification sent successfully' 
        : `Notification sent to all users`
    });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
// @desc    Pay for Cable TV subscription
// @route   POST /api/vtpass/tv/purchase
// @access  Private
app.post('/api/vtpass/tv/purchase', protect, verifyTransactionAuth, [
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
  console.log('Received TV purchase request.');
  console.log('Request Body:', req.body);
  
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
    
    console.log('VTPass Response for TV Purchase:', JSON.stringify(vtpassResult, null, 2));
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, session);
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `${serviceID} TV Subscription for ${billersCode}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Payment request received. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      newBalance: newBalance,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in TV payment:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
  }
});
// @desc    Purchase airtime
// @route   POST /api/vtpass/airtime/purchase
// @access  Private
app.post('/api/vtpass/airtime/purchase', protect, verifyTransactionAuth, [
  body('network').isIn(['mtn', 'airtel', 'glo', '9mobile']).withMessage('Network must be one of: mtn, airtel, glo, 9mobile'),
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
      
      await calculateAndAddCommission(userId, amount, session);
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
      req.authenticationMethod
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
// @desc    Purchase data
// @route   POST /api/vtpass/data/purchase
// @access  Private
app.post('/api/vtpass/data/purchase', protect, verifyTransactionAuth, [
  body('network').isIn(['mtn', 'airtel', 'glo', '9mobile']).withMessage('Network must be one of: mtn, airtel, glo, 9mobile'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
  body('variationCode').notEmpty().withMessage('Variation code is required'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { network, phone, variationCode, amount } = req.body;
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
      variation_code: variationCode, 
      amount, 
      request_id: reference 
    });
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, session);
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `Data purchase for ${phone} on ${network}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Data purchase initiated. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      status: newTransaction.status,
      newBalance: newBalance,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in data purchase:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
  }
});
// @desc    Verify electricity meter number
// @route   POST /api/vtpass/validate-electricity
// @access  Private
app.post('/api/vtpass/validate-electricity', protect, [
  body('serviceID').notEmpty().withMessage('Service ID is required'),
  body('billersCode').notEmpty().withMessage('Billers code is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  console.log('Received electricity meter verification request.');
  console.log('Request Body:', req.body);
  
  const { serviceID, billersCode } = req.body;
  
  try {
    const vtpassResult = await callVtpassApi('/merchant-verify', {
      serviceID,
      billersCode,
    });
    
    console.log('VTPass Electricity Verification Response:', JSON.stringify(vtpassResult, null, 2));
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      res.json({
        success: true,
        message: 'Electricity meter verified successfully.',
        data: vtpassResult.data
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Electricity meter verification failed.',
        details: vtpassResult.data
      });
    }
  } catch (error) {
    console.error('Error verifying electricity meter:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Pay for electricity
// @route   POST /api/vtpass/electricity/purchase
// @access  Private
app.post('/api/vtpass/electricity/purchase', protect, verifyTransactionAuth, [
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
  console.log('Received electricity purchase request.');
  console.log('Request Body:', req.body);
  
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
    
    console.log('VTPass Response for Electricity Purchase:', JSON.stringify(vtpassResult, null, 2));
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, session);
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `${serviceID} Electricity payment for meter ${billersCode}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Electricity payment request received. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      newBalance: newBalance,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in electricity payment:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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

// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});



// @desc    VTpass Proxy Endpoint - FIX FOR 404 ERROR
// @route   POST /api/vtpass/proxy
// @access  Private
app.post('/api/vtpass/proxy', protect, async (req, res) => {
  console.log('🔐 PROXY ENDPOINT HIT - FIXING 404 ERROR');
  console.log('📦 Received body:', req.body);

  try {
    const { request_id, serviceID, amount, phone, variation_code, billersCode } = req.body;

    // 1. Get user and check balance
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    console.log('💰 Balance check:', {
      userBalance: user.walletBalance,
      required: amount,
      sufficient: user.walletBalance >= parseFloat(amount)
    });

    if (user.walletBalance < parseFloat(amount)) {
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance}` 
      });
    }

    // 2. Prepare VTpass payload
    const vtpassPayload = {
      request_id,
      serviceID,
      amount: amount.toString(),
      phone,
    };

    if (variation_code) vtpassPayload.variation_code = variation_code;
    if (billersCode) vtpassPayload.billersCode = billersCode;

    console.log('🚀 Calling VTpass with:', vtpassPayload);

    // 3. Call VTpass
    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    console.log('📦 VTpass response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description
    });

    // 4. Handle VTpass response
    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      // SUCCESS - Deduct from balance
      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const balanceBefore = user.walletBalance;
        user.walletBalance -= parseFloat(amount);
        await user.save({ session });

        await createTransaction(
          user._id,
          parseFloat(amount),
          'debit',
          'successful',
          `${serviceID} purchase for ${phone}`,
          balanceBefore,
          user.walletBalance,
          session,
          false,
          'pin'
        );

        await session.commitTransaction();

        console.log('✅ TRANSACTION SUCCESS:', {
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance
        });

        res.json({
          success: true,
          message: 'Transaction successful',
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance,
          vtpassResponse: vtpassResult.data
        });

      } catch (transactionError) {
        await session.abortTransaction();
        console.error('❌ Transaction error:', transactionError);
        res.status(500).json({ 
          success: false, 
          message: 'Transaction processing failed' 
        });
      } finally {
        session.endSession();
      }

    } else {
      // VTpass failed
      console.log('❌ VTpass failed:', vtpassResult.data);
      res.status(400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'VTpass transaction failed',
        vtpassResponse: vtpassResult.data
      });
    }

  } catch (error) {
    console.error('❌ PROXY ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Service temporarily unavailable' 
    });
  }
});

// Add this to your main backend (vtpass-backend)
// @desc    Top up wallet from virtual account payment
// @route   POST /api/wallet/top-up
// @access  Private
app.post('/api/wallet/top-up', async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const { userId, amount, reference, description } = req.body;
        
        console.log('💰 Wallet top-up request:', { userId, amount, reference });

        if (!userId || !amount || !reference) {
            await session.abortTransaction();
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields: userId, amount, reference' 
            });
        }

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
                newBalance: user.walletBalance
            });
        }

        const balanceBefore = user.walletBalance;
        user.walletBalance += amount;
        const balanceAfter = user.walletBalance;
        
        await user.save({ session });

        // Create transaction record
        await createTransaction(
            userId,
            amount,
            'credit',
            'successful',
            description || `Wallet funding - Ref: ${reference}`,
            balanceBefore,
            balanceAfter,
            session,
            false,
            'paystack'
        );

        await session.commitTransaction();
        
        console.log('✅ Wallet top-up successful:', {
            userId,
            amount,
            newBalance: balanceAfter,
            reference
        });

        res.json({
            success: true,
            message: 'Wallet topped up successfully',
            amount: amount,
            newBalance: balanceAfter,
            transactionId: existingTransaction?._id
        });

    } catch (error) {
        await session.abortTransaction();
        console.error('❌ Wallet top-up error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Wallet top-up failed' 
        });
    } finally {
        session.endSession();
    }
});




// @desc    VTpass Proxy Endpoint (FIX FOR 404 ERROR)
// @route   POST /api/vtpass/proxy
// @access  Private
app.post('/api/vtpass/proxy', protect, async (req, res) => {
  console.log('🔐 PROXY ENDPOINT HIT - FIXING 404 ERROR');
  console.log('📦 Received body:', req.body);

  try {
    const { request_id, serviceID, amount, phone, variation_code, billersCode } = req.body;

    // 1. Get user and check balance
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    console.log('💰 Balance check:', {
      userBalance: user.walletBalance,
      required: amount,
      sufficient: user.walletBalance >= amount
    });

    if (user.walletBalance < amount) {
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance}` 
      });
    }

    // 2. Prepare VTpass payload
    const vtpassPayload = {
      request_id,
      serviceID,
      amount: amount.toString(),
      phone,
    };

    if (variation_code) vtpassPayload.variation_code = variation_code;
    if (billersCode) vtpassPayload.billersCode = billersCode;

    console.log('🚀 Calling VTpass with:', vtpassPayload);

    // 3. Call VTpass
    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    console.log('📦 VTpass response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description
    });

    // 4. Handle VTpass response
    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      // SUCCESS - Deduct from balance
      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const balanceBefore = user.walletBalance;
        user.walletBalance -= parseFloat(amount);
        await user.save({ session });

        await createTransaction(
          user._id,
          parseFloat(amount),
          'debit',
          'successful',
          `${serviceID} airtime for ${phone}`,
          balanceBefore,
          user.walletBalance,
          session,
          false,
          'pin'
        );

        await session.commitTransaction();

        console.log('✅ TRANSACTION SUCCESS:', {
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance
        });

        res.json({
          success: true,
          message: 'Airtime purchase successful',
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance,
          vtpassResponse: vtpassResult.data
        });

      } catch (transactionError) {
        await session.abortTransaction();
        console.error('❌ Transaction error:', transactionError);
        res.status(500).json({ 
          success: false, 
          message: 'Transaction processing failed' 
        });
      } finally {
        session.endSession();
      }

    } else {
      // VTpass failed
      console.log('❌ VTpass failed:', vtpassResult.data);
      res.status(400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'VTpass transaction failed',
        vtpassResponse: vtpassResult.data
      });
    }

  } catch (error) {
    console.error('❌ PROXY ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Service temporarily unavailable' 
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

This is my backend 


// --- File: index.js ---
const express = require('express');
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
// Standard middleware
app.use(express.json());
app.use(cors());
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
// Mongoose Models
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  transactionPin: { type: String },
  biometricEnabled: { type: Boolean, default: false },
  biometricKey: { type: String },
  biometricCredentialId: { type: String },
  walletBalance: { type: Number, default: 0 },
  commissionBalance: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  failedPinAttempts: { type: Number, default: 0 },
  pinLockedUntil: { type: Date },
  lastLoginAt: { type: Date },
  profileImage: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpire: { type: Date },
  virtualAccount: {
    assigned: { type: Boolean, default: false },
    bankName: { type: String },
    accountNumber: { type: String },
    accountName: { type: String },
  },
  refreshToken: { type: String },
}, { timestamps: true });
// Add indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ phone: 1 });
userSchema.index({ isActive: 1 });
// Authentication log schema
const authLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  action: { type: String, required: true },
  ipAddress: { type: String, required: true },
  userAgent: { type: String },
  success: { type: Boolean, required: true },
  details: { type: String },
  timestamp: { type: Date, default: Date.now }
});
// Transaction schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true, enum: ['credit', 'debit'] },
  amount: { type: Number, required: true },
  status: { type: String, required: true, enum: ['pending', 'successful', 'failed'] },
  description: { type: String, required: true },
  balanceBefore: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  reference: { type: String, required: true, unique: true },
  isCommission: { type: Boolean, default: false },
  authenticationMethod: { type: String, enum: ['pin', 'biometric', 'none'], default: 'none' },
}, { timestamps: true });
// Add indexes for performance
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ status: 1 });
// Notification schema
const notificationSchema = new mongoose.Schema({
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
}, { timestamps: true });
// Beneficiary schema
const beneficiarySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  type: { type: String, required: true, enum: ['phone', 'email'] },
  value: { type: String, required: true },
  network: { type: String },
}, { timestamps: true });
// Settings schema
const settingsSchema = new mongoose.Schema({
  appVersion: { type: String, default: '1.0.0' },
  maintenanceMode: { type: Boolean, default: false },
  minTransactionAmount: { type: Number, default: 100 },
  maxTransactionAmount: { type: Number, default: 1000000 },
  vtpassCommission: { type: Number, default: 0.05 },
  commissionRate: { type: Number, default: 0.02 },
  
  // Service Availability
  airtimeEnabled: { type: Boolean, default: true },
  dataEnabled: { type: Boolean, default: true },
  cableTvEnabled: { type: Boolean, default: true },
  electricityEnabled: { type: Boolean, default: true },
  transferEnabled: { type: Boolean, default: true },
  
  // Commission/Fee Management
  airtimeCommission: { type: Number, default: 1.5 },
  dataCommission: { type: Number, default: 1.0 },
  transferFee: { type: Number, default: 50.0 },
  isTransferFeePercentage: { type: Boolean, default: false },
  
  // User Management Defaults
  newUserDefaultWalletBalance: { type: Number, default: 0.0 },
  
  // Notification Settings
  emailNotificationsEnabled: { type: Boolean, default: true },
  pushNotificationsEnabled: { type: Boolean, default: true },
  smsNotificationsEnabled: { type: Boolean, default: false },
  notificationMessage: { type: String, default: 'System maintenance scheduled' },
  
  // Security Settings
  twoFactorAuthRequired: { type: Boolean, default: false },
  autoLogoutEnabled: { type: Boolean, default: true },
  sessionTimeout: { type: Number, default: 30 },
  transactionPinRequired: { type: Boolean, default: true },
  biometricAuthEnabled: { type: Boolean, default: true },
  
  // API Rate Limiting
  apiRateLimit: { type: Number, default: 100 },
  apiTimeWindow: { type: Number, default: 60 }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Beneficiary = mongoose.model('Beneficiary', beneficiarySchema);
const Settings = mongoose.model('Settings', settingsSchema);
const AuthLog = mongoose.model('AuthLog', authLogSchema);
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
// JWT Token Generation
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1h' });
};
// Generate Refresh Token
const generateRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};
// Middleware to protect routes with JWT
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      if (!req.user) {
        return res.status(401).json({ success: false, message: 'Not authorized, user for token not found' });
      }
      if (!req.user.isActive) {
        return res.status(403).json({ success: false, message: 'Account has been deactivated. Please contact support.' });
      }
      next();
    } catch (error) {
      console.error('JWT verification error:', error.message);
      return res.status(401).json({ success: false, message: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    return res.status(401).json({ success: false, message: 'Not authorized, no token' });
  }
};
// Middleware to protect routes for administrators only
const adminProtect = async (req, res, next) => {
  await protect(req, res, async () => {
    if (req.user.isAdmin) {
      return next();
    }
    
    const specificAdminUserId = process.env.SPECIFIC_ADMIN_USER_ID || "689945d4fb65f8f9179e661b";
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
// Transaction Helper Function
const createTransaction = async (userId, amount, type, status, description, balanceBefore, balanceAfter, session, isCommission = false, authenticationMethod = 'none') => {
  const newTransaction = new Transaction({
    userId,
    type,
    amount,
    status,
    description,
    balanceBefore,
    balanceAfter,
    reference: uuidv4(),
    isCommission,
    authenticationMethod
  });
  await newTransaction.save({ session });
  return newTransaction;
};
// Commission Helper Function
const calculateAndAddCommission = async (userId, amount, session) => {
  try {
    const settings = await Settings.findOne().session(session);
    const commissionRate = settings ? settings.commissionRate : 0.02;
    
    const commissionAmount = amount * commissionRate;
    
    const user = await User.findById(userId).session(session);
    if (user) {
      user.commissionBalance += commissionAmount;
      await user.save({ session });
      
      await createTransaction(
        userId,
        commissionAmount,
        'credit',
        'successful',
        `Commission earned from transaction`,
        user.commissionBalance - commissionAmount,
        user.commissionBalance,
        session,
        true,
        'none'
      );
      
      return commissionAmount;
    }
    
    return 0;
  } catch (error) {
    console.error('Error calculating commission:', error);
    return 0;
  }
};
// Helper function to log authentication attempts
const logAuthAttempt = async (userId, action, ipAddress, userAgent, success, details) => {
  try {
    await AuthLog.create({
      userId,
      action,
      ipAddress,
      userAgent,
      success,
      details
    });
  } catch (error) {
    console.error('Error logging auth attempt:', error);
  }
};
// Create default settings if they don't exist
const initializeSettings = async () => {
  try {
    const settingsCount = await Settings.countDocuments();
    if (settingsCount === 0) {
      await Settings.create({});
      console.log('Default settings created');
    }
  } catch (error) {
    console.error('Error initializing settings:', error);
  }
};
initializeSettings();
// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File size is too large. Maximum size is 2MB.' });
    }
    return res.status(400).json({ success: false, message: err.message });
  } else if (err) {
    return res.status(400).json({ success: false, message: err.message });
  }
  
  res.status(500).json({ success: false, message: 'Internal Server Error' });
});
// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});
// --- API Routes ---
// @desc    Register a new user
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
  })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { fullName, email, phone, password } = req.body;
  
  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }
    
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.create({
      fullName,
      email,
      phone,
      password: hashedPassword,
    });
    
    if (user) {
      const token = generateToken(user._id);
      const refreshToken = generateRefreshToken(user._id);
      
      // Store refresh token
      user.refreshToken = refreshToken;
      await user.save();
      
      res.status(201).json({
        success: true,
        message: 'Registration successful!',
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
    } else {
      res.status(400).json({ success: false, message: 'Invalid user data' });
    }
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Authenticate a user
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
    console.log(`Login attempt for email: ${email}`);
    
    const user = await User.findOne({ email });
    
    if (!user) {
      console.log(`User not found for email: ${email}`);
      await logAuthAttempt(null, 'login', ipAddress, userAgent, false, `Invalid email: ${email}`);
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    console.log(`User found, comparing passwords for: ${email}`);
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    
    if (!isPasswordMatch) {
      console.log(`Password mismatch for email: ${email}`);
      await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, 'Invalid password');
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      console.log(`Account deactivated for email: ${email}`);
      await logAuthAttempt(user._id, 'login', ipAddress, userAgent, false, 'Account deactivated');
      return res.status(403).json({ success: false, message: 'Your account has been deactivated. Please contact support.' });
    }
    
    console.log(`Generating tokens for user: ${email}`);
    // Update last login time
    user.lastLoginAt = getLagosTime();
    
    // Generate tokens
    const token = generateToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    
    // Store refresh token
    user.refreshToken = refreshToken;
    await user.save();
    
    console.log(`Login successful for user: ${email}`);
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
    console.error('Login error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Refresh access token
// @route   POST /api/users/refresh-token
// @access  Public
app.post('/api/users/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ success: false, message: 'Refresh token is required' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);
    
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }
    
    const token = generateToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);
    
    // Update refresh token
    user.refreshToken = newRefreshToken;
    await user.save();
    
    res.json({
      success: true,
      token,
      refreshToken: newRefreshToken
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(401).json({ success: false, message: 'Invalid refresh token' });
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
// @desc    Request password reset
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
    
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Generate reset token
    const resetToken = uuidv4();
    
    // Set token and expire time
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = new Date(getLagosTime().getTime() + 10 * 60 * 1000); // 10 minutes
    
    await user.save();
    
    // In a real implementation, you would send an email with the reset token
    // For this example, we'll just return the token in the response
    
    res.json({
      success: true,
      message: 'Password reset token generated',
      resetToken
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Reset password
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
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { resetToken, newPassword } = req.body;
    
    const user = await User.findOne({
      resetPasswordToken: resetToken,
      resetPasswordExpire: { $gt: getLagosTime() }
    });
    
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
    }
    
    // Hash the new password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update user password and clear reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    
    await user.save();
    
    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Set up transaction PIN
// @route   POST /api/users/set-transaction-pin
// @access  Private
app.post('/api/users/set-transaction-pin', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('pin').isLength({ min: 6, max: 8 }).withMessage('PIN must be 6-8 digits').matches(/^\d+$/).withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, pin } = req.body;
    const ipAddress = req.ip;
    const userAgent = req.get('User-Agent');
    
    if (req.user._id.toString() !== userId) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Unauthorized access');
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    // Check for common PINs
    const commonPins = ['123456', '111111', '000000', '121212', '777777', '100400', '200000', '444444', '222222', '333333', '12345678', '11111111', '00000000'];
    if (commonPins.includes(pin)) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Common PIN used');
      return res.status(400).json({ 
        success: false, 
        message: 'PIN is too common. Please choose a more secure PIN' 
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'User not found');
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Hash the PIN
    const salt = await bcrypt.genSalt(12);
    const hashedPin = await bcrypt.hash(pin, salt);
    
    user.transactionPin = hashedPin;
    user.failedPinAttempts = 0;
    user.pinLockedUntil = null;
    await user.save();
    
    await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, true, 'PIN set successfully');
    
    res.json({ 
      success: true, 
      message: 'Transaction PIN set successfully',
    });
  } catch (error) {
    console.error('Error setting transaction PIN:', error);
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
// @desc    Verify transaction PIN (standalone endpoint)
// @route   POST /api/users/verify-transaction-pin
// @access  Private
app.post('/api/users/verify-transaction-pin', protect, [
  body('userId').notEmpty().withMessage('User ID is required'),
  body('transactionPin').isLength({ min: 6, max: 8 }).withMessage('PIN must be 6-8 digits').matches(/^\d+$/).withMessage('PIN must contain only digits')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { userId, transactionPin } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Check if PIN is locked
    if (user.pinLockedUntil && user.pinLockedUntil > getLagosTime()) {
      const remainingTime = Math.ceil((user.pinLockedUntil - getLagosTime()) / 60000);
      return res.status(429).json({ 
        success: false, 
        message: `Too many failed attempts. Account locked for ${remainingTime} minutes.` 
      });
    }
    
    // Verify PIN
    const isPinMatch = await bcrypt.compare(transactionPin, user.transactionPin);
    
    if (isPinMatch) {
      // Reset failed attempts on successful PIN
      user.failedPinAttempts = 0;
      user.pinLockedUntil = null;
      await user.save();
      
      return res.json({ success: true, message: 'PIN verified successfully' });
    } else {
      // Increment failed attempts
      user.failedPinAttempts += 1;
      
      // Lock account if too many failed attempts
      if (user.failedPinAttempts >= 3) {
        user.pinLockedUntil = new Date(getLagosTime().getTime() + 15 * 60000); // Lock for 15 minutes
        await user.save();
        
        return res.status(429).json({ 
          success: false, 
          message: 'Too many failed attempts. Account locked for 15 minutes.' 
        });
      } else {
        await user.save();
        
        const remainingAttempts = 3 - user.failedPinAttempts;
        return res.status(400).json({ 
          success: false, 
          message: `Invalid transaction PIN. ${remainingAttempts} attempts remaining before lockout.` 
        });
      }
    }
  } catch (error) {
    console.error('Error verifying transaction PIN:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
// @desc    Withdraw commission to wallet
// @route   POST /api/users/withdraw-commission
// @access  Private
app.post('/api/users/withdraw-commission', protect, verifyTransactionAuth, [
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { amount } = req.body;
  const userId = req.user._id;
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    if (user.commissionBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Insufficient commission balance' });
    }
    
    const commissionBalanceBefore = user.commissionBalance;
    user.commissionBalance -= amount;
    const commissionBalanceAfter = user.commissionBalance;
    
    const walletBalanceBefore = user.walletBalance;
    user.walletBalance += amount;
    const walletBalanceAfter = user.walletBalance;
    
    await user.save({ session });
    
    await createTransaction(
      userId,
      amount,
      'debit',
      'successful',
      `Commission withdrawal to wallet`,
      commissionBalanceBefore,
      commissionBalanceAfter,
      session,
      true,
      req.authenticationMethod
    );
    
    await createTransaction(
      userId,
      amount,
      'credit',
      'successful',
      `Commission withdrawal from commission balance`,
      walletBalanceBefore,
      walletBalanceAfter,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({ 
      success: true, 
      message: `Commission withdrawal of ${amount} to wallet successful`,
      newCommissionBalance: commissionBalanceAfter,
      newWalletBalance: walletBalanceAfter
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error withdrawing commission:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
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
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const balanceBefore = user.walletBalance;
    user.walletBalance += amount;
    const balanceAfter = user.walletBalance;
    await user.save({ session });
    
    await createTransaction(
      userId,
      amount,
      'credit',
      'successful',
      `Admin funding of ${amount}`,
      balanceBefore,
      balanceAfter,
      session,
      false,
      'none'
    );
    
    await session.commitTransaction();
    
    res.json({ 
      success: true, 
      message: `Successfully funded user ${user.email} with ${amount}`, 
      newBalance: balanceAfter 
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error funding user:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
app.post('/api/transfer', protect, verifyTransactionAuth, [
  body('receiverEmail').isEmail().withMessage('Please provide a valid email'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { receiverEmail, amount } = req.body;
  const senderId = req.user._id;
  
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const sender = await User.findById(senderId).session(session);
    if (!sender) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'Sender not found' });
    }
    
    if (sender.walletBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }
    
    const receiver = await User.findOne({ email: receiverEmail }).session(session);
    if (!receiver) {
      await session.abortTransaction();
      return res.status(404).json({ success: false, message: 'Receiver not found' });
    }
    
    if (sender._id.toString() === receiver._id.toString()) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: 'Cannot transfer to yourself' });
    }
    
    const settings = await Settings.findOne().session(session);
    const minAmount = settings ? settings.minTransactionAmount : 100;
    const maxAmount = settings ? settings.maxTransactionAmount : 1000000;
    
    if (amount < minAmount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: `Transfer amount must be at least ${minAmount}` });
    }
    
    if (amount > maxAmount) {
      await session.abortTransaction();
      return res.status(400).json({ success: false, message: `Transfer amount cannot exceed ${maxAmount}` });
    }
    
    const senderBalanceBefore = sender.walletBalance;
    sender.walletBalance -= amount;
    const senderBalanceAfter = sender.walletBalance;
    await sender.save({ session });
    
    const receiverBalanceBefore = receiver.walletBalance;
    receiver.walletBalance += amount;
    const receiverBalanceAfter = receiver.walletBalance;
    await receiver.save({ session });
    
    await createTransaction(
      senderId,
      amount,
      'debit',
      'successful',
      `Transfer to ${receiverEmail}`,
      senderBalanceBefore,
      senderBalanceAfter,
      session,
      false,
      req.authenticationMethod
    );
    
    await createTransaction(
      receiver._id,
      amount,
      'credit',
      'successful',
      `Transfer from ${sender.email}`,
      receiverBalanceBefore,
      receiverBalanceAfter,
      session,
      false,
      req.authenticationMethod
    );
    
    if (sender._id.toString() !== receiver._id.toString()) {
      await calculateAndAddCommission(receiver._id, amount, session);
    }
    
    await session.commitTransaction();
    
    res.json({ 
      success: true, 
      message: `Transfer of ${amount} to ${receiverEmail} successful`,
      newSenderBalance: senderBalanceAfter
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in transfer:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
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
// @desc    Get all transactions (Admin only)
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
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;
    
    const transactions = await Transaction.find({})
      .sort({ createdAt: -1 })
      .populate('userId', 'fullName email')
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments();
    
    res.json({ 
      success: true, 
      transactions,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching all transactions:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
// @desc    Get user's notifications
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
    
    const notifications = await Notification.find({ recipientId: userId })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Notification.countDocuments({ recipientId: userId });
    
    res.json({
      success: true,
      notifications,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalItems: total
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Mark notification as read
// @route   POST /api/notifications/:id/read
// @access  Private
app.post('/api/notifications/:id/read', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user._id;
    
    const notification = await Notification.findById(id);
    if (!notification) {
      return res.status(404).json({ success: false, message: 'Notification not found' });
    }
    
    if (notification.recipientId.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    notification.isRead = true;
    await notification.save();
    
    res.json({ success: true, message: 'Notification marked as read' });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Send notification (Admin only)
// @route   POST /api/notifications/send
// @access  Private/Admin
app.post('/api/notifications/send', adminProtect, [
  body('title').notEmpty().withMessage('Title is required'),
  body('message').notEmpty().withMessage('Message is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  try {
    const { title, message, recipientId } = req.body;
    
    if (recipientId) {
      const recipient = await User.findById(recipientId);
      if (!recipient) {
        return res.status(404).json({ success: false, message: 'Recipient not found' });
      }
      
      await Notification.create({
        recipientId,
        title,
        message
      });
    } else {
      const users = await User.find({ isActive: true });
      
      const notifications = users.map(user => ({
        recipientId: user._id,
        title,
        message
      }));
      
      await Notification.insertMany(notifications);
    }
    
    res.json({ 
      success: true, 
      message: recipientId 
        ? 'Notification sent successfully' 
        : `Notification sent to all users`
    });
  } catch (error) {
    console.error('Error sending notification:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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
// @desc    Pay for Cable TV subscription
// @route   POST /api/vtpass/tv/purchase
// @access  Private
app.post('/api/vtpass/tv/purchase', protect, verifyTransactionAuth, [
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
  console.log('Received TV purchase request.');
  console.log('Request Body:', req.body);
  
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
    
    console.log('VTPass Response for TV Purchase:', JSON.stringify(vtpassResult, null, 2));
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, session);
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `${serviceID} TV Subscription for ${billersCode}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Payment request received. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      newBalance: newBalance,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in TV payment:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
  }
});
// @desc    Purchase airtime
// @route   POST /api/vtpass/airtime/purchase
// @access  Private
app.post('/api/vtpass/airtime/purchase', protect, verifyTransactionAuth, [
  body('network').isIn(['mtn', 'airtel', 'glo', '9mobile']).withMessage('Network must be one of: mtn, airtel, glo, 9mobile'),
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
      
      await calculateAndAddCommission(userId, amount, session);
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
      req.authenticationMethod
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
// @desc    Purchase data
// @route   POST /api/vtpass/data/purchase
// @access  Private
app.post('/api/vtpass/data/purchase', protect, verifyTransactionAuth, [
  body('network').isIn(['mtn', 'airtel', 'glo', '9mobile']).withMessage('Network must be one of: mtn, airtel, glo, 9mobile'),
  body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
  body('variationCode').notEmpty().withMessage('Variation code is required'),
  body('amount').isFloat({ min: 0.01 }).withMessage('Amount must be a positive number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  const { network, phone, variationCode, amount } = req.body;
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
      variation_code: variationCode, 
      amount, 
      request_id: reference 
    });
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, session);
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `Data purchase for ${phone} on ${network}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Data purchase initiated. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      status: newTransaction.status,
      newBalance: newBalance,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in data purchase:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
  }
});
// @desc    Verify electricity meter number
// @route   POST /api/vtpass/validate-electricity
// @access  Private
app.post('/api/vtpass/validate-electricity', protect, [
  body('serviceID').notEmpty().withMessage('Service ID is required'),
  body('billersCode').notEmpty().withMessage('Billers code is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, message: errors.array()[0].msg });
  }
  console.log('Received electricity meter verification request.');
  console.log('Request Body:', req.body);
  
  const { serviceID, billersCode } = req.body;
  
  try {
    const vtpassResult = await callVtpassApi('/merchant-verify', {
      serviceID,
      billersCode,
    });
    
    console.log('VTPass Electricity Verification Response:', JSON.stringify(vtpassResult, null, 2));
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      res.json({
        success: true,
        message: 'Electricity meter verified successfully.',
        data: vtpassResult.data
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Electricity meter verification failed.',
        details: vtpassResult.data
      });
    }
  } catch (error) {
    console.error('Error verifying electricity meter:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// @desc    Pay for electricity
// @route   POST /api/vtpass/electricity/purchase
// @access  Private
app.post('/api/vtpass/electricity/purchase', protect, verifyTransactionAuth, [
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
  console.log('Received electricity purchase request.');
  console.log('Request Body:', req.body);
  
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
    
    console.log('VTPass Response for Electricity Purchase:', JSON.stringify(vtpassResult, null, 2));
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
      
      await calculateAndAddCommission(userId, amount, session);
    } else {
      await session.abortTransaction();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = await createTransaction(
      userId,
      amount,
      'debit',
      transactionStatus,
      `${serviceID} Electricity payment for meter ${billersCode}`,
      balanceBefore,
      newBalance,
      session,
      false,
      req.authenticationMethod
    );
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Electricity payment request received. Status: ${newTransaction.status}.`,
      transactionId: newTransaction._id,
      newBalance: newBalance,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error in electricity payment:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
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

// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});



// @desc    VTpass Proxy Endpoint - FIX FOR 404 ERROR
// @route   POST /api/vtpass/proxy
// @access  Private
app.post('/api/vtpass/proxy', protect, async (req, res) => {
  console.log('🔐 PROXY ENDPOINT HIT - FIXING 404 ERROR');
  console.log('📦 Received body:', req.body);

  try {
    const { request_id, serviceID, amount, phone, variation_code, billersCode } = req.body;

    // 1. Get user and check balance
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    console.log('💰 Balance check:', {
      userBalance: user.walletBalance,
      required: amount,
      sufficient: user.walletBalance >= parseFloat(amount)
    });

    if (user.walletBalance < parseFloat(amount)) {
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance}` 
      });
    }

    // 2. Prepare VTpass payload
    const vtpassPayload = {
      request_id,
      serviceID,
      amount: amount.toString(),
      phone,
    };

    if (variation_code) vtpassPayload.variation_code = variation_code;
    if (billersCode) vtpassPayload.billersCode = billersCode;

    console.log('🚀 Calling VTpass with:', vtpassPayload);

    // 3. Call VTpass
    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    console.log('📦 VTpass response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description
    });

    // 4. Handle VTpass response
    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      // SUCCESS - Deduct from balance
      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const balanceBefore = user.walletBalance;
        user.walletBalance -= parseFloat(amount);
        await user.save({ session });

        await createTransaction(
          user._id,
          parseFloat(amount),
          'debit',
          'successful',
          `${serviceID} purchase for ${phone}`,
          balanceBefore,
          user.walletBalance,
          session,
          false,
          'pin'
        );

        await session.commitTransaction();

        console.log('✅ TRANSACTION SUCCESS:', {
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance
        });

        res.json({
          success: true,
          message: 'Transaction successful',
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance,
          vtpassResponse: vtpassResult.data
        });

      } catch (transactionError) {
        await session.abortTransaction();
        console.error('❌ Transaction error:', transactionError);
        res.status(500).json({ 
          success: false, 
          message: 'Transaction processing failed' 
        });
      } finally {
        session.endSession();
      }

    } else {
      // VTpass failed
      console.log('❌ VTpass failed:', vtpassResult.data);
      res.status(400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'VTpass transaction failed',
        vtpassResponse: vtpassResult.data
      });
    }

  } catch (error) {
    console.error('❌ PROXY ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Service temporarily unavailable' 
    });
  }
});

// Add this to your main backend (vtpass-backend)
// @desc    Top up wallet from virtual account payment
// @route   POST /api/wallet/top-up
// @access  Private
app.post('/api/wallet/top-up', async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const { userId, amount, reference, description } = req.body;
        
        console.log('💰 Wallet top-up request:', { userId, amount, reference });

        if (!userId || !amount || !reference) {
            await session.abortTransaction();
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields: userId, amount, reference' 
            });
        }

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
                newBalance: user.walletBalance
            });
        }

        const balanceBefore = user.walletBalance;
        user.walletBalance += amount;
        const balanceAfter = user.walletBalance;
        
        await user.save({ session });

        // Create transaction record
        await createTransaction(
            userId,
            amount,
            'credit',
            'successful',
            description || `Wallet funding - Ref: ${reference}`,
            balanceBefore,
            balanceAfter,
            session,
            false,
            'paystack'
        );

        await session.commitTransaction();
        
        console.log('✅ Wallet top-up successful:', {
            userId,
            amount,
            newBalance: balanceAfter,
            reference
        });

        res.json({
            success: true,
            message: 'Wallet topped up successfully',
            amount: amount,
            newBalance: balanceAfter,
            transactionId: existingTransaction?._id
        });

    } catch (error) {
        await session.abortTransaction();
        console.error('❌ Wallet top-up error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Wallet top-up failed' 
        });
    } finally {
        session.endSession();
    }
});




// @desc    VTpass Proxy Endpoint (FIX FOR 404 ERROR)
// @route   POST /api/vtpass/proxy
// @access  Private
app.post('/api/vtpass/proxy', protect, async (req, res) => {
  console.log('🔐 PROXY ENDPOINT HIT - FIXING 404 ERROR');
  console.log('📦 Received body:', req.body);

  try {
    const { request_id, serviceID, amount, phone, variation_code, billersCode } = req.body;

    // 1. Get user and check balance
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    console.log('💰 Balance check:', {
      userBalance: user.walletBalance,
      required: amount,
      sufficient: user.walletBalance >= amount
    });

    if (user.walletBalance < amount) {
      return res.status(400).json({ 
        success: false, 
        message: `Insufficient balance. Required: ₦${amount}, Available: ₦${user.walletBalance}` 
      });
    }

    // 2. Prepare VTpass payload
    const vtpassPayload = {
      request_id,
      serviceID,
      amount: amount.toString(),
      phone,
    };

    if (variation_code) vtpassPayload.variation_code = variation_code;
    if (billersCode) vtpassPayload.billersCode = billersCode;

    console.log('🚀 Calling VTpass with:', vtpassPayload);

    // 3. Call VTpass
    const vtpassResult = await callVtpassApi('/pay', vtpassPayload);

    console.log('📦 VTpass response:', {
      success: vtpassResult.success,
      code: vtpassResult.data?.code,
      message: vtpassResult.data?.response_description
    });

    // 4. Handle VTpass response
    if (vtpassResult.success && vtpassResult.data?.code === '000') {
      // SUCCESS - Deduct from balance
      const session = await mongoose.startSession();
      session.startTransaction();

      try {
        const balanceBefore = user.walletBalance;
        user.walletBalance -= parseFloat(amount);
        await user.save({ session });

        await createTransaction(
          user._id,
          parseFloat(amount),
          'debit',
          'successful',
          `${serviceID} airtime for ${phone}`,
          balanceBefore,
          user.walletBalance,
          session,
          false,
          'pin'
        );

        await session.commitTransaction();

        console.log('✅ TRANSACTION SUCCESS:', {
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance
        });

        res.json({
          success: true,
          message: 'Airtime purchase successful',
          transactionId: vtpassResult.data.content?.transactions?.transactionId,
          newBalance: user.walletBalance,
          vtpassResponse: vtpassResult.data
        });

      } catch (transactionError) {
        await session.abortTransaction();
        console.error('❌ Transaction error:', transactionError);
        res.status(500).json({ 
          success: false, 
          message: 'Transaction processing failed' 
        });
      } finally {
        session.endSession();
      }

    } else {
      // VTpass failed
      console.log('❌ VTpass failed:', vtpassResult.data);
      res.status(400).json({
        success: false,
        message: vtpassResult.data?.response_description || 'VTpass transaction failed',
        vtpassResponse: vtpassResult.data
      });
    }

  } catch (error) {
    console.error('❌ PROXY ERROR:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Service temporarily unavailable' 
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


// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
