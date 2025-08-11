// --- File: server.js ---
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const dotenv = require('dotenv');
dotenv.config();

// Mongoose Models
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  transactionPin: { type: String }, // Added for transaction PIN
  biometricEnabled: { type: Boolean, default: false }, // Added for biometric auth
  walletBalance: { type: Number, default: 0 },
  commissionBalance: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  virtualAccount: {
    assigned: { type: Boolean, default: false },
    bankName: { type: String },
    accountNumber: { type: String },
    accountName: { type: String },
  },
}, { timestamps: true });

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
  authenticationMethod: { type: String, enum: ['pin', 'biometric', 'none'], default: 'none' }, // Added to track auth method
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
}, { timestamps: true });

const beneficiarySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  type: { type: String, required: true, enum: ['phone', 'email'] },
  value: { type: String, required: true },
  network: { type: String },
}, { timestamps: true });

// Updated settings schema to match frontend expectations
const settingsSchema = new mongoose.Schema({
  // Existing fields
  appVersion: { type: String, default: '1.0.0' },
  maintenanceMode: { type: Boolean, default: false },
  minTransactionAmount: { type: Number, default: 100 }, // Renamed from minTransferAmount
  maxTransactionAmount: { type: Number, default: 1000000 }, // Renamed from maxTransferAmount
  vtpassCommission: { type: Number, default: 0.05 },
  commissionRate: { type: Number, default: 0.02 },
  
  // Service Availability - New fields
  airtimeEnabled: { type: Boolean, default: true },
  dataEnabled: { type: Boolean, default: true },
  cableTvEnabled: { type: Boolean, default: true },
  electricityEnabled: { type: Boolean, default: true },
  transferEnabled: { type: Boolean, default: true },
  
  // Commission/Fee Management - New fields
  airtimeCommission: { type: Number, default: 1.5 },
  dataCommission: { type: Number, default: 1.0 },
  transferFee: { type: Number, default: 50.0 },
  isTransferFeePercentage: { type: Boolean, default: false },
  
  // User Management Defaults - New fields
  newUserDefaultWalletBalance: { type: Number, default: 0.0 },
  
  // Notification Settings - New fields
  emailNotificationsEnabled: { type: Boolean, default: true },
  pushNotificationsEnabled: { type: Boolean, default: true },
  smsNotificationsEnabled: { type: Boolean, default: false },
  notificationMessage: { type: String, default: 'System maintenance scheduled' },
  
  // Security Settings - New fields
  twoFactorAuthRequired: { type: Boolean, default: false },
  autoLogoutEnabled: { type: Boolean, default: true },
  sessionTimeout: { type: Number, default: 30 },
  transactionPinRequired: { type: Boolean, default: true }, // Added for PIN requirement
  biometricAuthEnabled: { type: Boolean, default: true }, // Added for biometric option
  
  // API Rate Limiting - New fields
  apiRateLimit: { type: Number, default: 100 },
  apiTimeWindow: { type: Number, default: 60 }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Beneficiary = mongoose.model('Beneficiary', beneficiarySchema);
const Settings = mongoose.model('Settings', settingsSchema);

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

const app = express();
app.use(express.json());
app.use(cors());
const PORT = process.env.PORT || 5000;

// JWT Token Generation
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });
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
    
    // Get the specific admin user ID from environment variable
    const specificAdminUserId = process.env.SPECIFIC_ADMIN_USER_ID || "689945d4fb65f8f9179e661b";
    if (specificAdminUserId && req.user._id.toString() === specificAdminUserId) {
      return next();
    }
    
    return res.status(403).json({ success: false, message: 'Admin access only' });
  });
};

// Middleware to verify transaction authentication (PIN or Biometric)
const verifyTransactionAuth = async (req, res, next) => {
  try {
    const { transactionPin, useBiometric } = req.body;
    const userId = req.user._id;
    
    // Get user settings
    const settings = await Settings.findOne();
    const pinRequired = settings ? settings.transactionPinRequired : true;
    const biometricAllowed = settings ? settings.biometricAuthEnabled : true;
    
    // If PIN is not required globally, skip verification
    if (!pinRequired) {
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
      // In a real app, biometric verification happens on the client side
      // Here we just check if the user has enabled it and the client is requesting to use it
      req.authenticationMethod = 'biometric';
      return next();
    }
    
    // If PIN is provided
    if (transactionPin && hasPin) {
      const isPinMatch = await bcrypt.compare(transactionPin, user.transactionPin);
      if (isPinMatch) {
        req.authenticationMethod = 'pin';
        return next();
      } else {
        return res.status(400).json({ success: false, message: 'Invalid transaction PIN' });
      }
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
    authenticationMethod // Added authentication method
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
        'none' // Commission transactions don't require additional auth
      );
      
      return commissionAmount;
    }
    
    return 0;
  } catch (error) {
    console.error('Error calculating commission:', error);
    return 0;
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

// --- API Routes ---

// @desc    Register a new user
// @route   POST /api/users/register
// @access  Public
app.post('/api/users/register', async (req, res) => {
  const { fullName, email, phone, password } = req.body;
  if (!fullName || !email || !phone || !password) {
    return res.status(400).json({ success: false, message: 'Please add all fields' });
  }
  const userExists = await User.findOne({ email });
  if (userExists) {
    return res.status(400).json({ success: false, message: 'User already exists' });
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const user = await User.create({
    fullName,
    email,
    phone,
    password: hashedPassword,
  });
  if (user) {
    const token = generateToken(user._id);
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
        transactionPinSet: !!user.transactionPin, // Added to indicate if PIN is set
        biometricEnabled: user.biometricEnabled, // Added biometric status
      },
      token,
    });
  } else {
    res.status(400).json({ success: false, message: 'Invalid user data' });
  }
});

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && (await bcrypt.compare(password, user.password))) {
    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Your account has been deactivated. Please contact support.' });
    }
    const token = generateToken(user._id);
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
        transactionPinSet: !!user.transactionPin, // Added to indicate if PIN is set
        biometricEnabled: user.biometricEnabled, // Added biometric status
      },
      token,
    });
  } else {
    res.status(400).json({ success: false, message: 'Invalid credentials' });
  }
});

// @desc    Set up transaction PIN
// @route   POST /api/users/set-transaction-pin
// @access  Private
app.post('/api/users/set-transaction-pin', protect, async (req, res) => {
  try {
    const { userId, pin } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    if (!pin || pin.length !== 4 || !/^\d+$/.test(pin)) {
      return res.status(400).json({ success: false, message: 'PIN must be a 4-digit number' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Hash the PIN
    const salt = await bcrypt.genSalt(10);
    const hashedPin = await bcrypt.hash(pin, salt);
    
    user.transactionPin = hashedPin;
    await user.save();
    
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
app.post('/api/users/change-transaction-pin', protect, async (req, res) => {
  try {
    const { userId, currentPin, newPin } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    
    if (!newPin || newPin.length !== 4 || !/^\d+$/.test(newPin)) {
      return res.status(400).json({ success: false, message: 'New PIN must be a 4-digit number' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Verify current PIN if it exists
    if (user.transactionPin) {
      const isCurrentPinMatch = await bcrypt.compare(currentPin, user.transactionPin);
      if (!isCurrentPinMatch) {
        return res.status(400).json({ success: false, message: 'Current PIN is incorrect' });
      }
    }
    
    // Hash the new PIN
    const salt = await bcrypt.genSalt(10);
    const hashedPin = await bcrypt.hash(newPin, salt);
    
    user.transactionPin = hashedPin;
    await user.save();
    
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
app.post('/api/users/toggle-biometric', protect, async (req, res) => {
  try {
    const { userId, enable } = req.body;
    
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
    
    user.biometricEnabled = enable;
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
        biometricAllowed
      }
    });
  } catch (error) {
    console.error('Error fetching security settings:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Get user's balance
// @route   POST /api/users/get-balance
// @access  Private
app.post('/api/users/get-balance', protect, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access to balance' });
    }
    
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
// @route   POST /api/users/get-commission-balance
// @access  Private
app.post('/api/users/get-commission-balance', protect, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access to commission balance' });
    }
    
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
app.post('/api/users/withdraw-commission', protect, verifyTransactionAuth, async (req, res) => {
  const { userId, amount } = req.body;
  
  if (!userId || !amount || amount <= 0) {
    return res.status(400).json({ success: false, message: 'User ID and a positive amount are required' });
  }
  
  if (req.user._id.toString() !== userId) {
    return res.status(403).json({ success: false, message: 'You can only withdraw from your own commission balance' });
  }
  
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
app.get('/api/users', adminProtect, async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    res.json({ success: true, users });
  } catch (error) {
    console.error('Error fetching all users:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Toggle user active status (Admin only)
// @route   PUT /api/users/toggle-status/:userId
// @access  Private/Admin
app.put('/api/users/toggle-status/:userId', adminProtect, async (req, res) => {
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
app.put('/api/users/toggle-admin-status/:userId', adminProtect, async (req, res) => {
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
app.patch('/api/users/:userId', protect, async (req, res) => {
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
app.post('/api/users/change-password', protect, async (req, res) => {
  try {
    const { userId, currentPassword, newPassword } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'You can only change your own password' });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }
    
    const salt = await bcrypt.genSalt(10);
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
app.post('/api/users/fund', adminProtect, async (req, res) => {
  const { userId, amount } = req.body;
  if (!userId || !amount || amount <= 0) {
    return res.status(400).json({ success: false, message: 'User ID and a positive amount are required' });
  }
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
      'none' // Admin operations don't require additional auth
    );
    await session.commitTransaction();
    res.json({ success: true, message: `Successfully funded user ${user.email} with ${amount}`, newBalance: balanceAfter });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error funding user:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  } finally {
    session.endSession();
  }
});

// @desc    Transfer funds between users
// @route   POST /api/transfer
// @access  Private
app.post('/api/transfer', protect, verifyTransactionAuth, async (req, res) => {
  const { senderId, receiverEmail, amount } = req.body;
  
  if (!senderId || !receiverEmail || !amount || amount <= 0) {
    return res.status(400).json({ success: false, message: 'All fields are required and amount must be positive' });
  }
  
  if (req.user._id.toString() !== senderId) {
    return res.status(403).json({ success: false, message: 'You can only transfer from your own account' });
  }
  
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
    
    // Updated to use new field names
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
app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID query parameter is required' });
    }
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });
    res.json({
      success: true,
      transactions
    });
  } catch (error) {
    console.error('Error fetching transactions:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Get user's commission transactions
// @route   GET /api/commission-transactions
// @access  Private
app.get('/api/commission-transactions', protect, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID query parameter is required' });
    }
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    const commissionTransactions = await Transaction.find({ userId, isCommission: true }).sort({ createdAt: -1 });
    res.json({
      success: true,
      commissionTransactions
    });
  } catch (error) {
    console.error('Error fetching commission transactions:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Get all transactions (Admin only)
// @route   GET /api/transactions/all
// @access  Private/Admin
app.get('/api/transactions/all', adminProtect, async (req, res) => {
  try {
    const transactions = await Transaction.find({}).sort({ createdAt: -1 }).populate('userId', 'fullName email');
    res.json({ success: true, transactions });
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
// @route   GET /api/beneficiaries/:userId
// @access  Private
app.get('/api/beneficiaries/:userId', protect, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
    const beneficiaries = await Beneficiary.find({ userId }).sort({ createdAt: -1 });
    res.json({ success: true, beneficiaries });
  } catch (error) {
    console.error('Error fetching beneficiaries:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Add a beneficiary
// @route   POST /api/beneficiaries
// @access  Private
app.post('/api/beneficiaries', protect, async (req, res) => {
  try {
    const { userId, name, type, value, network } = req.body;
    
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Access denied' });
    }
    
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
    
    await beneficiary.remove();
    
    res.json({ success: true, message: 'Beneficiary deleted successfully' });
  } catch (error) {
    console.error('Error deleting beneficiary:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Get user's notifications
// @route   GET /api/notifications
// @access  Private
app.get('/api/notifications', protect, async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID query parameter is required' });
    }
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }
    const notifications = await Notification.find({ recipientId: userId }).sort({ createdAt: -1 });
    res.json({
      success: true,
      notifications
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
    const { userId } = req.body;
    
    const notification = await Notification.findById(id);
    if (!notification) {
      return res.status(404).json({ success: false, message: 'Notification not found' });
    }
    
    if (req.user._id.toString() !== userId || notification.recipientId.toString() !== userId) {
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
app.post('/api/notifications/send', adminProtect, async (req, res) => {
  try {
    const { title, message, recipientId } = req.body;
    
    if (!title || !message) {
      return res.status(400).json({ success: false, message: 'Title and message are required' });
    }
    
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
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    res.json({ success: true, settings });
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Update app settings (Admin only)
// @route   POST /api/settings
// @access  Private/Admin
app.post('/api/settings', adminProtect, async (req, res) => {
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

// @desc    Update app settings (Admin only) - PUT endpoint for REST consistency
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

// VTPass endpoints remain unchanged...
// @desc    Verify smartcard number
// @route   POST /api/vtpass/validate-smartcard
// @access  Private
app.post('/api/vtpass/validate-smartcard', protect, async (req, res) => {
  console.log('Received smartcard verification request.');
  console.log('Request Body:', req.body);
  
  const { serviceID, billersCode } = req.body;
  
  if (!serviceID || !billersCode) {
    return res.status(400).json({ success: false, message: 'Service ID and billersCode are required.' });
  }
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
app.post('/api/vtpass/tv/purchase', protect, verifyTransactionAuth, async (req, res) => {
  console.log('Received TV purchase request.');
  console.log('Request Body:', req.body);
  
  const { userId, serviceID, billersCode, variationCode, amount, phone } = req.body;
  const reference = uuidv4();
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
app.post('/api/vtpass/airtime/purchase', protect, verifyTransactionAuth, async (req, res) => {
  console.log('Received airtime purchase request.');
  console.log('Request Body:', req.body);
  
  const { userId, network, phone, amount } = req.body;
  const serviceID = network.toLowerCase();
  const reference = uuidv4();
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
    const vtpassResult = await callVtpassApi('/pay', { serviceID, phone, amount, request_id: reference });
    
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
app.post('/api/vtpass/data/purchase', protect, verifyTransactionAuth, async (req, res) => {
  const { userId, network, phone, variationCode, amount } = req.body;
  const serviceID = network.toLowerCase();
  const reference = uuidv4();
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
    const vtpassResult = await callVtpassApi('/pay', { serviceID, phone, variation_code: variationCode, amount, request_id: reference });
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
app.post('/api/vtpass/validate-electricity', protect, async (req, res) => {
  console.log('Received electricity meter verification request.');
  console.log('Request Body:', req.body);
  
  const { serviceID, billersCode } = req.body;
  
  if (!serviceID || !billersCode) {
    return res.status(400).json({ success: false, message: 'Service ID and meter number are required.' });
  }
  
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
app.post('/api/vtpass/electricity/purchase', protect, verifyTransactionAuth, async (req, res) => {
  console.log('Received electricity purchase request.');
  console.log('Request Body:', req.body);
  
  const { userId, serviceID, billersCode, variationCode, amount, phone } = req.body;
  const reference = uuidv4();
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

// NEW ENDPOINTS FOR VTPASS SERVICES AND VARIATIONS
// @desc    Get VTpass services
// @route   GET /api/vtpass/services
// @access  Private
app.get('/api/vtpass/services', protect, async (req, res) => {
  try {
    const { serviceID } = req.query;
    
    if (!serviceID) {
      return res.status(400).json({ success: false, message: 'Service ID is required' });
    }
    
    // Call VTpass API to get services
    const vtpassResult = await callVtpassApi('/services', { serviceID });
    
    if (vtpassResult.success) {
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
app.get('/api/vtpass/variations', protect, async (req, res) => {
  try {
    const { serviceID } = req.query;
    
    if (!serviceID) {
      return res.status(400).json({ success: false, message: 'Service ID is required' });
    }
    
    // Call VTpass API to get variations
    const vtpassResult = await callVtpassApi('/variations', { serviceID });
    
    if (vtpassResult.success) {
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

// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});