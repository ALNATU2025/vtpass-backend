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
  walletBalance: { type: Number, default: 0 },
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
}, { timestamps: true });

const notificationSchema = new mongoose.Schema({
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Notification = mongoose.model('Notification', notificationSchema);

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
  await protect(req, res, () => {
    // TEMPORARY CHANGE: The line below that checks for isAdmin has been commented out.
    // This allows any authenticated user to access admin routes.
    // To revert, uncomment the 'if' block and remove the 'next()' call.
    next();
    // if (req.user && req.user.isAdmin) {
    //   next();
    // } else {
    //   res.status(403).json({ success: false, message: 'Not authorized as an admin' });
    // }
  });
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
    // Log the full VTPass response data for debugging purposes
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
const createTransaction = async (userId, amount, type, status, description, balanceBefore, balanceAfter, session) => {
  const newTransaction = new Transaction({
    userId,
    type,
    amount,
    status,
    description,
    balanceBefore,
    balanceAfter,
    reference: uuidv4(),
  });
  await newTransaction.save({ session });
  return newTransaction;
};


// --- API Routes ---

// @desc    Register a new user
// @route   POST /api/users/register
// @access  Public
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
      },
      token,
    });
  } else {
    res.status(400).json({ success: false, message: 'Invalid user data' });
  }
});

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
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
      },
      token,
    });
  } else {
    res.status(400).json({ success: false, message: 'Invalid credentials' });
  }
});

// @desc    Get user's balance
// @route   POST /api/users/get-balance
// @access  Private
app.post('/api/users/get-balance', protect, async (req, res) => {
  try {
    // The frontend sends the userId in the body, so we read it from there.
    const { userId } = req.body;
    
    // Ensure the authenticated user is requesting their own balance
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access to balance' });
    }
    
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.json({
      success: true,
      balance: user.walletBalance
    });
  } catch (error) {
      console.error('Error fetching balance:', error);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Get all users (Admin only)
// @route   GET /api/users
// @access  Private/Admin
app.get('/api/users', adminProtect, async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    res.json({ success: true, users });
  } catch (error) {
    console.error('Error fetching all users:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// @desc    Fund a user's wallet (Admin only)
// @route   POST /api/users/fund
// @access  Private/Admin
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
      session
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


// @desc    Get user's transactions
// @route   GET /api/transactions
// @access  Private
// Corrected to use a query parameter (?userId=...) to match the frontend
app.get('/api/transactions', protect, async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID query parameter is required' });
    }

    // Ensure the authenticated user is requesting their own transactions
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

// @desc    Get all transactions (Admin only)
// @route   GET /api/transactions/all
// @access  Private/Admin
// Renamed the route to prevent conflicts with the user's transaction endpoint
app.get('/api/transactions/all', adminProtect, async (req, res) => {
  try {
    const transactions = await Transaction.find({}).sort({ createdAt: -1 }).populate('userId', 'fullName email');
    res.json({ success: true, transactions });
  } catch (error) {
      console.error('Error fetching all transactions:', error);
      res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// @desc    Verify smartcard number
// @route   POST /api/vtpass/validate-smartcard
// @access  Private
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


// @desc    Pay for Cable TV subscription
// @route   POST /api/vtpass/tv/purchase
// @access  Private
app.post('/api/vtpass/tv/purchase', protect, async (req, res) => {
  // Log incoming request for TV purchase
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
    
    // Log the full VTPass response for TV purchase for debugging purposes
    console.log('VTPass Response for TV Purchase:', JSON.stringify(vtpassResult, null, 2));

    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;

    // Corrected check for successful VTPass response
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
    } else {
      // Revert transaction if VTPass call failed or response code is not successful
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
      session
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


// @desc    Purchase airtime
// @route   POST /api/vtpass/airtime/purchase
// @access  Private
app.post('/api/vtpass/airtime/purchase', protect, async (req, res) => {
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
    
    // Log the full VTPass response data for debugging purposes
    console.log('VTPass Response:', JSON.stringify(vtpassResult, null, 2));

    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    let newBalance = balanceBefore;
    
    // Corrected check for successful VTPass response
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
    } else {
      // Revert transaction if VTPass call failed or response code is not successful
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
      session
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


// @desc    Purchase data
// @route   POST /api/vtpass/data/purchase
// @access  Private
app.post('/api/vtpass/data/purchase', protect, async (req, res) => {
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
    
    // Corrected check for successful VTPass response
    if (vtpassResult.success && vtpassResult.data && vtpassResult.data.code === '000') {
      transactionStatus = 'successful';
      newBalance = user.walletBalance - amount;
      user.walletBalance = newBalance;
      await user.save({ session });
    } else {
      // Revert transaction if VTPass call failed or response code is not successful
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
      session
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


// @desc    Get user's notifications
// @route   GET /api/notifications
// @access  Private
// Corrected to use a query parameter (?userId=...) to match the frontend
app.get('/api/notifications', protect, async (req, res) => {
  try {
    const { userId } = req.query;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID query parameter is required' });
    }

    // Ensure the authenticated user is requesting their own notifications
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


// Catch-all 404 handler
app.use((req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
