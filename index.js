// server.js with all schemas, middleware, and routes combined
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected...'))
  .catch(err => console.log(err));

// User Schema
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

const User = mongoose.model('User', userSchema);

// Transaction Schema
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

const Transaction = mongoose.model('Transaction', transactionSchema);

// Beneficiary Schema
const beneficiarySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  type: { type: String, required: true, enum: ['phone', 'smartcard', 'account'] },
  value: { type: String, required: true },
  network: { type: String }, // For phone top-ups
}, { timestamps: true });

const Beneficiary = mongoose.model('Beneficiary', beneficiarySchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

const Notification = mongoose.model('Notification', notificationSchema);

// Settings Schema
const settingsSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  value: { type: mongoose.Schema.Types.Mixed },
}, { timestamps: true });

const Setting = mongoose.model('Setting', settingsSchema);

// JWT Middleware
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select('-password');
      next();
    } catch (error) {
      console.error('JWT verification error:', error);
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  }
  if (!token) {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ message: 'Not authorized as an admin' });
  }
};

// VTPass Configuration
const vtpassConfig = {
  apiKey: process.env.VTPASS_API_KEY,
  secretKey: process.env.VTPASS_SECRET_KEY,
  baseUrl: 'https://sandbox.vtpass.com/api',
};

// Helper function for VTpass API calls
const callVtpassApi = async (endpoint, data, headers) => {
  try {
    const response = await axios.post(`${vtpassConfig.baseUrl}${endpoint}`, data, {
      headers: {
        'Content-Type': 'application/json',
        'api-key': vtpassConfig.apiKey,
        'secret-key': vtpassConfig.secretKey,
        ...headers,
      },
      timeout: 10000 // 10-second timeout
    });
    console.log(`VTPass API call to ${endpoint} successful.`);
    return { success: true, data: response.data };
  } catch (error) {
    console.error(`--- VTPass API Error to ${endpoint} ---`);
    if (error.response) {
      console.error('Server responded with non-2xx status:', error.response.status);
      console.error('Response data:', error.response.data);
      return { success: false, status: error.response.status, message: error.response.data.message || 'Error from VTpass API', details: error.response.data };
    } else if (error.request) {
      console.error('No response received from VTpass API:', error.request);
      return { success: false, status: 504, message: 'Timeout: No response from VTpass API' };
    } else {
      console.error('Error setting up request:', error.message);
      return { success: false, status: 500, message: error.message || 'Internal Server Error' };
    }
  }
};

// ✅ USER ROUTES
// Register User
app.post('/api/users/register', async (req, res) => {
  const { fullName, email, phone, password } = req.body;
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ fullName, email, phone, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({
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
  } catch (err) {
    console.error('Error in user registration:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login User
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(403).json({ message: 'Your account has been deactivated. Please contact support.' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({
      message: 'Login successful!',
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        isAdmin: user.isAdmin,
        walletBalance: user.walletBalance,
        virtualAccount: user.virtualAccount,
      },
      token,
    });
  } catch (err) {
    console.error('Error in user login:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all users (Admin only)
app.get('/api/users', protect, admin, async (req, res) => {
  try {
    const users = await User.find({});
    res.json({ users });
  } catch (err) {
    console.error('Error getting all users:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user profile by ID
app.get('/api/users/:userId', protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ user });
  } catch (err) {
    console.error('Error getting user profile:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile (Admin only)
app.put('/api/users/:userId', protect, admin, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const updatedUser = await User.findByIdAndUpdate(req.params.userId, req.body, { new: true, runValidators: true });
    res.json({ message: 'User updated successfully', user: updatedUser });
  } catch (err) {
    console.error('Error updating user profile:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Change password
app.post('/api/users/change-password', protect, async (req, res) => {
  const { userId, currentPassword, newPassword } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!(await bcrypt.compare(currentPassword, user.password))) {
      return res.status(400).json({ message: 'Incorrect current password' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error changing password:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Toggle user status (Admin only)
app.put('/api/users/toggle-status/:userId', protect, admin, async (req, res) => {
  try {
    const { isActive } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.userId,
      { isActive },
      { new: true, runValidators: true }
    );
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User status updated successfully', user });
  } catch (err) {
    console.error('Error toggling user status:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ WALLET & TRANSACTION ROUTES
// Get user balance
app.post('/api/users/get-balance', protect, async (req, res) => {
  const { userId } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ walletBalance: user.walletBalance });
  } catch (err) {
    console.error('Error getting user balance:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fund Wallet (Admin or internal use)
app.post('/api/fund-wallet', protect, async (req, res) => {
  const { userId, amount, type = 'credit', description = 'Wallet funding' } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'User not found' });
    }

    const balanceBefore = user.walletBalance;
    user.walletBalance += amount;
    await user.save({ session });

    const newTransaction = new Transaction({
      userId: user._id,
      type: 'credit',
      amount,
      status: 'successful',
      description,
      balanceBefore,
      balanceAfter: user.walletBalance,
      reference: uuidv4(),
    });
    await newTransaction.save({ session });

    await session.commitTransaction();
    session.endSession();
    res.json({
      message: 'Wallet funded successfully',
      newBalance: user.walletBalance,
      transaction: newTransaction,
    });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error funding wallet:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Transfer funds between users
app.post('/api/transfer', protect, async (req, res) => {
  const { senderId, receiverEmail, amount } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const sender = await User.findById(senderId).session(session);
    if (!sender) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Sender not found' });
    }

    if (sender.walletBalance < amount) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    const receiver = await User.findOne({ email: receiverEmail }).session(session);
    if (!receiver) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ message: 'Receiver not found' });
    }
    if (senderId === receiver._id.toString()) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ message: 'Cannot transfer to yourself' });
    }

    // Debit sender
    const senderBalanceBefore = sender.walletBalance;
    sender.walletBalance -= amount;
    await sender.save({ session });

    // Credit receiver
    const receiverBalanceBefore = receiver.walletBalance;
    receiver.walletBalance += amount;
    await receiver.save({ session });

    // Create transaction records
    const senderTransaction = new Transaction({
      userId: sender._id,
      type: 'debit',
      amount,
      status: 'successful',
      description: `Transfer to ${receiver.email}`,
      balanceBefore: senderBalanceBefore,
      balanceAfter: sender.walletBalance,
      reference: uuidv4(),
    });
    await senderTransaction.save({ session });

    const receiverTransaction = new Transaction({
      userId: receiver._id,
      type: 'credit',
      amount,
      status: 'successful',
      description: `Transfer from ${sender.email}`,
      balanceBefore: receiverBalanceBefore,
      balanceAfter: receiver.walletBalance,
      reference: uuidv4(),
    });
    await receiverTransaction.save({ session });

    await session.commitTransaction();
    session.endSession();
    res.json({
      message: 'Transfer successful',
      newSenderBalance: sender.walletBalance,
    });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error during transfer:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user transactions
app.get('/api/transactions/:userId', protect, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.json(transactions);
  } catch (err) {
    console.error('Error getting user transactions:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all transactions (Admin only)
app.get('/api/transactions', protect, admin, async (req, res) => {
  try {
    const transactions = await Transaction.find({}).sort({ createdAt: -1 }).populate('userId', 'email');
    res.json(transactions);
  } catch (err) {
    console.error('Error getting all transactions:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ BENEFICIARY ROUTES
// Add a new beneficiary
app.post('/api/beneficiaries', protect, async (req, res) => {
  const { userId, name, type, value, network } = req.body;
  try {
    const newBeneficiary = new Beneficiary({ userId, name, type, value, network });
    await newBeneficiary.save();
    res.status(201).json({ message: 'Beneficiary added successfully', beneficiary: newBeneficiary });
  } catch (err) {
    console.error('Error adding beneficiary:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all beneficiaries for a user
app.get('/api/beneficiaries/:userId', protect, async (req, res) => {
  try {
    const beneficiaries = await Beneficiary.find({ userId: req.params.userId }).sort({ createdAt: -1 });
    res.json(beneficiaries);
  } catch (err) {
    console.error('Error getting beneficiaries:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete a beneficiary
app.delete('/api/beneficiaries/:id', protect, async (req, res) => {
  try {
    const beneficiary = await Beneficiary.findByIdAndDelete(req.params.id);
    if (!beneficiary) {
      return res.status(404).json({ message: 'Beneficiary not found' });
    }
    res.json({ message: 'Beneficiary deleted successfully' });
  } catch (err) {
    console.error('Error deleting beneficiary:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ NOTIFICATION ROUTES
// Send a notification (Admin only or system)
app.post('/api/notifications/send', protect, admin, async (req, res) => {
  const { title, message, recipientId } = req.body;
  try {
    let notification;
    if (recipientId) {
      notification = new Notification({ recipientId, title, message });
    } else {
      const users = await User.find({}).select('_id');
      const notifications = users.map(user => new Notification({ recipientId: user._id, title, message }));
      await Notification.insertMany(notifications);
      return res.json({ message: 'Notification sent to all users successfully' });
    }
    await notification.save();
    res.json({ message: 'Notification sent successfully', notification });
  } catch (err) {
    console.error('Error sending notification:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get notifications for a user
app.get('/api/notifications/:userId', protect, async (req, res) => {
  try {
    const notifications = await Notification.find({ recipientId: req.params.userId }).sort({ createdAt: -1 });
    res.json(notifications);
  } catch (err) {
    console.error('Error getting user notifications:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mark notification as read
app.post('/api/notifications/:id/read', protect, async (req, res) => {
  try {
    const notification = await Notification.findById(req.params.id);
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    notification.isRead = true;
    await notification.save();
    res.json({ message: 'Notification marked as read', notification });
  } catch (err) {
    console.error('Error marking notification as read:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get unread notification count
app.get('/api/notifications/unread-count/:userId', protect, async (req, res) => {
  try {
    const count = await Notification.countDocuments({ recipientId: req.params.userId, isRead: false });
    res.json({ unreadCount: count });
  } catch (err) {
    console.error('Error getting unread notification count:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ APP SETTINGS ROUTES
app.get('/api/settings', protect, async (req, res) => {
  try {
    const settings = await Setting.find({});
    const settingsMap = settings.reduce((acc, setting) => {
      acc[setting.name] = setting.value;
      return acc;
    }, {});
    res.json(settingsMap);
  } catch (err) {
    console.error('Error getting app settings:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/settings', protect, admin, async (req, res) => {
  try {
    const updates = Object.keys(req.body).map(name =>
      Setting.findOneAndUpdate(
        { name },
        { value: req.body[name] },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      )
    );
    await Promise.all(updates);
    res.json({ message: 'Settings updated successfully' });
  } catch (err) {
    console.error('Error updating app settings:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ VTPASS ROUTES (with new logging and error handling)
// Validate Smartcard
app.post('/api/vtpass/validate-smartcard', protect, async (req, res) => {
  const { serviceID, billersCode } = req.body;
  
  if (!serviceID || !billersCode) {
    return res.status(400).json({ success: false, message: 'serviceID and billersCode are required.' });
  }
  
  const vtpassResult = await callVtpassApi('/merchant-verify', { serviceID, billersCode });
  
  if (vtpassResult.success) {
    res.json({ success: true, message: 'Smartcard validation successful.', data: vtpassResult.data });
  } else {
    res.status(vtpassResult.status).json(vtpassResult);
  }
});

// Airtime Purchase
app.post('/api/vtpass/airtime/purchase', protect, async (req, res) => {
  const { userId, network, phone, amount } = req.body;
  const serviceID = network.toLowerCase();
  const reference = uuidv4();
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    if (user.walletBalance < amount) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    const vtpassResult = await callVtpassApi('/pay', { serviceID, phone, amount, request_id: reference });

    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    if (vtpassResult.success && (vtpassResult.data.response_code === '00' || vtpassResult.data.response_code === '01')) {
      transactionStatus = vtpassResult.data.response_code === '00' ? 'successful' : 'pending';
      user.walletBalance -= amount;
      await user.save({ session });
    } else {
      await session.abortTransaction();
      session.endSession();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = new Transaction({
      userId,
      type: 'debit',
      amount,
      status: transactionStatus,
      description: `Airtime purchase for ${phone} on ${network}`,
      balanceBefore,
      balanceAfter: user.walletBalance,
      reference,
    });
    await newTransaction.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({
      success: true,
      message: 'Airtime purchase initiated successfully.',
      transactionId: newTransaction._id,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error in airtime purchase:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// Data Purchase
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
      session.endSession();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    if (user.walletBalance < amount) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    const vtpassResult = await callVtpassApi('/pay', { serviceID, phone, billersCode: '', variation_code: variationCode, amount, request_id: reference });
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    if (vtpassResult.success && (vtpassResult.data.response_code === '00' || vtpassResult.data.response_code === '01')) {
      transactionStatus = vtpassResult.data.response_code === '00' ? 'successful' : 'pending';
      user.walletBalance -= amount;
      await user.save({ session });
    } else {
      await session.abortTransaction();
      session.endSession();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = new Transaction({
      userId,
      type: 'debit',
      amount,
      status: transactionStatus,
      description: `Data purchase for ${phone} on ${network}`,
      balanceBefore,
      balanceAfter: user.walletBalance,
      reference,
    });
    await newTransaction.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({
      success: true,
      message: 'Data purchase initiated successfully.',
      transactionId: newTransaction._id,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error in data purchase:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

// Cable TV Payment
app.post('/api/vtpass/tv/purchase', protect, async (req, res) => {
  const { userId, serviceID, billersCode, variationCode, amount, phone } = req.body;
  const reference = uuidv4();
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    if (user.walletBalance < amount) {
      await session.abortTransaction();
      session.endSession();
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
    
    const balanceBefore = user.walletBalance;
    let transactionStatus = 'failed';
    if (vtpassResult.success && (vtpassResult.data.response_code === '00' || vtpassResult.data.response_code === '01')) {
      transactionStatus = vtpassResult.data.response_code === '00' ? 'successful' : 'pending';
      user.walletBalance -= amount;
      await user.save({ session });
    } else {
      await session.abortTransaction();
      session.endSession();
      return res.status(vtpassResult.status || 400).json(vtpassResult);
    }
    
    const newTransaction = new Transaction({
      userId,
      type: 'debit',
      amount,
      status: transactionStatus,
      description: `${serviceID} TV Subscription for ${billersCode}`,
      balanceBefore,
      balanceAfter: user.walletBalance,
      reference,
    });
    await newTransaction.save({ session });

    await session.commitTransaction();
    session.endSession();
    res.json({
      success: true,
      message: 'Payment request received. Check transaction status for confirmation.',
      transactionId: newTransaction._id,
      newBalance: user.walletBalance,
      status: newTransaction.status,
    });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error in TV payment:', error);
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
