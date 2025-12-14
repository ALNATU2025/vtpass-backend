// middleware/transactionAuthMiddleware.js
const Settings = require('../models/AppSettings');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const { getLagosTime, logAuthAttempt } = require('../utils/helpers'); // If you have these in a utils file; otherwise copy the functions here or import from index if needed

// Paste the full verifyTransactionAuth function from your index.js here
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
      // Add your verifyBiometricAuth logic here or call it
      // For now, assuming it's similar — implement as in index.js
      req.authenticationMethod = 'biometric';
      return next();
    }
    
    // If PIN is provided
    if (transactionPin && hasPin) {
      // Add your verifyTransactionPin logic here
      req.authenticationMethod = 'pin';
      return next();
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

module.exports = { verifyTransactionAuth };
