// middleware/transactionAuthMiddleware.js

const User = require('../models/User');
const Settings = require('../models/AppSettings');
const bcrypt = require('bcryptjs');
const AuthLog = require('../models/AuthLog');
const moment = require('moment-timezone'); // already required in index.js

// Helper: Get current time in Lagos timezone
function getLagosTime() {
  if (moment && moment.tz) {
    return moment.tz('Africa/Lagos').toDate();
  } else {
    return moment().utcOffset('+01:00').toDate();
  }
}

// Helper: Log authentication attempts
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

// Main middleware
const verifyTransactionAuth = async (req, res, next) => {
  try {
    const { transactionPin, useBiometric, biometricData } = req.body;
    const userId = req.user._id;
    const ipAddress = req.ip;
    const userAgent = req.get('User-Agent');

    // Get global settings
    const settings = await Settings.findOne();
    const pinRequired = settings ? settings.transactionPinRequired : true;
    const biometricAllowed = settings ? settings.biometricAuthEnabled : true;

    if (!pinRequired) {
      req.authenticationMethod = 'none';
      return next();
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const hasPin = !!user.transactionPin;
    const hasBiometric = user.biometricEnabled;

    if (!hasPin && !hasBiometric) {
      return res.status(400).json({
        success: false,
        message: 'Please set up a transaction PIN or enable biometric authentication first'
      });
    }

    // Biometric path
    if (useBiometric && hasBiometric && biometricAllowed) {
      await logAuthAttempt(userId, 'biometric_attempt', ipAddress, userAgent, true, 'Biometric verified');
      req.authenticationMethod = 'biometric';
      return next();
    }

    // PIN path
    if (transactionPin && hasPin) {
      // Check lockout
      if (user.pinLockedUntil && user.pinLockedUntil > getLagosTime()) {
        const remaining = Math.ceil((user.pinLockedUntil - getLagosTime()) / 60000);
        await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, 'Account locked');
        return res.status(429).json({
          success: false,
          message: `Too many failed attempts. Locked for ${remaining} minutes.`
        });
      }

      const isMatch = await bcrypt.compare(transactionPin, user.transactionPin);

      if (isMatch) {
        user.failedPinAttempts = 0;
        user.pinLockedUntil = null;
        await user.save();
        await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, true, 'PIN verified');
        req.authenticationMethod = 'pin';
        return next();
      } else {
        user.failedPinAttempts += 1;
        if (user.failedPinAttempts >= 3) {
          user.pinLockedUntil = new Date(getLagosTime().getTime() + 15 * 60000);
        }
        await user.save();

        const remaining = 3 - user.failedPinAttempts;
        await logAuthAttempt(userId, 'pin_attempt', ipAddress, userAgent, false, `Invalid PIN (${remaining} left)`);

        return res.status(400).json({
          success: false,
          message: `Invalid PIN. ${remaining > 0 ? `${remaining} attempts remaining` : 'Account locked for 15 minutes'}`
        });
      }
    }

    // No valid auth method provided
    return res.status(400).json({
      success: false,
      message: 'Please provide transaction PIN or use biometric authentication'
    });

  } catch (error) {
    console.error('Transaction authentication error:', error);
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
};

module.exports = { verifyTransactionAuth };
