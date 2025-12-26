const mongoose = require('mongoose');

const authLogSchema = mongoose.Schema(
  {
    userId: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User', 
      required: false 
    },
    action: { 
      type: String, 
      required: true,
      enum: ['login', 'pin_attempt', 'biometric_attempt', 'password_reset', 'logout', 'token_refresh', 'other']
    },
    ipAddress: { 
      type: String, 
      required: true 
    },
    userAgent: { 
      type: String,
      default: 'Unknown'
    },
    success: { 
      type: Boolean, 
      required: true 
    },
    details: { 
      type: String,
      default: 'No details'
    },
    timestamp: { 
      type: Date, 
      default: Date.now 
    }
  }
);

module.exports = mongoose.models.AuthLog || mongoose.model('AuthLog', authLogSchema);
