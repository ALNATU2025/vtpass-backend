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
      required: true 
    },
    ipAddress: { 
      type: String, 
      required: true 
    },
    userAgent: { 
      type: String 
    },
    success: { 
      type: Boolean, 
      required: true 
    },
    details: { 
      type: String 
    },
    timestamp: { 
      type: Date, 
      default: Date.now 
    }
  }
);

module.exports = mongoose.models.AuthLog || mongoose.model('AuthLog', authLogSchema);
