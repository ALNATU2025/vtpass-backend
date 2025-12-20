const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['VTPASS_LOW_BALANCE', 'USER_REPORT', 'SYSTEM_ERROR', 'TRANSACTION_FAILURE']
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['INFO', 'WARNING', 'CRITICAL'],
    default: 'INFO'
  },
  data: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  acknowledged: {
    type: Boolean,
    default: false
  },
  acknowledgedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  acknowledgedAt: {
    type: Date
  }
}, {
  timestamps: true
});

const Alert = mongoose.model('Alert', alertSchema);
module.exports = Alert;
