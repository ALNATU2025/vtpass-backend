const mongoose = require('mongoose');

const referralSchema = new mongoose.Schema({
  referrerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  referredUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  referralCode: {
    type: String,
    required: true
  },
  referredUserEmail: String,
  referredUserName: String,
  status: {
    type: String,
    enum: ['pending', 'registered', 'completed', 'failed'],
    default: 'pending'
  },
  level: {
    type: Number,
    default: 1
  },
  bonusPaid: {
    type: Number,
    default: 0
  },
  depositAmount: Number,
  completedAt: Date,
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update timestamp on save
referralSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('Referral', referralSchema);
