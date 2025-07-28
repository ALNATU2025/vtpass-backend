// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    phone: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    walletBalance: {
      type: Number,
      default: 0.0,
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    virtualAccount: {
      accountNumber: { type: String, unique: true, sparse: true },
      bankName: { type: String },
      accountName: { type: String },
      reference: { type: String, unique: true, sparse: true },
      assigned: { type: Boolean, default: false },
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  // --- DEBUG LOGS FOR PRE-SAVE START ---
  console.log(`DEBUG (User Model Pre-Save): isModified('password'): ${this.isModified('password')}`);
  if (this.isModified('password')) {
    console.log(`DEBUG (User Model Pre-Save): Raw password before hashing (masked): ${this.password ? '********' : 'N/A'}`);
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    console.log(`DEBUG (User Model Pre-Save): Hashed password after bcrypt (masked): ${this.password ? '********' : 'N/A'}`);
  }
  // --- DEBUG LOGS FOR PRE-SAVE END ---
  next();
});

// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  // --- DEBUG LOGS FOR MATCH PASSWORD START ---
  console.log(`DEBUG (User Model MatchPassword): Entered password (masked): ${enteredPassword ? '********' : 'N/A'}`);
  console.log(`DEBUG (User Model MatchPassword): Stored hashed password (masked): ${this.password ? '********' : 'N/A'}`);
  const isMatch = await bcrypt.compare(enteredPassword, this.password);
  console.log(`DEBUG (User Model MatchPassword): Result of bcrypt.compare: ${isMatch}`);
  // --- DEBUG LOGS FOR MATCH PASSWORD END ---
  return isMatch;
};

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
