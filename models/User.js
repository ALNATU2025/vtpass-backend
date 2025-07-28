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
  // Check if password field is being modified or if it's a new document
  if (this.isModified('password') || this.isNew) {
    // --- DEBUG LOGS FOR PRE-SAVE START ---
    console.log(`DEBUG (User Model Pre-Save): isModified('password'): ${this.isModified('password')}`);
    console.log(`DEBUG (User Model Pre-Save): isNew document: ${this.isNew}`);
    console.log(`DEBUG (User Model Pre-Save): Raw password length before hashing: ${this.password ? this.password.length : 'N/A'}`);
    console.log(`DEBUG (User Model Pre-Save): Raw password content (first 5 chars, masked): ${this.password ? this.password.substring(0, Math.min(this.password.length, 5)) + '...' : 'N/A'}`); // Show first few chars
    // --- DEBUG LOGS FOR PRE-SAVE END ---

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);

    // --- DEBUG LOGS FOR PRE-SAVE AFTER HASHING ---
    console.log(`DEBUG (User Model Pre-Save): Hashed password length after bcrypt: ${this.password ? this.password.length : 'N/A'}`);
    console.log(`DEBUG (User Model Pre-Save): Hashed password content (first 5 chars, masked): ${this.password ? this.password.substring(0, Math.min(this.password.length, 5)) + '...' : 'N/A'}`); // Show first few chars
    // --- DEBUG LOGS FOR PRE-SAVE AFTER HASHING END ---
  } else {
    console.log(`DEBUG (User Model Pre-Save): Password not modified, skipping hashing.`);
  }
  next();
});

// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  // --- DEBUG LOGS FOR MATCH PASSWORD START ---
  console.log(`DEBUG (User Model MatchPassword): Entered password length: ${enteredPassword ? enteredPassword.length : 'N/A'}`);
  console.log(`DEBUG (User Model MatchPassword): Entered password content (first 5 chars, masked): ${enteredPassword ? enteredPassword.substring(0, Math.min(enteredPassword.length, 5)) + '...' : 'N/A'}`);
  console.log(`DEBUG (User Model MatchPassword): Stored hashed password length: ${this.password ? this.password.length : 'N/A'}`);
  console.log(`DEBUG (User Model MatchPassword): Stored hashed password content (first 5 chars, masked): ${this.password ? this.password.substring(0, Math.min(this.password.length, 5)) + '...' : 'N/A'}`);
  // --- DEBUG LOGS FOR MATCH PASSWORD END ---

  const isMatch = await bcrypt.compare(enteredPassword, this.password);

  // --- DEBUG LOGS FOR MATCH PASSWORD RESULT ---
  console.log(`DEBUG (User Model MatchPassword): Result of bcrypt.compare: ${isMatch}`);
  // --- DEBUG LOGS FOR MATCH PASSWORD RESULT END ---
  return isMatch;
};

module.exports = mongoose.models.User || mongoose.model('User', userSchema);
