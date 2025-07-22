// models/user.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Define the User Schema
const UserSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true, // Email must be unique
    lowercase: true, // Store emails in lowercase for consistency
    trim: true
  },
  phone: {
    type: String,
    required: true, // Phone number is now required
    unique: true,   // Phone number must be unique
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  walletBalance: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true // Adds createdAt and updatedAt timestamps
});

// Pre-save hook to hash password if it's new or modified
UserSchema.pre('save', async function (next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified('password')) {
    return next();
  }

  // Generate a salt and hash the password
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare entered password with the hashed password in the database
UserSchema.methods.matchPassword = async function (enteredPassword) {
  // 'this.password' refers to the hashed password stored in the database
  return await bcrypt.compare(enteredPassword, this.password);
};

// Export the User model directly
// Use mongoose.models.User to prevent OverwriteModelError in development/hot-reloading
module.exports = mongoose.models.User || mongoose.model('User', UserSchema);
