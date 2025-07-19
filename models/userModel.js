// models/userModel.js
const mongoose = require('mongoose');
const UserSchema = require('./user'); // Import the schema defined in user.js

// Export the User model. Use existing model if it's already defined to prevent OverwriteModelError.
module.exports = mongoose.models.User || mongoose.model('User', UserSchema);
