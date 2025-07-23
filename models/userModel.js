// models/userModel.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Import bcrypt here to use in schema methods

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
        unique: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    walletBalance: {
        type: Number,
        default: 0,
    },
}, { timestamps: true });

// Add a method to compare entered password with hashed password in the database
// This method will be available on user documents (e.g., user.matchPassword(somePassword))
userSchema.methods.matchPassword = async function (enteredPassword) {
    // 'this.password' refers to the hashed password stored in the user document
    return await bcrypt.compare(enteredPassword, this.password);
};

// ✅ Avoid OverwriteModelError
module.exports = mongoose.models.User || mongoose.model('User', userSchema);
