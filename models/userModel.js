// models/userModel.js
const mongoose = require('mongoose');
const userSchema = mongoose.Schema(
    {
        username: {
            type: String,
            required: [true, 'Please add a username'],
            unique: true,
        },
        email: {
            type: String,
            required: [true, 'Please add an email'],
            unique: true,
        },
        password: {
            type: String,
            required: [true, 'Please add a password'],
        },
        // You might add other fields like walletBalance, etc.
        // walletBalance: {
        //     type: Number,
        //     default: 0,
        // },
    },
    {
        timestamps: true, // Adds createdAt and updatedAt fields
    }
);
module.exports = mongoose.model('User', userSchema);