// controllers/userController.js
// ✅ CHANGE THIS LINE:
const User = require('../models/User'); // Changed from '../models/user' to '../models/User'
const jwt = require('jsonwebtoken');

// Helper function to generate a JWT token
const generateToken = (id) => {
  // Use a fallback secret if JWT_SECRET is not defined (though it should be in .env)
  return jwt.sign({ id }, process.env.JWT_SECRET || 'your_jwt_secret', {
    expiresIn: '7d', // Token expires in 7 days
  });
};

// @desc    Register a new user
// @route   POST /api/users/register
// @access  Public
const registerUser = async (req, res) => {
  try {
    const { fullName, email, password, phone } = req.body;

    // Check if user with given email or phone already exists
    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      // Return specific message if email or phone already exists
      if (existingUser.email === email) {
        return res.status(400).json({ message: 'User with this email already exists' });
      } else {
        return res.status(400).json({ message: 'User with this phone number already exists' });
      }
    }

    // Create a new user (password will be hashed by the pre-save hook in the User schema)
    const user = await User.create({ fullName, email, password, phone });

    // Generate a JWT token for the newly registered user
    const token = generateToken(user._id);

    // Respond with the token and user details
    res.status(201).json({
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        walletBalance: user.walletBalance,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
};

// @desc    Authenticate user & get token
// @route   POST /api/users/login
// @access  Public
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Compare the provided password with the hashed password using the schema method
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Generate a JWT token for the logged-in user
    const token = generateToken(user._id);

    // Respond with the token and user details
    res.status(200).json({
      token,
      user: {
        _id: user._id,
        fullName: user.fullName,
        email: user.email,
        walletBalance: user.walletBalance,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
};

// Export the controller functions
module.exports = {
  registerUser,
  loginUser,
  // You can add other user-related controller functions here if needed
};
