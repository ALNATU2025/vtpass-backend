// routes/fundWalletRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User'); // Corrected: Import from '../models/User'
const Transaction = require('../models/Transaction');const { protect } = require('../middleware/authMiddleware'); // <<< FIXED: Destructure 'protect' from the export

// @desc    Fund user wallet
// @route   POST /api/fund-wallet
// @access  Private (requires authentication)
router.post('/', protect, async (req, res) => { // Line 11 is here, 'protect' needs to be a function
    const { userId, amount, type } = req.body; // 'type' could be 'credit', 'manual_deposit', etc.

    if (!userId || !amount || amount <= 0) {
        return res.status(400).json({ message: 'User ID and a valid positive amount are required.' });
    }

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Update wallet balance
        user.walletBalance += amount;
        await user.save();

        // Create a transaction record
        const transaction = new Transaction({
            userId,
            type: type || 'FundWallet', // Use provided type or default 'FundWallet'
            amount,
            status: 'Successful', // For manual funding, assume successful if processed by admin
            details: {
                description: `Wallet funded with ${amount} via ${type || 'manual deposit'}.`,
                userPreviousBalance: user.walletBalance - amount, // Calculate previous balance
                userNewBalance: user.walletBalance, // New balance after credit
            },
        });
        await transaction.save();

        res.status(200).json({
            message: 'Wallet funded successfully.',
            newBalance: user.walletBalance,
            transactionId: transaction._id,
        });

    } catch (error) {
        console.error('❌ Error funding wallet:', error);
        res.status(500).json({ message: 'Server error during wallet funding.', error: error.message });
    }
});

module.exports = router;
