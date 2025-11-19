// vtpass-backend/routes/fundWalletRoutes.js - UPDATED
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { protect } = require('../middleware/authMiddleware'); 

// @desc    Fund user wallet (for virtual account deposits too)
// @route   POST /api/fund-wallet
// @access  Private (requires authentication) OR from virtual account backend
router.post('/', async (req, res) => { // Temporarily remove 'protect' for testing
    const { userId, amount, type, transactionId, details } = req.body;

    console.log('💰 Fund wallet request:', { userId, amount, type, transactionId });

    if (!userId || !amount || amount <= 0) {
        return res.status(400).json({ 
            success: false,
            message: 'User ID and a valid positive amount are required.' 
        });
    }

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ 
                success: false,
                message: 'User not found.' 
            });
        }

        // Check if transaction already exists (using transactionId)
        if (transactionId) {
            const existingTransaction = await Transaction.findOne({
                transactionId: transactionId
            });

            if (existingTransaction) {
                console.log('⚠️ Transaction already processed in main backend:', transactionId);
                return res.json({
                    success: true,
                    message: 'Transaction already processed',
                    newBalance: user.walletBalance,
                    transactionId: existingTransaction._id
                });
            }
        }

        // Calculate balances
        const userPreviousBalance = user.walletBalance;
        user.walletBalance += amount;
        const userNewBalance = user.walletBalance;

        // Update wallet balance
        await user.save();

        // Create a transaction record in main backend
        const transaction = new Transaction({
            userId,
            type: type || 'FundWallet',
            amount,
            status: 'Successful',
            transactionId: transactionId || `VA_${Date.now()}`, // Use provided or generate
            details: {
                description: details?.description || `Wallet funded with ${amount} via virtual account.`,
                userPreviousBalance: userPreviousBalance,
                userNewBalance: userNewBalance,
                source: details?.source || 'virtual_account',
                reference: details?.reference || transactionId
            },
        });
        
        await transaction.save();

        console.log('✅ Main backend wallet funded:', {
            userId,
            amount,
            previousBalance: userPreviousBalance,
            newBalance: userNewBalance
        });

        res.status(200).json({
            success: true,
            message: 'Wallet funded successfully.',
            newBalance: user.walletBalance,
            transactionId: transaction._id,
        });

    } catch (error) {
        console.error('❌ Error funding wallet:', error);
        res.status(500).json({ 
            success: false,
            message: 'Server error during wallet funding.', 
            error: error.message 
        });
    }
});

// ADD THIS NEW ENDPOINT specifically for virtual account webhooks
router.post('/virtual-account-deposit', async (req, res) => {
    try {
        const { userId, amount, reference, description } = req.body;

        console.log('💰 Virtual account deposit sync:', { userId, amount, reference });

        if (!userId || !amount || !reference) {
            return res.status(400).json({
                success: false,
                message: 'userId, amount, and reference are required'
            });
        }

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if transaction already exists
        const existingTransaction = await Transaction.findOne({
            transactionId: reference
        });

        if (existingTransaction) {
            console.log('⚠️ Virtual account transaction already processed:', reference);
            return res.json({
                success: true,
                message: 'Virtual account deposit already processed',
                newBalance: user.walletBalance
            });
        }

        // Update wallet balance
        const previousBalance = user.walletBalance;
        user.walletBalance += parseFloat(amount);
        await user.save();

        // Create transaction record
        const transaction = new Transaction({
            userId: userId,
            type: 'FundWallet',
            amount: parseFloat(amount),
            transactionId: reference,
            status: 'Successful',
            details: {
                description: description || `Virtual account deposit - ${reference}`,
                userPreviousBalance: previousBalance,
                userNewBalance: user.walletBalance,
                source: 'virtual_account',
                reference: reference
            }
        });

        await transaction.save();

        console.log('✅ Virtual account deposit recorded in main backend:', reference);

        res.json({
            success: true,
            message: 'Virtual account deposit processed',
            amount: amount,
            newBalance: user.walletBalance,
            transactionId: transaction._id
        });

    } catch (error) {
        console.error('💥 Virtual account deposit error:', error);
        res.status(500).json({
            success: false,
            message: 'Virtual account deposit failed: ' + error.message
        });
    }
});

module.exports = router;
