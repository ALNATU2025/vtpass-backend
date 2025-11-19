// vtpass-backend/routes/fundWalletRoutes.js - FIXED & UPDATED
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { protect } = require('../middleware/authMiddleware'); // Optional auth

// ------------------------
// POST /api/fund-wallet
// Fund user wallet (general or virtual account)
// ------------------------
router.post('/', async (req, res) => {
    const { userId, amount, transactionId, details } = req.body;

    console.log('💰 Fund wallet request:', { userId, amount, transactionId });

    if (!userId || !amount || amount <= 0) {
        return res.status(400).json({ 
            success: false,
            message: 'User ID and a valid positive amount are required.' 
        });
    }

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });

        // Check duplicate transaction
        if (transactionId) {
            const existingTransaction = await Transaction.findOne({ transactionId });
            if (existingTransaction) {
                console.log('⚠️ Transaction already processed:', transactionId);
                return res.json({
                    success: true,
                    message: 'Transaction already processed',
                    newBalance: user.walletBalance,
                    transactionId: existingTransaction._id
                });
            }
        }

        // Update balances
        const balanceBefore = user.walletBalance;
        user.walletBalance += parseFloat(amount);
        const balanceAfter = user.walletBalance;
        await user.save();

        // Create transaction with correct enums & required fields
        const transaction = new Transaction({
            userId: user._id,
            type: 'credit',             // ✅ matches enum
            amount: parseFloat(amount),
            status: 'success',          // ✅ matches enum
            transactionId: transactionId || `VA_${Date.now()}`,
            balanceBefore,              // ✅ required
            balanceAfter,               // ✅ required
            details: {
                description: details?.description || `Wallet funded with ${amount}`,
                source: details?.source || 'virtual_account',
                reference: details?.reference || transactionId
            }
        });

        await transaction.save();

        console.log('✅ Wallet funded:', { userId, amount, balanceBefore, balanceAfter });

        res.status(200).json({
            success: true,
            message: 'Wallet funded successfully.',
            newBalance: user.walletBalance,
            transactionId: transaction._id
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

// ------------------------
// POST /api/fund-wallet/virtual-account-deposit
// Specifically for virtual account webhooks
// ------------------------
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

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        // Check duplicate transaction
        const existingTransaction = await Transaction.findOne({ transactionId: reference });
        if (existingTransaction) {
            console.log('⚠️ Virtual account transaction already processed:', reference);
            return res.json({
                success: true,
                message: 'Virtual account deposit already processed',
                newBalance: user.walletBalance
            });
        }

        // Update balances
        const balanceBefore = user.walletBalance;
        user.walletBalance += parseFloat(amount);
        const balanceAfter = user.walletBalance;
        await user.save();

        // Create transaction with correct enums
        const transaction = new Transaction({
            userId: user._id,
            type: 'virtual_account_deposit', // ✅ matches enum for VA deposits
            amount: parseFloat(amount),
            status: 'success',               // ✅ matches enum
            transactionId: reference,
            balanceBefore,                   // ✅ required
            balanceAfter,                    // ✅ required
            details: {
                description: description || `Virtual account deposit - ${reference}`,
                source: 'virtual_account',
                reference: reference
            }
        });

        await transaction.save();

        console.log('✅ Virtual account deposit recorded:', reference);

        res.json({
            success: true,
            message: 'Virtual account deposit processed',
            amount,
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
