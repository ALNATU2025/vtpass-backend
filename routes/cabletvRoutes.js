// routes/cabletvRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User'); // <<< This is now CORRECT!
const Transaction = require('../models/transactionModel');
const axios = require("axios");

router.post('/pay', async (req, res) => {
    try {
        const { userId, serviceID, smartCardNumber, selectedPackage, amount, selectedCable } = req.body;

        if (!userId || !smartCardNumber || !amount || !selectedPackage || !serviceID || !selectedCable) {
            return res.status(400).json({
                success: false,
                message: 'All fields (userId, smartCardNumber, amount, selectedPackage, serviceID, selectedCable) are required'
            });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const numericAmount = parseFloat(amount);
        if (isNaN(numericAmount) || numericAmount <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid amount format' });
        }

        if (user.walletBalance < numericAmount) {
            return res.status(400).json({ success: false, message: 'Insufficient balance' });
        }

        if (!process.env.VTPASS_API_KEY || !process.env.VTPASS_SECRET_KEY || !process.env.VTPASS_BASE_URL) {
            console.error("❌ VTpass environment variables (API_KEY, SECRET_KEY, BASE_URL) are not set!");
            return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing.' });
        }

        const requestId = `CABLE_${user._id}_${Date.now()}`;

        console.log("📡 Making cable payment with VTpass...");
        console.log("➡️ Body Sent to VTpass:", {
            serviceID,
            billersCode: smartCardNumber,
            variation_code: selectedPackage,
            amount: numericAmount,
            phone: user.phone,
            request_id: requestId,
        });

        console.log("🔍 Debugging VTpass Request Headers:");
        console.log("    VTPASS_API_KEY (from env, masked):", process.env.VTPASS_API_KEY ? process.env.VTPASS_API_KEY.substring(0, 5) + '...' + process.env.VTPASS_API_KEY.substring(process.env.VTPASS_API_KEY.length - 5) : 'N/A');
        console.log("    VTPASS_SECRET_KEY (from env, masked):", process.env.VTPASS_SECRET_KEY ? process.env.VTPASS_SECRET_KEY.substring(0, 5) + '...' + process.env.VTPASS_SECRET_KEY.substring(process.env.VTPASS_SECRET_KEY.length - 5) : 'N/A');
        console.log("    VTPASS_BASE_URL (from env):", process.env.VTPASS_BASE_URL);

        const vtpassResponse = await axios.post(
            `${process.env.VTPASS_BASE_URL}/pay`,
            {
                serviceID,
                billersCode: smartCardNumber,
                variation_code: selectedPackage,
                amount: numericAmount,
                phone: user.phone,
                request_id: requestId,
            },
            {
                headers: {
                    "api-key": process.env.VTPASS_API_KEY,
                    "secret-key": process.env.VTPASS_SECRET_KEY,
                    "Content-Type": "application/json",
                },
            }
        );

        console.log("✅ VTpass payment response:", vtpassResponse.data);

        if (vtpassResponse.data && vtpassResponse.data.code === '000') {
            user.walletBalance -= numericAmount;
            await user.save();

            const newTransaction = new Transaction({
                userId: user._id,
                type: 'CableTV',
                amount: numericAmount,
                status: 'Successful',
                smartCardNumber: smartCardNumber,
                packageName: selectedPackage,
                transactionId: vtpassResponse.data.content.transactions.transactionId || requestId,
                details: {
                    vtpassResponse: vtpassResponse.data,
                },
            });

            await newTransaction.save();

            res.status(200).json({
                success: true,
                message: 'Payment successful',
                newBalance: user.walletBalance,
                transactionId: newTransaction.transactionId,
                transactionDetails: newTransaction,
            });
        } else {
            const errorMessage = vtpassResponse.data.response_description || vtpassResponse.data.message || 'VTpass payment failed.';
            const failedTransaction = new Transaction({
                userId: user._id,
                type: 'CableTV',
                amount: numericAmount,
                status: 'Failed',
                smartCardNumber: smartCardNumber,
                packageName: selectedPackage,
                transactionId: requestId,
                details: {
                    errorMessage: errorMessage,
                    vtpassResponse: vtpassResponse.data,
                },
            });
            await failedTransaction.save();

            return res.status(400).json({
                success: false,
                message: errorMessage,
                details: vtpassResponse.data
            });
        }

    } catch (err) {
        console.error('❌ CableTV Payment Error:', err.response?.data || err.message);
        const errorTransaction = new Transaction({
            userId: req.body.userId,
            type: 'CableTV',
            amount: req.body.amount ? parseFloat(req.body.amount) : 0,
            status: 'Failed',
            transactionId: `ERROR_${Date.now()}`,
            details: {
                errorMessage: 'Server error during cable TV payment.',
                errorDetails: err.response?.data || err.message,
            },
        });
        await errorTransaction.save().catch(e => console.error("Failed to save error transaction:", e));

        res.status(500).json({
            success: false,
            message: 'Server error during cable TV payment.',
            details: err.response?.data || err.message
        });
    }
});

module.exports = router;
