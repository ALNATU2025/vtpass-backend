// controllers/vtpassController.js

const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User'); // Assuming you have a User model
const Transaction = require('../models/Transaction'); // Assuming a generic Transaction model

// VTpass API credentials from environment variables.
// NOTE: It's best to load these once in index.js, but this is a fail-safe.
const VTPASS_API_KEY = process.env.VTPASS_API_KEY;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;
const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL;

// Check if VTpass credentials are set. This is a crucial check.
if (!VTPASS_API_KEY || !VTPASS_SECRET_KEY || !VTPASS_BASE_URL) {
    console.error("❌ Critical: VTpass environment variables are not set. API calls will fail.");
}

/**
 * Common function to make a payment to VTpass.
 * @param {object} payload - The body to send to the VTpass /pay endpoint.
 * @param {string} type - The transaction type (e.g., 'Airtime', 'Data', 'CableTV').
 * @returns {object} The VTpass API response data.
 */
const makeVtpassPayment = async (payload, type) => {
    const headers = {
        'api-key': VTPASS_API_KEY,
        'secret-key': VTPASS_SECRET_KEY,
        'Content-Type': 'application/json',
    };

    console.log(`[${type}] Sending request to VTpass with payload:`, payload);

    try {
        const response = await axios.post(`${VTPASS_BASE_URL}/pay`, payload, { headers });
        console.log(`[${type}] VTpass response received:`, response.data);
        return response.data;
    } catch (error) {
        console.error(`[${type}] VTpass API Error:`, error.response ? error.response.data : error.message);
        throw new Error(`Failed to process payment with VTpass. Details: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
};

/**
 * Handles the purchase of airtime.
 */
const buyAirtime = async (req, res) => {
    const { userId, network, phoneNumber, amount } = req.body;

    if (!userId || !network || !phoneNumber || !amount || amount <= 0) {
        return res.status(400).json({ message: 'Missing or invalid required fields (userId, network, phoneNumber, amount).' });
    }
    
    // NOTE: `getVtpassServiceId` should map a user-friendly name ('MTN') to VTpass's service ID ('mtn').
    const serviceID = getVtpassServiceId(network, 'airtime');
    const request_id = uuidv4();

    try {
        // Find user and check balance (if you have a wallet system)
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (user.walletBalance < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });
        }
        
        // --- Wallet Deduction (BEFORE API call) ---
        // It's safer to deduct the balance before the call, and refund on failure.
        user.walletBalance -= amount;
        await user.save();

        const vtpassResponse = await makeVtpassPayment({
            request_id: request_id,
            serviceID: serviceID,
            amount: amount,
            phone: phoneNumber,
        }, 'Airtime');

        // Check VTpass response and update transaction status
        if (vtpassResponse.code === '000' || vtpassResponse.response_description.includes('successful')) {
            // Save transaction as successful
            const newTransaction = new Transaction({
                userId, type: 'Airtime', amount, status: 'Successful', 
                transactionId: vtpassResponse.content.transactions.transactionId,
                details: { network, phoneNumber }
            });
            await newTransaction.save();
            return res.status(200).json({ message: 'Airtime purchase successful.', data: vtpassResponse, newBalance: user.walletBalance });
        } else {
            // --- Refund on Failure ---
            user.walletBalance += amount;
            await user.save();

            const errorMessage = vtpassResponse.response_description || 'Airtime purchase failed on VTpass side.';
            const failedTransaction = new Transaction({
                userId, type: 'Airtime', amount, status: 'Failed', 
                transactionId: request_id, // Use our generated ID if VTpass didn't provide one
                details: { network, phoneNumber, errorMessage }
            });
            await failedTransaction.save();
            return res.status(400).json({ message: errorMessage, data: vtpassResponse, newBalance: user.walletBalance });
        }

    } catch (error) {
        // --- Refund on catastrophic failure ---
        // You'll need to re-fetch the user to ensure no race condition on the balance
        const user = await User.findById(userId);
        if (user) {
            user.walletBalance += amount;
            await user.save();
        }

        const errorMessage = error.message;
        const errorTransaction = new Transaction({
            userId, type: 'Airtime', amount, status: 'Failed',
            transactionId: request_id, 
            details: { errorMessage }
        });
        await errorTransaction.save();

        return res.status(500).json({ message: 'Internal server error during airtime purchase.', error: errorMessage });
    }
};

/**
 * Handles the purchase of data.
 */
const buyData = async (req, res) => {
    const { userId, network, phoneNumber, plan, amount } = req.body;

    if (!userId || !network || !phoneNumber || !plan || amount <= 0) {
        return res.status(400).json({ message: 'Missing or invalid required fields (userId, network, phoneNumber, plan, amount).' });
    }

    const serviceID = getVtpassServiceId(network, 'data');
    const request_id = uuidv4();

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        if (user.walletBalance < amount) return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });
        
        // --- Fetch data plans to find variation code ---
        const variationsResponse = await axios.post(`${VTPASS_BASE_URL}/service-variations`, { serviceID });
        const variations = variationsResponse.data.content?.variations || [];
        
        const selectedVariation = variations.find(v => v.variation_code === plan);
        if (!selectedVariation || parseFloat(selectedVariation.variation_amount) !== amount) {
            return res.status(400).json({ message: 'Invalid data plan or amount for the selected network.' });
        }
        
        // --- Wallet Deduction & Transaction Save (Before VTpass call) ---
        user.walletBalance -= amount;
        await user.save();

        const vtpassResponse = await makeVtpassPayment({
            request_id: request_id,
            serviceID: serviceID,
            billersCode: phoneNumber,
            variation_code: selectedVariation.variation_code,
            amount: amount,
            phone: phoneNumber,
        }, 'Data');

        // Check VTpass response and update transaction status
        if (vtpassResponse.code === '000' || vtpassResponse.response_description.includes('successful')) {
            const newTransaction = new Transaction({
                userId, type: 'Data', amount, status: 'Successful', 
                transactionId: vtpassResponse.content.transactions.transactionId,
                details: { network, phoneNumber, plan }
            });
            await newTransaction.save();
            return res.status(200).json({ message: 'Data purchase successful.', data: vtpassResponse, newBalance: user.walletBalance });
        } else {
            // Refund on failure
            user.walletBalance += amount;
            await user.save();

            const errorMessage = vtpassResponse.response_description || 'Data purchase failed on VTpass side.';
            const failedTransaction = new Transaction({
                userId, type: 'Data', amount, status: 'Failed',
                transactionId: request_id,
                details: { network, phoneNumber, plan, errorMessage }
            });
            await failedTransaction.save();
            return res.status(400).json({ message: errorMessage, data: vtpassResponse, newBalance: user.walletBalance });
        }

    } catch (error) {
        const user = await User.findById(userId);
        if (user) {
            user.walletBalance += amount;
            await user.save();
        }

        const errorMessage = error.message;
        const errorTransaction = new Transaction({
            userId, type: 'Data', amount, status: 'Failed',
            transactionId: request_id,
            details: { errorMessage }
        });
        await errorTransaction.save();

        return res.status(500).json({ message: 'Internal server error during data purchase.', error: errorMessage });
    }
};

/**
 * Handles the purchase of a cable TV subscription.
 */
const buyCableTV = async (req, res) => {
    const { userId, serviceID, smartCardNumber, variation_code, amount, phone } = req.body;

    if (!userId || !serviceID || !smartCardNumber || !variation_code || !amount || amount <= 0 || !phone) {
        return res.status(400).json({ message: 'Missing or invalid required fields.' });
    }

    const request_id = uuidv4();

    try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found.' });
        if (user.walletBalance < amount) return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });
        
        user.walletBalance -= amount;
        await user.save();

        const vtpassResponse = await makeVtpassPayment({
            request_id: request_id,
            serviceID: serviceID,
            billersCode: smartCardNumber,
            variation_code: variation_code,
            amount: amount,
            phone: phone,
        }, 'CableTV');

        if (vtpassResponse.code === '000') {
            const newTransaction = new Transaction({
                userId, type: 'CableTV', amount, status: 'Successful', 
                transactionId: vtpassResponse.content.transactions.transactionId,
                details: { serviceID, smartCardNumber, variation_code }
            });
            await newTransaction.save();
            return res.status(200).json({ message: 'Cable TV payment successful.', data: vtpassResponse, newBalance: user.walletBalance });
        } else {
            user.walletBalance += amount;
            await user.save();

            const errorMessage = vtpassResponse.response_description || 'Cable TV payment failed on VTpass side.';
            const failedTransaction = new Transaction({
                userId, type: 'CableTV', amount, status: 'Failed',
                transactionId: request_id,
                details: { serviceID, smartCardNumber, variation_code, errorMessage }
            });
            await failedTransaction.save();
            return res.status(400).json({ message: errorMessage, data: vtpassResponse, newBalance: user.walletBalance });
        }
    } catch (error) {
        const user = await User.findById(userId);
        if (user) {
            user.walletBalance += amount;
            await user.save();
        }

        const errorMessage = error.message;
        const errorTransaction = new Transaction({
            userId, type: 'CableTV', amount, status: 'Failed',
            transactionId: request_id,
            details: { errorMessage }
        });
        await errorTransaction.save();

        return res.status(500).json({ message: 'Internal server error during cable TV payment.', error: errorMessage });
    }
};

module.exports = {
    buyAirtime,
    buyData,
    buyCableTV
};