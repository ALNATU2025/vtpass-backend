// controllers/airtimeController.js

require('dotenv').config(); // Load environment variables for this controller

const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const { getVtpassServiceId } = require('../utils/vtpass'); // Import helper

// VTpass API credentials directly from environment variables
const VTPASS_EMAIL = process.env.VTPASS_EMAIL; // Used for Basic Auth username
const VTPASS_API_KEY = process.env.VTPASS_API_KEY; // Used for Basic Auth password and 'api-key' header
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY; // Used for 'secret-key' header
const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL;

// Basic authentication header for VTpass API (using email as username, API_KEY as password)
// This is a common VTpass Basic Auth format.
const VTPASS_AUTH_HEADER = 'Basic ' + Buffer.from(`${VTPASS_EMAIL}:${VTPASS_API_KEY}`).toString('base64');

/**
 * Handles the airtime purchase request.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
const buyAirtime = async (req, res) => {
    const { userId, network, phoneNumber, amount } = req.body;

    // Basic validation
    if (!userId || !network || !phoneNumber || !amount || amount <= 0) {
        return res.status(400).json({ message: 'Missing or invalid required fields.' });
    }

    // Ensure environment variables are set
    if (!VTPASS_EMAIL || !VTPASS_API_KEY || !VTPASS_SECRET_KEY || !VTPASS_BASE_URL) {
        console.error("❌ VTpass environment variables (EMAIL, API_KEY, SECRET_KEY, BASE_URL) are not fully set in airtimeController.js!");
        return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing or incomplete.' });
    }

    try {
        const serviceID = getVtpassServiceId(network, 'airtime');
        const request_id = uuidv4(); // Generate a unique request ID for the transaction

        console.log(`[Airtime] User ${userId} attempting to buy ${amount} on ${network} for ${phoneNumber} (Request ID: ${request_id})`);

        const vtpassResponse = await axios.post(`${VTPASS_BASE_URL}/pay`, {
            request_id: request_id,
            serviceID: serviceID,
            amount: amount.toString(), // VTpass expects amount as a string
            phone: phoneNumber
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': VTPASS_AUTH_HEADER, // Use the Basic Auth header
                'api-key': VTPASS_API_KEY,           // Specific 'api-key' header
                'secret-key': VTPASS_SECRET_KEY      // Specific 'secret-key' header
            }
        });

        const vtpassData = vtpassResponse.data;
        console.log('[Airtime] VTpass Response:', vtpassData);

        if (vtpassData.code === '000' || vtpassData.response_description.includes('successful')) {
            // Transaction successful or pending (VTpass often returns 'successful' even if pending)
            // In a real app, you'd update your user's wallet and transaction history here.
            return res.status(200).json({
                message: 'Airtime purchase initiated successfully!',
                transactionId: vtpassData.content.transactions.transactionId,
                status: vtpassData.response_description,
                data: vtpassData
            });
        } else {
            // Transaction failed or an error occurred on VTpass side
            return res.status(400).json({
                message: vtpassData.response_description || 'Airtime purchase failed.',
                data: vtpassData
            });
        }

    } catch (error) {
        console.error('[Airtime] Backend Error:', error.response ? error.response.data : error.message);
        return res.status(500).json({
            message: 'Internal server error during airtime purchase.',
            error: error.response ? error.response.data : error.message
        });
    }
};

module.exports = {
    buyAirtime
};
