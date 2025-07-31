// controllers/dataController.js

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
 * Handles the data purchase request.
 * @param {object} req - Express request object.
 * @param {object} res - Express response object.
 */
const buyData = async (req, res) => {
    const { userId, network, phoneNumber, plan, amount } = req.body;

    // Basic validation
    if (!userId || !network || !phoneNumber || !plan || amount <= 0) {
        return res.status(400).json({ message: 'Missing or invalid required fields.' });
    }

    // Ensure environment variables are set
    if (!VTPASS_EMAIL || !VTPASS_API_KEY || !VTPASS_SECRET_KEY || !VTPASS_BASE_URL) {
        console.error("❌ VTpass environment variables (EMAIL, API_KEY, SECRET_KEY, BASE_URL) are not fully set in dataController.js!");
        return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing or incomplete.' });
    }

    try {
        const serviceID = getVtpassServiceId(network, 'data');
        const request_id = uuidv4(); // Generate a unique request ID

        console.log(`[Data] User ${userId} attempting to buy ${plan} on ${network} for ${phoneNumber} (Request ID: ${request_id})`);

        // Step 1: Fetch data variations (plans) for the selected network
        const variationsResponse = await axios.post(`${VTPASS_BASE_URL}/service-variations`, {
            serviceID: serviceID
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': VTPASS_AUTH_HEADER, // Use the Basic Auth header
                'api-key': VTPASS_API_KEY,           // Specific 'api-key' header
                'secret-key': VTPASS_SECRET_KEY      // Specific 'secret-key' header
            }
        });

        const variationsData = variationsResponse.data;
        if (variationsData.code !== '000' || !variationsData.content || !variationsData.content.variations) {
            console.error('[Data] Failed to fetch data plans:', variationsData);
            return res.status(500).json({ message: 'Could not fetch data plans for the selected network.' });
        }

        // Find the variation_code that matches the selected plan and amount
        let variation_code = null;
        for (const variation of variationsData.content.variations) {
            const vtpassPlanAmount = parseFloat(variation.variation_amount);
            const flutterPlanAmount = amount;

            if (vtpassPlanAmount === flutterPlanAmount && variation.name.includes(plan.split(' - ')[0])) {
                variation_code = variation.variation_code;
                break;
            }
        }

        if (!variation_code) {
            return res.status(400).json({ message: `Data plan '${plan}' not found for network '${network}'. Please check VTpass variations.` });
        }

        // Step 2: Purchase the data bundle
        const vtpassResponse = await axios.post(`${VTPASS_BASE_URL}/pay`, {
            request_id: request_id,
            serviceID: serviceID,
            billersCode: phoneNumber, // For data, billersCode is the phone number
            variation_code: variation_code,
            amount: amount.toString(), // Amount of the data plan
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
        console.log('[Data] VTpass Response:', vtpassData);

        if (vtpassData.code === '000' || vtpassData.response_description.includes('successful')) {
            return res.status(200).json({
                message: 'Data purchase initiated successfully!',
                transactionId: vtpassData.content.transactions.transactionId,
                status: vtpassData.response_description,
                data: vtpassData
            });
        } else {
            return res.status(400).json({
                message: vtpassData.response_description || 'Data purchase failed.',
                data: vtpassData
            });
        }

    } catch (error) {
        console.error('[Data] Backend Error:', error.response ? error.response.data : error.message);
        return res.status(500).json({
            message: 'Internal server error during data purchase.',
            error: error.response ? error.response.data : error.message
        });
    }
};

module.exports = {
    buyData
};
