// controllers/vtpassController.js

const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User'); // Assuming you have a User model
const Transaction = require('../models/Transaction'); // Assuming a generic Transaction model

// VTpass API credentials from environment variables.
// NOTE: It's best to load these once in index.js, but this is a fail-safe.
const VTPASS_API_KEY = process.env.VTPASS_API_KEY;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;
const VTPASS_PUBLIC_KEY = process.env.VTPASS_PUBLIC_KEY; 
const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL;

// Check if VTpass credentials are set. This is a crucial check.
if (!VTPASS_API_KEY || !VTPASS_SECRET_KEY || !VTPASS_PUBLIC_KEY || !VTPASS_BASE_URL) {
    console.error("❌ Critical: VTpass environment variables are not set. API calls will fail.");
}

/**
 * Common function to make a POST request to VTpass.
 */
const makeVtpassPostRequest = async (endpoint, payload, type) => {
    const headers = {
        'api-key': VTPASS_API_KEY,
        'secret-key': VTPASS_SECRET_KEY,
        'Content-Type': 'application/json',
    };

    console.log(`[${type}] Sending POST request to VTpass at ${endpoint} with payload:`, payload);

    try {
        const response = await axios.post(`${VTPASS_BASE_URL}${endpoint}`, payload, { headers });
        console.log(`[${type}] VTpass response received:`, response.data);
        return response.data;
    } catch (error) {
        console.error(`[${type}] VTpass API Error:`, error.response ? error.response.data : error.message);
        throw new Error(`Failed to process payment with VTpass. Details: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
};

/**
 * Common function to make a GET request to VTpass.
 */
const makeVtpassGetRequest = async (endpoint) => {
    const headers = {
        'api-key': VTPASS_API_KEY,
        'public-key': VTPASS_PUBLIC_KEY,
        'Content-Type': 'application/json',
    };

    console.log(`Sending GET request to VTpass at ${endpoint}`);

    try {
        const response = await axios.get(`${VTPASS_BASE_URL}${endpoint}`, { headers });
        console.log(`VTpass response received:`, response.data);
        return response.data;
    } catch (error) {
        console.error(`VTpass API GET Error:`, error.response ? error.response.data : error.message);
        throw new Error(`Failed to fetch data from VTpass. Details: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
};

/**
 * Helper function to map user-friendly names to VTpass service IDs.
 * NOTE: It's better to have this function in the controller file.
 */
const getVtpassServiceId = (network, type) => {
    const serviceMap = {
        'airtime': {
            'MTN': 'mtn', 'Glo': 'glo', 'Airtel': 'airtel', '9mobile': '9mobile',
        },
        'data': {
            'MTN': 'mtn-data', 'Glo': 'glo-data', 'Airtel': 'airtel-data', '9mobile': '9mobile-data',
        },
        'cabletv': {
            'DSTV': 'dstv', 'GOTV': 'gotv', 'Startimes': 'startimes',
        }
    };

    const serviceID = serviceMap[type]?.[network];
    if (!serviceID) {
        throw new Error(`Invalid service: ${network} for type: ${type}`);
    }
    return serviceID;
};

/**
 * Handles smart card validation before a cable TV purchase.
 */
const validateSmartCard = async (req, res) => {
    const { serviceID, billersCode } = req.query; 

    if (!serviceID || !billersCode) {
        return res.status(400).json({ message: 'Missing serviceID or billersCode.' });
    }

    try {
        const vtpassResponse = await makeVtpassGetRequest(`/merchant-verify?serviceID=${serviceID}&billersCode=${billersCode}`);

        if (vtpassResponse.content && vtpassResponse.content.error) {
            return res.status(400).json({ success: false, message: vtpassResponse.content.error });
        }
        if (vtpassResponse.content && vtpassResponse.content.customer) {
            return res.status(200).json({ success: true, customer: vtpassResponse.content.customer });
        }

        return res.status(500).json({ success: false, message: 'Unexpected response from VTpass.' });

    } catch (error) {
        return res.status(500).json({ success: false, message: 'Failed to validate smart card.', error: error.message });
    }
};


/**
 * Handles the purchase of airtime.
 */
const buyAirtime = async (req, res) => {
    const { userId, network, phoneNumber, amount } = req.body;
    // ... (rest of buyAirtime logic remains the same)
};

/**
 * Handles the purchase of data.
 */
const buyData = async (req, res) => {
    const { userId, network, phoneNumber, plan, amount } = req.body;
    // ... (rest of buyData logic remains the same)
};

/**
 * Handles the purchase of a cable TV subscription.
 */
const buyCableTV = async (req, res) => {
    const { userId, serviceID, smartCardNumber, variation_code, amount, phone } = req.body;
    // ... (rest of buyCableTV logic remains the same)
};

module.exports = {
    buyAirtime,
    buyData,
    buyCableTV,
    validateSmartCard // NEW: Export the new function
};