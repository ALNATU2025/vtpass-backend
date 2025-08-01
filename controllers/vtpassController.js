// controllers/vtpassController.js

const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User'); // Assuming you have a User model
const Transaction = require('../models/Transaction'); // Assuming a generic Transaction model

// VTpass API credentials from environment variables.
const VTPASS_API_KEY = process.env.VTPASS_API_KEY;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;
const VTPASS_PUBLIC_KEY = process.env.VTPASS_PUBLIC_KEY;
const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL;

// Check if VTpass credentials are set. This is a crucial check.
if (!VTPASS_API_KEY || !VTPASS_SECRET_KEY || !VTPASS_PUBLIC_KEY || !VTPASS_BASE_URL) {
    console.error("❌ Critical: VTpass environment variables are not set. API calls will fail.");
}

// Global timeout value for all VTpass API calls.
const VTPASS_TIMEOUT = 20000; // 20 seconds

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
        const response = await axios.post(`${VTPASS_BASE_URL}${endpoint}`, payload, {
            headers,
            timeout: VTPASS_TIMEOUT // Added timeout to prevent hanging requests
        });
        console.log(`[${type}] VTpass response received:`, response.data);
        return response.data;
    } catch (error) {
        // More specific error handling for timeouts and network issues
        if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            console.error(`[${type}] VTpass API Timeout: The request to ${endpoint} timed out.`);
            throw new Error(`The request to the VTpass API timed out. Please try again.`);
        }
        console.error(`[${type}] VTpass API Error:`, error.response ? error.response.data : error.message);
        throw new Error(`Failed to process with VTpass. Details: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
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
        const response = await axios.get(`${VTPASS_BASE_URL}${endpoint}`, {
            headers,
            timeout: VTPASS_TIMEOUT // Added timeout to prevent hanging requests
        });
        console.log(`VTpass response received:`, response.data);
        return response.data;
    } catch (error) {
        // More specific error handling for timeouts and network issues
        if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            console.error(`[GET] VTpass API Timeout: The request to ${endpoint} timed out.`);
            throw new Error(`The request to the VTpass API timed out. Please try again.`);
        }
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
    // Note: The original code used req.query, which is correct for GET requests.
    // The previous conversation assumed a POST with req.body, but we'll stick to the correct
    // implementation based on your existing code.
    const { serviceID, billersCode } = req.query;

    if (!serviceID || !billersCode) {
        return res.status(400).json({ message: 'Missing serviceID or billersCode.' });
    }

    try {
        // Use the common GET request function which now has a timeout and error handling.
        const vtpassResponse = await makeVtpassGetRequest(`/merchant-verify?serviceID=${serviceID}&billersCode=${billersCode}`);

        // Check if the VTpass API returned a known error structure
        if (vtpassResponse.content && vtpassResponse.content.error) {
            return res.status(400).json({ success: false, message: vtpassResponse.content.error });
        }
        
        // Check for a successful validation with customer details
        if (vtpassResponse.content && vtpassResponse.content.customer) {
            return res.status(200).json({ success: true, customer: vtpassResponse.content.customer });
        }

        // If neither of the above, it's an unexpected response
        return res.status(500).json({ success: false, message: 'Unexpected response from VTpass.' });

    } catch (error) {
        // The makeVtpassGetRequest function now throws a more descriptive error
        console.error('Error during smart card validation:', error.message);
        return res.status(500).json({
            success: false,
            message: 'Failed to validate smart card.',
            error: error.message
        });
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
    validateSmartCard
};
