// vtpassRoutes.js
const express = require('express');
const axios = require('axios');
const router = express.Router();

// --- VTpass API Configuration ---
// These variables should be loaded from your .env file
const VTPASS_URL = process.env.VTPASS_URL;
const VTPASS_API_KEY = process.env.VTPASS_API_KEY;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;

// IMPORTANT: A critical check to ensure environment variables are loaded
if (!VTPASS_URL || !VTPASS_API_KEY || !VTPASS_SECRET_KEY) {
  console.error("Critical Error: Missing VTpass environment variables. Please check your .env file and ensure it is being loaded correctly in your main server file.");
  // If the keys are missing, the server will log an error but continue to run.
  // The API calls will still fail, but this helps you diagnose the problem.
}

// Function to generate a unique request ID in the required YYYYMMDDHHII format
const generateRequestId = () => {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');

  // Generate a random 8-character alphanumeric string to ensure uniqueness
  const randomSuffix = Math.random().toString(36).substring(2, 10);

  return `${year}${month}${day}${hours}${minutes}${seconds}${randomSuffix}`;
};

// Middleware to log API requests (optional, but good for debugging)
router.use((req, res, next) => {
  console.log(`[VTpass Route] Incoming ${req.method} request to ${req.originalUrl}`);
  next();
});

// --- API Endpoints ---

/**
 * @swagger
 * /buy-airtime:
 * post:
 * summary: Purchase airtime on VTpass
 * tags: [VTpass]
 * requestBody:
 * required: true
 * content:
 * application/json:
 * schema:
 * type: object
 * properties:
 * phone:
 * type: string
 * example: "08012345678"
 * serviceID:
 * type: string
 * example: "mtn"
 * amount:
 * type: number
 * example: 100
 * responses:
 * 200:
 * description: Airtime purchase was successful
 * content:
 * application/json:
 * schema:
 * type: object
 * 400:
 * description: Missing required parameters
 * 500:
 * description: Failed to process airtime purchase
 */
router.post('/buy-airtime', async (req, res) => {
  const { phone, serviceID, amount } = req.body;
  if (!phone || !serviceID || !amount) {
    return res.status(400).json({ error: 'Missing required parameters: phone, serviceID, or amount' });
  }

  const payload = {
    request_id: generateRequestId(),
    serviceID: serviceID,
    amount: amount,
    phone: phone,
  };

  const headers = {
    'api-key': VTPASS_API_KEY,
    'secret-key': VTPASS_SECRET_KEY,
    'Content-Type': 'application/json',
  };

  console.log(`Sending Airtime request for ${phone}...`, payload);

  try {
    const response = await axios.post(`${VTPASS_URL}/pay`, payload, { headers });
    res.json(response.data);
  } catch (error) {
    console.error('Error in /buy-airtime:', error.response ? error.response.data : error.message);
    res.status(500).json({
      error: 'Failed to process airtime purchase',
      details: error.response ? error.response.data : error.message
    });
  }
});

/**
 * @swagger
 * /buy-data:
 * post:
 * summary: Purchase data on VTpass
 * tags: [VTpass]
 * requestBody:
 * required: true
 * content:
 * application/json:
 * schema:
 * type: object
 * properties:
 * phone:
 * type: string
 * example: "08012345678"
 * serviceID:
 * type: string
 * example: "mtn-data"
 * variation_code:
 * type: string
 * example: "mtn-100mb-100"
 * responses:
 * 200:
 * description: Data purchase was successful
 * content:
 * application/json:
 * schema:
 * type: object
 * 400:
 * description: Missing required parameters
 * 500:
 * description: Failed to process data purchase
 */
router.post('/buy-data', async (req, res) => {
  const { phone, serviceID, variation_code } = req.body;
  if (!phone || !serviceID || !variation_code) {
    return res.status(400).json({ error: 'Missing required parameters: phone, serviceID, or variation_code' });
  }

  const payload = {
    request_id: generateRequestId(),
    serviceID: serviceID,
    variation_code: variation_code,
    phone: phone,
  };

  const headers = {
    'api-key': VTPASS_API_KEY,
    'secret-key': VTPASS_SECRET_KEY,
    'Content-Type': 'application/json',
  };

  console.log(`Sending Data purchase request for ${phone}...`, payload);

  try {
    const response = await axios.post(`${VTPASS_URL}/pay`, payload, { headers });
    res.json(response.data);
  } catch (error) {
    console.error('Error in /buy-data:', error.response ? error.response.data : error.message);
    res.status(500).json({
      error: 'Failed to process data purchase',
      details: error.response ? error.response.data : error.message
    });
  }
});

/**
 * @swagger
 * /buy-cabletv:
 * post:
 * summary: Purchase a cable TV subscription on VTpass
 * tags: [VTpass]
 * requestBody:
 * required: true
 * content:
 * application/json:
 * schema:
 * type: object
 * properties:
 * billersCode:
 * type: string
 * example: "1234567890"
 * serviceID:
 * type: string
 * example: "dstv"
 * variation_code:
 * type: string
 * example: "dstv-padi"
 * phone:
 * type: string
 * example: "08012345678"
 * amount:
 * type: number
 * example: 1850
 * responses:
 * 200:
 * description: Cable TV subscription was successful
 * content:
 * application/json:
 * schema:
 * type: object
 * 400:
 * description: Missing required parameters
 * 500:
 * description: Failed to process cable TV subscription
 */
router.post('/buy-cabletv', async (req, res) => {
  const { billersCode, serviceID, variation_code, phone, amount } = req.body;
  if (!billersCode || !serviceID || !variation_code || !phone || !amount) {
    return res.status(400).json({ error: 'Missing required parameters: billersCode, serviceID, variation_code, phone, or amount' });
  }

  const payload = {
    request_id: generateRequestId(),
    serviceID: serviceID,
    billersCode: billersCode,
    variation_code: variation_code,
    phone: phone,
    amount: amount,
  };

  const headers = {
    'api-key': VTPASS_API_KEY,
    'secret-key': VTPASS_SECRET_KEY,
    'Content-Type': 'application/json',
  };

  console.log(`Sending Cable TV request for smartcard ${billersCode}...`, payload);

  try {
    const response = await axios.post(`${VTPASS_URL}/pay`, payload, { headers });
    res.json(response.data);
  } catch (error) {
    console.error('Error in /buy-cabletv:', error.response ? error.response.data : error.message);
    res.status(500).json({
      error: 'Failed to process cable TV subscription',
      details: error.response ? error.response.data : error.message
    });
  }
});

// Export the router
module.exports = router;
