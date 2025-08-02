const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();
const cors = require('cors');

// Load environment variables from .env file
require('dotenv').config();

app.use(express.json());
app.use(cors());

const VTPASS_API_KEY = process.env.VTPASS_API_KEY;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;
const BASE_URL = 'https://sandbox.vtpass.com/api'; // Use sandbox for testing

// Function to generate the Authorization header
const getAuthHeader = () => {
    // Log the keys to the console for debugging. This should be removed in production.
    console.log(`[DEBUG] API Key: ${VTPASS_API_KEY ? 'Loaded' : 'NOT loaded'}`);
    console.log(`[DEBUG] Secret Key: ${VTPASS_SECRET_KEY ? 'Loaded' : 'NOT loaded'}`);

    if (!VTPASS_API_KEY || !VTPASS_SECRET_KEY) {
        console.error('API keys are missing.');
        return null;
    }

    const authString = `${VTPASS_API_KEY}:${VTPASS_SECRET_KEY}`;
    const base64Auth = Buffer.from(authString).toString('base64');
    return `Basic ${base64Auth}`;
};

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Middleware to check for API keys
app.use((req, res, next) => {
    if (!VTPASS_API_KEY || !VTPASS_SECRET_KEY) {
        return res.status(500).json({ error: 'VTpass API keys are not configured.' });
    }
    next();
});

// 1. Get a list of supported services for a category
app.get('/services/:category', async (req, res) => {
    const { category } = req.params;
    const url = `${BASE_URL}/services?category=${category}`;
    console.log(`[DEBUG] Requesting services from URL: ${url}`);
    
    try {
        const authHeader = getAuthHeader();
        if (!authHeader) {
            return res.status(500).json({ error: 'Authentication failed.' });
        }
        const response = await axios.get(url, {
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching services:', error.response ? error.response.data : error.message);
        res.status(error.response?.status || 500).json({ error: 'Failed to fetch services.', details: error.message });
    }
});

// 2. Get a list of variations for a specific service (e.g., MTN, Glo, etc.)
app.get('/variations/:serviceId', async (req, res) => {
    const { serviceId } = req.params;
    const url = `${BASE_URL}/service-variations?serviceID=${serviceId}`;
    console.log(`[DEBUG] Requesting variations from URL: ${url}`);
    
    try {
        const authHeader = getAuthHeader();
        if (!authHeader) {
            return res.status(500).json({ error: 'Authentication failed.' });
        }
        const response = await axios.get(url, {
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error fetching variations:', error.response ? error.response.data : error.message);
        res.status(error.response?.status || 500).json({ error: 'Failed to fetch service variations.', details: error.message });
    }
});

// 3. Validate smartcard or meter number
app.post('/validate', async (req, res) => {
    const { serviceID, billersCode, type } = req.body;
    const url = `${BASE_URL}/merchant-verify`;
    console.log(`[DEBUG] Validating smartcard/meter from URL: ${url}`);
    
    if (!serviceID || !billersCode || !type) {
        return res.status(400).json({ error: 'Missing required fields: serviceID, billersCode, and type.' });
    }

    try {
        const authHeader = getAuthHeader();
        if (!authHeader) {
            return res.status(500).json({ error: 'Authentication failed.' });
        }
        
        const response = await axios.post(url, {
            serviceID,
            billersCode,
            type
        }, {
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error validating smartcard/meter:', error.response ? error.response.data : error.message);
        res.status(error.response?.status || 500).json({ error: 'Failed to validate smartcard/meter.', details: error.message });
    }
});

// 4. Send a transaction to purchase a product
app.post('/purchase', async (req, res) => {
    const { serviceID, amount, phone, variation_code, billersCode } = req.body;
    const url = `${BASE_URL}/pay`;
    console.log(`[DEBUG] Purchasing a product from URL: ${url}`);
    
    if (!serviceID || !amount || !phone || !variation_code) {
        return res.status(400).json({ error: 'Missing required fields: serviceID, amount, phone, and variation_code.' });
    }

    const request_id = crypto.randomUUID(); // Use UUID for request_id

    const payload = {
        request_id,
        serviceID,
        amount,
        phone,
        variation_code,
        billersCode
    };

    try {
        const authHeader = getAuthHeader();
        if (!authHeader) {
            return res.status(500).json({ error: 'Authentication failed.' });
        }

        const response = await axios.post(url, payload, {
            headers: {
                'Authorization': authHeader,
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Error with purchase transaction:', error.response ? error.response.data : error.message);
        res.status(error.response?.status || 500).json({ error: 'Failed to complete transaction.', details: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
