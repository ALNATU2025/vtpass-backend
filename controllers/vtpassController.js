const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const Transaction = require('../models/Transaction');

// Environment variables
const VTPASS_API_KEY = process.env.VTPASS_API_KEY;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;
const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL || 'https://vtpass.com/api';
const VTPASS_TIMEOUT = 20000;

if (!VTPASS_API_KEY || !VTPASS_SECRET_KEY || !VTPASS_BASE_URL) {
  console.error('❌ VTpass credentials missing in .env');
}

// ✅ New VTpass Header with API and SECRET key
const getAuthHeader = () => {
  return {
    'api-key': VTPASS_API_KEY,
    'secret-key': VTPASS_SECRET_KEY,
    'Content-Type': 'application/json',
  };
};

// GET request (e.g., smartcard verification)
const makeVtpassGetRequest = async (endpoint) => {
  const headers = getAuthHeader();
  const response = await axios.get(`${VTPASS_BASE_URL}${endpoint}`, {
    headers,
    timeout: VTPASS_TIMEOUT,
  });
  return response.data;
};

// POST request (e.g., payments)
const makeVtpassPostRequest = async (endpoint, payload) => {
  const headers = getAuthHeader();
  const response = await axios.post(`${VTPASS_BASE_URL}${endpoint}`, payload, {
    headers,
    timeout: VTPASS_TIMEOUT,
  });
  return response.data;
};

// Map VTpass service IDs
const getVtpassServiceId = (network, type) => {
  const map = {
    airtime: { MTN: 'mtn', Glo: 'glo', Airtel: 'airtel', '9mobile': '9mobile' },
    data: { MTN: 'mtn-data', Glo: 'glo-data', Airtel: 'airtel-data', '9mobile': '9mobile-data' },
    cabletv: { DSTV: 'dstv', GOTV: 'gotv', Startimes: 'startimes' },
  };
  return map[type]?.[network];
};

// ✅ Smartcard validation
const validateSmartCard = async (req, res, next) => {
  const { serviceID, billersCode } = req.query;

  if (!serviceID || !billersCode) {
    return res.status(400).json({ message: 'Missing serviceID or billersCode' });
  }

  try {
    const data = await makeVtpassGetRequest(`/merchant-verify?serviceID=${serviceID}&billersCode=${billersCode}`);
    return res.status(200).json({ success: true, data });
  } catch (err) {
    return next({
      statusCode: err.response?.status || 500,
      message: 'Smartcard validation failed',
      errorDetails: err.response?.data || err.message,
    });
  }
};

// ✅ Generic purchase handler
const buyService = async (req, res, next, type) => {
  const { userId, network, amount, phone, billersCode, variationCode } = req.body;

  if (!userId || !amount || !network) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const user = await User.findById(userId);
    if (!user || user.wallet < amount) {
      return res.status(400).json({ message: 'Insufficient wallet balance' });
    }

    const serviceID = getVtpassServiceId(network, type);
    const requestId = uuidv4();

    const payload = {
      request_id: requestId,
      serviceID,
      amount,
      phone,
      billersCode,
      variation_code: variationCode,
    };

    const result = await makeVtpassPostRequest('/pay', payload);

    if (result.code === '000') {
      user.wallet -= amount;
      await user.save();

      await Transaction.create({
        userId,
        requestId,
        type,
        amount,
        phone,
        billersCode,
        serviceID,
        status: 'success',
        details: result,
      });

      return res.status(200).json({ success: true, message: 'Transaction successful', result });
    } else {
      return res.status(400).json({ success: false, message: result.response_description });
    }
  } catch (err) {
    return next({
      statusCode: err.response?.status || 500,
      message: `VTpass ${type} failed`,
      errorDetails: err.response?.data || err.message,
    });
  }
};

// Exported handlers
const buyAirtime = (req, res, next) => buyService(req, res, next, 'airtime');
const buyData = (req, res, next) => buyService(req, res, next, 'data');
const buyCableTV = (req, res, next) => buyService(req, res, next, 'cabletv');

module.exports = {
  validateSmartCard,
  buyAirtime,
  buyData,
  buyCableTV,
};
