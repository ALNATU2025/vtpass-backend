const axios = require('axios');
const {
  v4: uuidv4
} = require('uuid');
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

// ✅ VTpass Header with API and SECRET key
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
    airtime: {
      MTN: 'mtn',
      Glo: 'glo',
      Airtel: 'airtel',
      '9mobile': '9mobile'
    },
    data: {
      MTN: 'mtn-data',
      Glo: 'glo-data',
      Airtel: 'airtel-data',
      '9mobile': '9mobile-data'
    },
    cabletv: {
      DSTV: 'dstv',
      GOTV: 'gotv',
      Startimes: 'startimes'
    },
  };
  return map[type]?.[network];
};

// ====================================================================
// ✅ UPDATED: SMARTCARD VALIDATION
// ⚠️ FIX: Changed to POST request as per VTpass API docs and added response check.
// ====================================================================
const validateSmartCard = async (req, res, next) => {
  const {
    serviceID,
    billersCode
  } = req.query;

  if (!serviceID) {
    return res.status(400).json({
      message: 'Missing serviceID'
    });
  }
  if (!billersCode) {
    return res.status(400).json({
      message: 'Missing billersCode'
    });
  }

  try {
    // ⚠️ CRITICAL FIX: The VTpass API uses a POST method for this endpoint.
    const payload = {
      serviceID,
      billersCode,
    };
    const data = await makeVtpassPostRequest('/merchant-verify', payload);

    // ✅ Added a check to ensure the response indicates success.
    if (data.code === '000' && data.content?.Customer_Name) {
      return res.status(200).json({
        success: true,
        data: data.content,
        message: 'Smartcard validated successfully.'
      });
    } else {
      return res.status(400).json({
        success: false,
        message: data.response_description || 'Smartcard validation failed.',
        errorDetails: data,
      });
    }
  } catch (err) {
    return next({
      statusCode: err.response?.status || 500,
      message: 'Smartcard validation failed',
      errorDetails: err.response?.data || err.message,
    });
  }
};

// ====================================================================
// ✅ UPDATED: AIRTIME PURCHASE
// ⚠️ FIX: Ensured the payload is correctly structured for airtime.
// ====================================================================
const buyAirtime = async (req, res, next) => {
  const {
    userId,
    network,
    amount,
    phone
  } = req.body;

  if (!userId || !network || !amount || !phone) {
    return res.status(400).json({
      message: 'Missing required fields: userId, network, amount, or phone.'
    });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }
    if (user.wallet < amount) {
      return res.status(400).json({
        message: 'Insufficient wallet balance'
      });
    }

    const serviceID = getVtpassServiceId(network, 'airtime');
    if (!serviceID) {
      return res.status(400).json({
        message: 'Invalid network provided'
      });
    }

    const requestId = uuidv4();
    const payload = {
      request_id: requestId,
      serviceID,
      amount,
      phone,
      billersCode: phone, // ✅ FIX: Correctly mapping phone to billersCode
    };

    const result = await makeVtpassPostRequest('/pay', payload);

    // ✅ FIX: More robust success check for both `code` and `response_description`
    if (result.code === '000' || result.response_description?.includes('successful')) {
      user.wallet -= amount;
      await user.save();

      await Transaction.create({
        userId,
        requestId,
        type: 'airtime',
        amount,
        phone,
        serviceID,
        status: 'success',
        details: result,
      });

      return res.status(200).json({
        success: true,
        message: 'Airtime transaction successful',
        result
      });
    } else {
      return res.status(400).json({
        success: false,
        message: result.response_description || 'Airtime transaction failed.'
      });
    }
  } catch (err) {
    return next({
      statusCode: err.response?.status || 500,
      message: 'VTpass airtime failed',
      errorDetails: err.response?.data || err.message,
    });
  }
};

// ====================================================================
// ✅ UPDATED: DATA PURCHASE
// ⚠️ FIX: Ensured the payload is correctly structured for data and removed redundant amount field from VTpass payload.
// ====================================================================
const buyData = async (req, res, next) => {
  const {
    userId,
    network,
    amount,
    phone,
    variationCode
  } = req.body;

  if (!userId || !network || !amount || !phone || !variationCode) {
    return res.status(400).json({
      message: 'Missing required fields: userId, network, amount, phone, or variationCode.'
    });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }
    if (user.wallet < amount) {
      return res.status(400).json({
        message: 'Insufficient wallet balance'
      });
    }

    const serviceID = getVtpassServiceId(network, 'data');
    if (!serviceID) {
      return res.status(400).json({
        message: 'Invalid network provided'
      });
    }

    const requestId = uuidv4();
    const payload = {
      request_id: requestId,
      serviceID,
      billersCode: phone, // ✅ FIX: Correctly mapping phone to billersCode
      variation_code: variationCode,
      phone,
    };

    const result = await makeVtpassPostRequest('/pay', payload);

    // ✅ FIX: More robust success check for both `code` and `response_description`
    if (result.code === '000' || result.response_description?.includes('successful')) {
      user.wallet -= amount;
      await user.save();

      await Transaction.create({
        userId,
        requestId,
        type: 'data',
        amount,
        phone,
        serviceID,
        variationCode,
        status: 'success',
        details: result,
      });

      return res.status(200).json({
        success: true,
        message: 'Data transaction successful',
        result
      });
    } else {
      return res.status(400).json({
        success: false,
        message: result.response_description || 'Data transaction failed.'
      });
    }
  } catch (err) {
    return next({
      statusCode: err.response?.status || 500,
      message: 'VTpass data failed',
      errorDetails: err.response?.data || err.message,
    });
  }
};

// ====================================================================
// ✅ UPDATED: CABLETV PURCHASE
// ⚠️ FIX: Ensured the payload is correctly structured for cabletv.
// ====================================================================
const buyCableTV = async (req, res, next) => {
  const {
    userId,
    network,
    amount,
    phone,
    billersCode,
    variationCode
  } = req.body;

  if (!userId || !network || !amount || !phone || !billersCode || !variationCode) {
    return res.status(400).json({
      message: 'Missing required fields for cable TV purchase.'
    });
  }

  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: 'User not found'
      });
    }
    if (user.wallet < amount) {
      return res.status(400).json({
        message: 'Insufficient wallet balance'
      });
    }

    const serviceID = getVtpassServiceId(network, 'cabletv');
    if (!serviceID) {
      return res.status(400).json({
        message: 'Invalid network provided'
      });
    }

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

    // ✅ FIX: More robust success check for both `code` and `response_description`
    if (result.code === '000' || result.response_description?.includes('successful')) {
      user.wallet -= amount;
      await user.save();

      await Transaction.create({
        userId,
        requestId,
        type: 'cabletv',
        amount,
        phone,
        billersCode,
        serviceID,
        variationCode,
        status: 'success',
        details: result,
      });

      return res.status(200).json({
        success: true,
        message: 'Cable TV transaction successful',
        result
      });
    } else {
      return res.status(400).json({
        success: false,
        message: result.response_description || 'Cable TV transaction failed.'
      });
    }
  } catch (err) {
    return next({
      statusCode: err.response?.status || 500,
      message: 'VTpass cable TV failed',
      errorDetails: err.response?.data || err.message,
    });
  }
};

module.exports = {
  validateSmartCard,
  buyAirtime,
  buyData,
  buyCableTV,
};
