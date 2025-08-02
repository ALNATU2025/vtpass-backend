// vtpassController.js

require('dotenv').config();
const axios = require('axios');
const { v4: uuidv4 } = require('uuid'); // Import uuid for generating unique IDs

// Assuming you have a database connection and models set up
const Transaction = require('../models/Transaction'); // Import the Transaction model
const User = require('../models/User'); // Import the User model

const VTPASS_BASE_URL = process.env.VTPASS_BASE_URL;
const VTPASS_SECRET_KEY = process.env.VTPASS_SECRET_KEY;
const VTPASS_API_KEY = process.env.VTPASS_API_KEY;

// Check if keys are loaded
if (!VTPASS_SECRET_KEY || !VTPASS_API_KEY) {
  console.error("🚨 VTPASS API keys not found in .env file. Please add them to proceed.");
}

// Reusable function to make a post request to the VTpass API
// This function now handles user wallet debit, credit, and transaction logging.
async function postToVtpass(endpoint, data, res, userId, transactionAmount, serviceType) {
  let transactionId;
  let transactionStatus = 'pending';

  try {
    // 1. Check if the user exists and has enough funds
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    if (user.wallet < transactionAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient funds.' });
    }

    // 2. Debit the user's wallet before making the API call
    user.wallet -= transactionAmount;
    await user.save();

    // 3. Make the VTpass API call
    const response = await axios.post(`${VTPASS_BASE_URL}${endpoint}`, data, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${VTPASS_API_KEY}:${VTPASS_SECRET_KEY}`).toString('base64')}`
      }
    });

    // 4. Update the transaction status and save to the database on success
    transactionStatus = 'success';
    await Transaction.create({
      userId,
      amount: transactionAmount,
      service: serviceType,
      vtpassRequestId: data.request_id,
      vtpassTransactionId: response.data.content.transactions.transactionId,
      status: transactionStatus,
      responseDetails: response.data
    });

    // Return a success response
    res.status(response.status).json({
      success: true,
      data: response.data
    });

  } catch (error) {
    // 💡 BEGIN DEBUGGING LOGS 💡
    console.error(`🚨 Error during API call to ${endpoint}:`, error.message);
    if (error.response) {
      console.error('Raw API Response Status:', error.response.status);
      console.error('Raw API Response Data:', error.response.data);
    } else {
      console.error('No response received from API:', error.request);
    }
    // 💡 END DEBUGGING LOGS 💡
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.response_description || 'An unknown error occurred with the VTpass API.';

    // 5. If VTpass call fails, credit the amount back to the user's wallet
    if (userId) {
      const user = await User.findById(userId);
      if (user) {
        user.wallet += transactionAmount;
        await user.save();
      }
    }

    // 6. Log the failed transaction
    transactionStatus = 'failed';
    await Transaction.create({
      userId,
      amount: transactionAmount,
      service: serviceType,
      vtpassRequestId: data.request_id,
      status: transactionStatus,
      responseDetails: error.response?.data || { message: error.message }
    });

    // Return a structured error response
    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      errorDetails: error.response?.data || { message: error.message }
    });
  }
}

// Controller functions for different VTpass services
exports.purchaseAirtime = async (req, res) => {
  // Assuming a user ID is available from a preceding authentication middleware
  const userId = req.userId;
  const { serviceID, amount, phone, billersCode } = req.body;
  const request_id = uuidv4(); // Use uuid to generate a unique request ID
  const data = {
    request_id,
    serviceID,
    amount,
    phone,
    billersCode
  };
  await postToVtpass('/pay', data, res, userId, amount, 'Airtime Purchase');
};

exports.validateSmartcard = async (req, res) => {
  const { serviceID, smartcard_number } = req.body;
  const data = {
    serviceID,
    smartcard_number,
    billersCode: smartcard_number
  };
  // Note: This is a validation endpoint and does not involve a transaction
  // Therefore, we use the original postToVtpass logic without wallet/transaction handling.
  // This is a simple request, so we will use a simplified version of the function
  // to avoid unnecessary logic.
  try {
    const response = await axios.post(`${VTPASS_BASE_URL}/merchant-verify`, data, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${VTPASS_API_KEY}:${VTPASS_SECRET_KEY}`).toString('base64')}`
      }
    });
    res.status(response.status).json({
      success: true,
      data: response.data
    });
  } catch (error) {
    // 💡 BEGIN DEBUGGING LOGS 💡
    console.error('🚨 Error validating smartcard:', error.message);
    if (error.response) {
      console.error('Raw API Response Status:', error.response.status);
      console.error('Raw API Response Data:', error.response.data);
    } else {
      console.error('No response received from API:', error.request);
    }
    // 💡 END DEBUGGING LOGS 💡
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.response_description || 'An unknown error occurred with the VTpass API.';
    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      errorDetails: error.response?.data || { message: error.message }
    });
  }
};

exports.purchaseData = async (req, res) => {
  const userId = req.userId;
  const { serviceID, amount, phone, variation_code } = req.body;
  const request_id = uuidv4();
  const data = {
    request_id,
    serviceID,
    amount,
    phone,
    variation_code
  };
  await postToVtpass('/pay', data, res, userId, amount, 'Data Purchase');
};

exports.purchaseElectricity = async (req, res) => {
  const userId = req.userId;
  const { serviceID, amount, phone, billersCode, variation_code } = req.body;
  const request_id = uuidv4();
  const data = {
    request_id,
    serviceID,
    amount,
    phone,
    billersCode,
    variation_code
  };
  await postToVtpass('/pay', data, res, userId, amount, 'Electricity Purchase');
};

exports.purchaseTvSubscription = async (req, res) => {
  const userId = req.userId;
  const { serviceID, amount, phone, billersCode, variation_code, subscription_type } = req.body;
  const request_id = uuidv4();
  const data = {
    request_id,
    serviceID,
    amount,
    phone,
    billersCode,
    variation_code,
    subscription_type
  };
  await postToVtpass('/pay', data, res, userId, amount, 'TV Subscription');
};

exports.getServices = async (req, res) => {
  const { serviceID } = req.body;
  const data = { serviceID };
  // No transaction involved, so we use a simplified post request
  await postToVtpass('/services', data, res, null, 0, null);
};

exports.getVariations = async (req, res) => {
  const { serviceID } = req.body;
  const data = { serviceID };
  // No transaction involved, so we use a simplified post request
  await postToVtpass('/variations', data, res, null, 0, null);
};

exports.revalidateTransaction = async (req, res) => {
  const { request_id } = req.body;
  const data = { request_id };
  // No new transaction, just a revalidation
  await postToVtpass('/re-validate', data, res, null, 0, null);
};
