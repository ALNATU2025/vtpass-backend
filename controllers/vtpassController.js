const axios = require('axios');
const Wallet = require('../models/Wallet');
const Transaction = require('../models/Transaction');
const User = require('../models/User');

const API_BASE_URL = process.env.VTPASS_BASE_URL;
const VTPASS_AUTH = process.env.VTPASS_AUTH;
const headers = {
  'Authorization': `Basic ${VTPASS_AUTH}`,
  'Content-Type': 'application/json'
};

/**
 * Handles the purchase of airtime.
 * Checks for required arguments and user wallet balance before proceeding.
 * It now returns more specific error messages for easier debugging.
 */
exports.purchaseAirtime = async (req, res, next) => {
  try {
    const { phone, amount, serviceID, request_id } = req.body;
    const userId = req.user._id;

    // --- Start: More Specific Validation Checks ---
    if (!phone) {
      return res.status(400).json({ success: false, message: "Missing 'phone' in request body" });
    }
    if (!amount) {
      return res.status(400).json({ success: false, message: "Missing 'amount' in request body" });
    }
    if (!serviceID) {
      return res.status(400).json({ success: false, message: "Missing 'serviceID' in request body" });
    }
    if (!request_id) {
      return res.status(400).json({ success: false, message: "Missing 'request_id' in request body" });
    }
    // --- End: More Specific Validation Checks ---

    const user = await User.findById(userId);
    const wallet = await Wallet.findOne({ user: userId });

    if (!user || !wallet) {
      return res.status(404).json({ success: false, message: 'User or Wallet not found' });
    }

    if (wallet.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient wallet balance' });
    }

    // Prepare the request payload for VTpass
    const payload = {
      serviceID,
      amount,
      phone,
      request_id
    };

    // Make the API call to VTpass
    const response = await axios.post(`${API_BASE_URL}/pay`, payload, { headers });

    if (response.data.code === '000') {
      // Update the user's wallet
      wallet.balance -= amount;
      await wallet.save();

      // Create a new transaction record
      const transaction = new Transaction({
        user: userId,
        type: 'airtime_purchase',
        amount: amount,
        status: 'completed',
        description: `Airtime purchase for ${phone}`,
        provider: serviceID,
        provider_reference: response.data.response_id,
        balance_after: wallet.balance
      });
      await transaction.save();

      res.status(200).json({
        success: true,
        message: 'Airtime purchase successful',
        transaction: transaction
      });
    } else {
      res.status(400).json({ success: false, message: response.data.response_description, details: response.data });
    }
  } catch (error) {
    next(error);
  }
};

/**
 * Handles the purchase of data.
 * The validation and logic are similar to the airtime purchase function.
 */
exports.purchaseData = async (req, res, next) => {
  try {
    const { serviceID, phone, amount, request_id, variation_code } = req.body;
    const userId = req.user._id;

    // --- Start: More Specific Validation Checks ---
    if (!phone) {
      return res.status(400).json({ success: false, message: "Missing 'phone' in request body" });
    }
    if (!amount) {
      return res.status(400).json({ success: false, message: "Missing 'amount' in request body" });
    }
    if (!serviceID) {
      return res.status(400).json({ success: false, message: "Missing 'serviceID' in request body" });
    }
    if (!request_id) {
      return res.status(400).json({ success: false, message: "Missing 'request_id' in request body" });
    }
    if (!variation_code) {
      return res.status(400).json({ success: false, message: "Missing 'variation_code' in request body" });
    }
    // --- End: More Specific Validation Checks ---

    const user = await User.findById(userId);
    const wallet = await Wallet.findOne({ user: userId });

    if (!user || !wallet) {
      return res.status(404).json({ success: false, message: 'User or Wallet not found' });
    }

    if (wallet.balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient wallet balance' });
    }

    const payload = {
      serviceID,
      variation_code,
      amount,
      phone,
      request_id
    };

    const response = await axios.post(`${API_BASE_URL}/pay`, payload, { headers });

    if (response.data.code === '000') {
      wallet.balance -= amount;
      await wallet.save();

      const transaction = new Transaction({
        user: userId,
        type: 'data_purchase',
        amount: amount,
        status: 'completed',
        description: `Data purchase for ${phone}`,
        provider: serviceID,
        provider_reference: response.data.response_id,
        balance_after: wallet.balance
      });
      await transaction.save();

      res.status(200).json({
        success: true,
        message: 'Data purchase successful',
        transaction: transaction
      });
    } else {
      res.status(400).json({ success: false, message: response.data.response_description, details: response.data });
    }
  } catch (error) {
    next(error);
  }
};
