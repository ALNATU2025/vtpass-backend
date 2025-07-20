// routes/cabletvRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/userModel');
const CableTVTransaction = require('../models/CableTVTransaction.js');
const axios = require("axios");

router.post('/pay', async (req, res) => {
  try {
    const { userId, serviceID, smartCardNumber, selectedPackage, amount, selectedCable } = req.body;

    if (!userId || !smartCardNumber || !amount || !selectedPackage || !serviceID || !selectedCable) {
      return res.status(400).json({
        success: false,
        message: 'All fields (userId, smartCardNumber, amount, selectedPackage, serviceID, selectedCable) are required'
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount format' });
    }

    if (user.walletBalance < numericAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    if (!process.env.VTPASS_EMAIL || !process.env.VTPASS_PASSWORD || !process.env.VTPASS_API_KEY || !process.env.VTPASS_BASE_URL) {
      console.error("❌ VTpass environment variables (EMAIL, PASSWORD, API_KEY, BASE_URL) are not set!");
      return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing.' });
    }

    // FIX: Use VTPASS_EMAIL and VTPASS_PASSWORD for Basic Authentication
    const VTpassBasicAuth = Buffer.from(
      `${process.env.VTPASS_EMAIL}:${process.env.VTPASS_PASSWORD}`
    ).toString("base64");

    const requestId = `CABLE_${user._id}_${Date.now()}`;

    console.log("📡 Making cable payment with VTpass...");
    console.log("➡️ Body Sent to VTpass:", {
      serviceID,
      billersCode: smartCardNumber,
      variation_code: selectedPackage,
      amount: numericAmount,
      phone: user.phone,
      request_id: requestId,
    });

    // --- START DEBUGGING LOGS ---
    console.log("🔍 Debugging VTpass Request Headers:");
    console.log("   VTPASS_EMAIL (from env):", process.env.VTPASS_EMAIL);
    console.log("   VTPASS_PASSWORD (from env, masked):", process.env.VTPASS_PASSWORD ? '********' : 'N/A'); // Mask password in logs
    console.log("   VTPASS_API_KEY (from env, masked):", process.env.VTPASS_API_KEY ? process.env.VTPASS_API_KEY.substring(0, 5) + '...' + process.env.VTPASS_API_KEY.substring(process.env.VTPASS_API_KEY.length - 5) : 'N/A');
    console.log("   VTPASS_BASE_URL (from env):", process.env.VTPASS_BASE_URL);
    console.log("   Authorization Header (Basic):", `Basic ${VTpassBasicAuth}`);
    // --- END DEBUGGING LOGS ---

    const vtpassResponse = await axios.post(
      `${process.env.VTPASS_BASE_URL}/pay`,
      {
        serviceID,
        billersCode: smartCardNumber,
        variation_code: selectedPackage,
        amount: numericAmount,
        phone: user.phone,
        request_id: requestId,
      },
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "Authorization": `Basic ${VTpassBasicAuth}`, // FIX: Use Basic Auth with email:password
          "Content-Type": "application/json",
        },
      }
    );

    console.log("✅ VTpass payment response:", vtpassResponse.data);

    if (vtpassResponse.data && vtpassResponse.data.code === '000') {
      user.walletBalance -= numericAmount;
      await user.save();

      const newTransaction = new CableTVTransaction({
        userId: user._id,
        serviceType: serviceID,
        smartCardNumber,
        packageName: selectedPackage,
        amount: numericAmount,
        status: 'success',
        transactionId: vtpassResponse.data.content.transactions.transactionId || requestId,
      });

      await newTransaction.save();

      res.status(200).json({
        success: true,
        message: 'Payment successful',
        newBalance: user.walletBalance,
        transactionId: newTransaction.transactionId,
        transactionDetails: newTransaction,
      });
    } else {
      const errorMessage = vtpassResponse.data.response_description || vtpassResponse.data.message || 'VTpass payment failed.';
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: vtpassResponse.data
      });
    }

  } catch (err) {
    console.error('❌ CableTV Payment Error:', err.response?.data || err.message);
    res.status(500).json({
      success: false,
      message: 'Server error during cable TV payment.',
      details: err.response?.data || err.message
    });
  }
});

module.exports = router;
