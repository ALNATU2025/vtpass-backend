// routes/cabletvRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/userModel'); // Ensure this imports the consolidated User model
const CableTVTransaction = require('../models/cableTVTransaction'); // Import the specific CableTVTransaction model
const axios = require("axios"); // For making actual VTpass payment API call

router.post('/pay', async (req, res) => {
  try {
    // Changed email to userId for user lookup
    // Changed serviceType to serviceID for consistency with VTpass
    const { userId, serviceID, smartCardNumber, selectedPackage, amount, selectedCable } = req.body;

    // Validate fields
    if (!userId || !smartCardNumber || !amount || !selectedPackage || !serviceID || !selectedCable) {
      return res.status(400).json({
        success: false, // Consistent success/failure flag
        message: 'All fields (userId, smartCardNumber, amount, selectedPackage, serviceID, selectedCable) are required'
      });
    }

    // Find user by userId (more robust than email for authenticated actions)
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

    // --- Integrate with VTpass for actual payment ---
    // Ensure environment variables are set
    if (!process.env.VTPASS_EMAIL || !process.env.VTPASS_API_KEY || !process.env.VTPASS_BASE_URL) {
      console.error("❌ VTpass environment variables are not set!");
      return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing.' });
    }

    const VTpassAuth = Buffer.from(
      `${process.env.VTPASS_EMAIL}:${process.env.VTPASS_API_KEY}`
    ).toString("base64");

    // Generate a unique request ID for VTpass (important for idempotency)
    const requestId = `CABLE_${user._id}_${Date.now()}`;

    console.log("📡 Making cable payment with VTpass...");
    console.log("➡️ Body Sent to VTpass:", {
      serviceID,
      billersCode: smartCardNumber,
      variation_code: selectedPackage, // VTpass often uses 'variation_code' for packages
      amount: numericAmount,
      phone: user.phone, // Assuming user has a phone number
      request_id: requestId,
    });

    const vtpassResponse = await axios.post(
      `${process.env.VTPASS_BASE_URL}/pay`, // VTpass payment endpoint
      {
        serviceID,
        billersCode: smartCardNumber,
        variation_code: selectedPackage, // Use VTpass specific parameter name
        amount: numericAmount,
        phone: user.phone, // Assuming user has a phone number stored
        request_id: requestId, // Unique request ID
      },
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "Authorization": `Basic ${VTpassAuth}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("✅ VTpass payment response:", vtpassResponse.data);

    // Check VTpass response status
    if (vtpassResponse.data && vtpassResponse.data.code === '000') {
      // Payment successful on VTpass side
      // Deduct amount from user's wallet
      user.walletBalance -= numericAmount;
      await user.save();

      // Save transaction using the dedicated CableTVTransaction model
      const newTransaction = new CableTVTransaction({
        userId: user._id,
        serviceType: serviceID, // Store the service ID (e.g., 'dstv')
        smartCardNumber,
        packageName: selectedPackage, // Store the package name
        amount: numericAmount,
        status: 'success',
        transactionId: vtpassResponse.data.content.transactions.transactionId || requestId, // Use VTpass transaction ID or fallback
      });

      await newTransaction.save();

      res.status(200).json({
        success: true,
        message: 'Payment successful',
        newBalance: user.walletBalance, // Return newBalance for Flutter
        transactionId: newTransaction.transactionId, // Return the saved transaction ID
        transactionDetails: newTransaction, // Optionally return full transaction object
      });
    } else {
      // VTpass payment failed or returned an error code
      const errorMessage = vtpassResponse.data.response_description || vtpassResponse.data.message || 'VTpass payment failed.';
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: vtpassResponse.data // For debugging purposes
      });
    }

  } catch (err) {
    console.error('❌ CableTV Payment Error:', err.response?.data || err.message);
    res.status(500).json({
      success: false,
      message: 'Server error during cable TV payment.',
      details: err.response?.data || err.message // Provide error details
    });
  }
});

module.exports = router;
