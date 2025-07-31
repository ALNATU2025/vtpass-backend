// routes/vtpassRoutes.js
const express = require("express");
const router = express.Router();
const axios = require("axios");
const crypto = require('crypto');
const moment = require('moment-timezone');

// --- Helper Function to Generate a Unique Request ID ---
// The VTpass API requires a unique request_id for every transaction.
// The format must be YYYYMMDDHHII followed by at least 4 alphanumeric characters.
// We'll use a combination of the current date/time and a random string.
function generateRequestId() {
  const datePart = moment().tz('Africa/Lagos').format('YYYYMMDDHHmm');
  const randomPart = crypto.randomBytes(4).toString('hex');
  return `${datePart}${randomPart}`;
}

// Helper function to check for VTpass environment variables
function checkEnvVariables(res) {
  if (!process.env.VTPASS_API_KEY || !process.env.VTPASS_SECRET_KEY || !process.env.VTPASS_BASE_URL) {
    const message = "Server configuration error: VTpass credentials missing.";
    console.error(`❌ ${message}`);
    res.status(500).json({ success: false, message });
    return false;
  }
  return true;
}

// POST /api/validate-smartcard (Your original route)
router.post("/validate-smartcard", async (req, res) => {
  if (!checkEnvVariables(res)) return;

  const { billersCode, serviceID } = req.body;

  if (!billersCode || !serviceID) {
    return res.status(400).json({ success: false, message: 'billersCode and serviceID are required.' });
  }

  console.log("📡 Validating smartcard with VTpass...");
  console.log("➡️ Body Sent to VTpass:", { billersCode, serviceID });

  try {
    const response = await axios.post(
      `${process.env.VTPASS_BASE_URL}/merchant-verify`,
      { billersCode, serviceID },
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "secret-key": process.env.VTPASS_SECRET_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("✅ VTpass raw response for validation:", response.data);

    if (response.data && response.data.code === '000' && response.data.content && response.data.content.Customer_Name) {
      return res.json({
        success: true,
        customerName: response.data.content.Customer_Name,
        message: response.data.message || "Smartcard validated successfully.",
        details: response.data.content
      });
    } else {
      const errorMessage = response.data.message || response.data.response_description || response.data.content?.error || "Smartcard validation failed.";
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: response.data
      });
    }
  } catch (error) {
    console.error("❌ VTpass Error during validation:", error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: "Server error during validation.",
      details: error.response?.data || error.message,
    });
  }
});

// POST /api/purchase/airtime (New route for airtime)
router.post("/purchase/airtime", async (req, res) => {
  if (!checkEnvVariables(res)) return;

  const { serviceID, phone, amount } = req.body;
  const request_id = generateRequestId();

  if (!serviceID || !phone || !amount) {
    return res.status(400).json({ success: false, message: 'serviceID, phone, and amount are required.' });
  }

  console.log("📡 Purchasing airtime with VTpass...");
  console.log("➡️ Body Sent to VTpass:", { serviceID, phone, amount, request_id });

  try {
    const response = await axios.post(
      `${process.env.VTPASS_BASE_URL}/pay`,
      { serviceID, phone, amount, request_id },
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "secret-key": process.env.VTPASS_SECRET_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    console.log(`✅ VTpass raw response for airtime purchase (request_id: ${request_id}):`, response.data);

    if (response.data && response.data.code === '000') {
      return res.json({
        success: true,
        message: response.data.message || "Airtime purchase successful.",
        details: response.data
      });
    } else {
      const errorMessage = response.data.message || response.data.response_description || response.data.content?.error || "Airtime purchase failed.";
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: response.data
      });
    }
  } catch (error) {
    console.error(`❌ VTpass Error during airtime purchase (request_id: ${request_id}):`, error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: "Server error during airtime purchase.",
      details: error.response?.data || error.message,
    });
  }
});

// POST /api/purchase/data (New route for data)
router.post("/purchase/data", async (req, res) => {
  if (!checkEnvVariables(res)) return;

  const { serviceID, variation_code, phone } = req.body;
  const request_id = generateRequestId();

  if (!serviceID || !variation_code || !phone) {
    return res.status(400).json({ success: false, message: 'serviceID, variation_code, and phone are required.' });
  }

  console.log("📡 Purchasing data with VTpass...");
  console.log("➡️ Body Sent to VTpass:", { serviceID, variation_code, phone, request_id });

  try {
    const response = await axios.post(
      `${process.env.VTPASS_BASE_URL}/pay`,
      { serviceID, variation_code, phone, request_id },
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "secret-key": process.env.VTPASS_SECRET_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    console.log(`✅ VTpass raw response for data purchase (request_id: ${request_id}):`, response.data);

    if (response.data && response.data.code === '000') {
      return res.json({
        success: true,
        message: response.data.message || "Data purchase successful.",
        details: response.data
      });
    } else {
      const errorMessage = response.data.message || response.data.response_description || response.data.content?.error || "Data purchase failed.";
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: response.data
      });
    }
  } catch (error) {
    console.error(`❌ VTpass Error during data purchase (request_id: ${request_id}):`, error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: "Server error during data purchase.",
      details: error.response?.data || error.message,
    });
  }
});

module.exports = router;
