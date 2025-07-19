// routes/vtpassRoutes.js
const express = require("express");
const router = express.Router();
const axios = require("axios");

// POST /api/validate-smartcard
router.post("/validate-smartcard", async (req, res) => {
  const { billersCode, serviceID } = req.body;

  // Basic validation for request body
  if (!billersCode || !serviceID) {
    return res.status(400).json({ success: false, message: 'billersCode and serviceID are required.' });
  }

  // Ensure environment variables are set
  if (!process.env.VTPASS_EMAIL || !process.env.VTPASS_API_KEY || !process.env.VTPASS_BASE_URL) {
    console.error("❌ VTpass environment variables are not set!");
    return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing.' });
  }

  const VTpassAuth = Buffer.from(
    `${process.env.VTPASS_EMAIL}:${process.env.VTPASS_API_KEY}`
  ).toString("base64");

  console.log("📡 Validating smartcard with VTpass...");
  console.log("➡️ Body Sent to VTpass:", { billersCode, serviceID });

  try {
    const response = await axios.post(
      `${process.env.VTPASS_BASE_URL}/merchant-verify`,
      {
        billersCode,
        serviceID,
      },
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "Authorization": `Basic ${VTpassAuth}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("✅ VTpass raw response:", response.data);

    // Parse VTpass response and send a consistent format to Flutter
    if (response.data && response.data.response_description === "VALID" && response.data.content) {
      return res.json({
        success: true,
        customerName: response.data.content.Customer_Name,
        message: response.data.response_description,
        details: response.data.content // Optionally send more details if needed by frontend
      });
    } else {
      // Handle cases where VTpass returns an invalid or unsuccessful response
      return res.status(400).json({
        success: false,
        message: response.data.response_description || "Smartcard validation failed.",
        details: response.data // Send full VTpass response for debugging
      });
    }
  } catch (error) {
    console.error("❌ VTpass Error during validation:", error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: "Validation failed due to server error.",
      details: error.response?.data || error.message, // Provide error details for debugging
    });
  }
});

module.exports = router;