// routes/vtpassRoutes.js
const express = require("express");
const router = express.Router();
const axios = require("axios");

// POST /api/validate-smartcard
router.post("/validate-smartcard", async (req, res) => {
  const { billersCode, serviceID } = req.body;

  if (!billersCode || !serviceID) {
    return res.status(400).json({ success: false, message: 'billersCode and serviceID are required.' });
  }

  // Ensure environment variables are set
  if (!process.env.VTPASS_API_KEY || !process.env.VTPASS_SECRET_KEY || !process.env.VTPASS_BASE_URL) {
    console.error("❌ VTpass environment variables (API_KEY, SECRET_KEY, BASE_URL) are not set!");
    return res.status(500).json({ success: false, message: 'Server configuration error: VTpass credentials missing.' });
  }

  console.log("📡 Validating smartcard with VTpass...");
  console.log("➡️ Body Sent to VTpass:", { billersCode, serviceID });

  // --- START DEBUGGING LOGS ---
  console.log("🔍 Debugging VTpass Request Headers:");
  console.log("   VTPASS_EMAIL (from env):", process.env.VTPASS_EMAIL); // Still log email for context
  console.log("   VTPASS_API_KEY (from env, masked):", process.env.VTPASS_API_KEY ? process.env.VTPASS_API_KEY.substring(0, 5) + '...' + process.env.VTPASS_API_KEY.substring(process.env.VTPASS_API_KEY.length - 5) : 'N/A');
  console.log("   VTPASS_SECRET_KEY (from env, masked):", process.env.VTPASS_SECRET_KEY ? process.env.VTPASS_SECRET_KEY.substring(0, 5) + '...' + process.env.VTPASS_SECRET_KEY.substring(process.env.VTPASS_SECRET_KEY.length - 5) : 'N/A');
  console.log("   VTPASS_BASE_URL (from env):", process.env.VTPASS_BASE_URL);
  // --- END DEBUGGING LOGS ---

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
          "secret-key": process.env.VTPASS_SECRET_KEY,
          "Content-Type": "application/json",
        },
      }
    );

    console.log("✅ VTpass raw response for validation:", response.data); // Log the full VTpass response

    // CORRECTED: Check for 'success: true' directly from VTpass's response for validation
    if (response.data && response.data.success === true && response.data.details && response.data.details.Customer_Name) {
      return res.json({
        success: true, // This will now correctly be true
        customerName: response.data.customerName, // Use customerName from VTpass response
        message: response.data.message || "Smartcard validated successfully.", // Use message from VTpass response
        details: response.data.details // Pass the full details object
      });
    } else {
      const errorMessage = response.data.message || response.data.response_description || response.data.content?.error || "Smartcard validation failed.";
      return res.status(400).json({
        success: false,
        message: errorMessage,
        details: response.data // Still pass the full VTpass response for debugging
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

module.exports = router;
