const express = require("express");
const router = express.Router();
const axios = require("axios");

// POST /api/validate-smartcard
router.post("/validate-smartcard", async (req, res) => {
  const { billersCode, serviceID } = req.body;

  const VTpassAuth = Buffer.from(
  `${process.env.VTPASS_EMAIL}:${process.env.VTPASS_PASSWORD}`
).toString("base64");


  console.log("📡 Validating smartcard...");
console.log("➡️ Email:", process.env.VTPASS_EMAIL);
console.log("➡️ Password (from .env):", process.env.VTPASS_PASSWORD);
console.log("➡️ Base64 Auth:", VTpassAuth);
console.log("➡️ Body Sent:", { billersCode, serviceID });

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

    console.log("✅ VTpass response:", response.data);
    res.json(response.data);
  } catch (error) {
    console.error("❌ VTpass Error:", error.response?.data || error.message);
    res.status(500).json({
      error: "Validation failed",
      details: error.response?.data || error.message,
    });
  }
});

module.exports = router;
