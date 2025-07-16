const express = require("express");
const router = express.Router();
const axios = require("axios");

// POST /api/validate-smartcard
router.post("/validate-smartcard", async (req, res) => {
  const { billersCode, serviceID } = req.body;

  const VTpassAuth = Buffer.from(
    `${process.env.VTPASS_EMAIL}:${process.env.VTPASS_API_KEY}`
  ).toString("base64");

  try {
    const response = await axios.post(
      "https://sandbox.vtpass.com/api/merchant-verify",
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

    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: "Validation failed", details: error.message });
  }
});

module.exports = router;
