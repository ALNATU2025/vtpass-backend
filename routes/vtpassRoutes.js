const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

// ====================================================================
// ✅ CORRECTED ROUTE: Smartcard Validation
// ⚠️ CRITICAL FIX: Changed from a GET to a POST route.
// The controller now uses a POST request to send data to the VTpass API.
// ====================================================================
// Full Endpoint: /api/validate-smartcard
router.post('/validate-smartcard', vtpassController.validateSmartCard);

// ====================================================================
// ✅ VTPASS SERVICE PURCHASE ROUTES
// These routes and their methods are correct and do not need to be changed.
// ====================================================================

// Airtime Purchase
// Full Endpoint: /api/airtime/purchase
router.post('/airtime/purchase', vtpassController.buyAirtime);

// Data Purchase
// Full Endpoint: /api/data/purchase
router.post('/data/purchase', vtpassController.buyData);

// CableTV Purchase
// Full Endpoint: /api/cabletv/buy-cabletv
router.post('/cabletv/buy-cabletv', vtpassController.buyCableTV);

module.exports = router;
