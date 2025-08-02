const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

// Validate smartcard (GET)
// Full Endpoint: /api/validate-smartcard
router.get('/validate-smartcard', vtpassController.validateSmartCard);

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
