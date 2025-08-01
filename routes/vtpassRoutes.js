const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

// Validate smartcard (GET)
router.get('/validate-smartcard', vtpassController.validateSmartCard);

// Airtime
router.post('/buy-airtime', vtpassController.buyAirtime);

// Data
router.post('/buy-data', vtpassController.buyData);

// CableTV
router.post('/buy-cabletv', vtpassController.buyCableTV);

module.exports = router;
