const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

// Purchases
router.post('/airtime/purchase', vtpassController.buyAirtime);
router.post('/data/purchase', vtpassController.buyData);
router.post('/cabletv/purchase', vtpassController.buyCableTV);

// Validate Smartcard
router.get('/cabletv/validate-smartcard', vtpassController.validateSmartCard);

module.exports = router;
