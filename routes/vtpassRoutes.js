const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

// Purchases
router.post('/airtime/purchase', vtpassController.buyAirtime);
router.post('/data/purchase', vtpassController.buyData);
router.post('/cabletv/purchase', vtpassController.buyCableTV);
router.post('/cabletv/validate-smartcard', vtpassController.validateSmartCard);

// Validate Smartcard
router.get('/cabletv/validate-smartcard', vtpassController.validateSmartCard);
router.post('/cabletv/validate-smartcard', vtpassController.validateSmartCard);

module.exports = router;
