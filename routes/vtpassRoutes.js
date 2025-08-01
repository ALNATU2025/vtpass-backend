// routes/vtpassRoutes.js

const express = require('express');
const router = express.Router();
const {
  validateSmartCard,
  buyAirtime,
  buyData,
  buyCableTV,
} = require('../controllers/vtpassController');

// Smartcard validation (GET)
router.get('/cabletv/validate-smartcard', validateSmartCard);

// Purchase services (POST)
router.post('/airtime', buyAirtime);
router.post('/data', buyData);
router.post('/cabletv', buyCableTV);

module.exports = router;
