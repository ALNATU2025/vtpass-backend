// routes/airtime.js

const express = require('express');
const router = express.Router();
const airtimeController = require('../controllers/airtimeController');

// POST /api/airtime/purchase
router.post('/purchase', airtimeController.buyAirtime);

module.exports = router;
