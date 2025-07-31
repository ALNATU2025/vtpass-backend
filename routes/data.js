// routes/data.js

const express = require('express');
const router = express.Router();
const dataController = require('../controllers/dataController');

// POST /api/data/purchase
router.post('/purchase', dataController.buyData);

module.exports = router;
