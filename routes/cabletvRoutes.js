const express = require('express');
const router = express.Router();
const { payCableTV } = require('../controllers/cabletvController');

router.post('/pay', payCableTV);

module.exports = router;
