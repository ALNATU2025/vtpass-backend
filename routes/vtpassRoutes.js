const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

router.get('/validate-smartcard', vtpassController.validateSmartCard);


router.post('/airtime/purchase', vtpassController.buyAirtime);


router.post('/data/purchase', vtpassController.buyData);

router.post('/cabletv/buy-cabletv', vtpassController.buyCableTV);

module.exports = router;
