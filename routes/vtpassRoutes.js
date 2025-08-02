// vtpassRoutes.js
const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');


// Define API endpoints for VTpass services
router.post('/api/vtpass/airtime/purchase', vtpassController.purchaseAirtime);
router.post('/api/vtpass/validate-smartcard', vtpassController.validateSmartcard);
router.post('/api/vtpass/data/purchase', vtpassController.purchaseData);
router.post('/api/vtpass/electricity/purchase', vtpassController.purchaseElectricity);
router.post('/api/vtpass/tv/purchase', vtpassController.purchaseTvSubscription);
router.post('/api/vtpass/services', vtpassController.getServices);
router.post('/api/vtpass/variations', vtpassController.getVariations);
router.post('/api/vtpass/re-validate', vtpassController.revalidateTransaction);

module.exports = router;