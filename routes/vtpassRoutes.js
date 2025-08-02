// vtpassRoutes.js
const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');


// Define API endpoints for VTpass services
// The '/api' prefix is handled by the main router in index.js,
// so we only need to define the 'vtpass' sub-path here.
router.post('/vtpass/airtime/purchase', vtpassController.purchaseAirtime);
router.post('/vtpass/validate-smartcard', vtpassController.validateSmartcard);
router.post('/vtpass/data/purchase', vtpassController.purchaseData);
router.post('/vtpass/electricity/purchase', vtpassController.purchaseElectricity);
router.post('/vtpass/tv/purchase', vtpassController.purchaseTvSubscription);
router.post('/vtpass/services', vtpassController.getServices);
router.post('/vtpass/variations', vtpassController.getVariations);
router.post('/vtpass/re-validate', vtpassController.revalidateTransaction);

module.exports = router;
