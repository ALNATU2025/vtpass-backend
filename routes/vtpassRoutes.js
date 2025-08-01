// routes/vtpassRoutes.js

const express = require('express');
const router = express.Router();
const vtpassController = require('../controllers/vtpassController');

// All VTpass purchase routes now point to the consolidated controller
router.post('/airtime/purchase', vtpassController.buyAirtime);
router.post('/data/purchase', vtpassController.buyData);
router.post('/cabletv/purchase', vtpassController.buyCableTV);

// Helper function to map user-friendly names to VTpass service IDs
// This is a good place to define this mapping.
// You can also create a separate file for this utility.
const getVtpassServiceId = (network, type) => {
    const serviceMap = {
        'airtime': {
            'MTN': 'mtn',
            'Glo': 'glo',
            'Airtel': 'airtel',
            '9mobile': '9mobile',
        },
        'data': {
            'MTN': 'mtn-data',
            'Glo': 'glo-data',
            'Airtel': 'airtel-data',
            '9mobile': '9mobile-data',
        },
        'cabletv': {
            'DSTV': 'dstv',
            'GOTV': 'gotv',
            'Startimes': 'startimes',
        }
    };

    const serviceID = serviceMap[type]?.[network];
    if (!serviceID) {
        throw new Error(`Invalid service: ${network} for type: ${type}`);
    }
    return serviceID;
};

module.exports = router;