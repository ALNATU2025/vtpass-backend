// utils/vtpass.js

/**
 * Maps Flutter network names to VTpass service IDs.
 * @param {string} network - The network name from the Flutter app (e.g., 'MTN', 'Airtel').
 * @param {'airtime' | 'data'} type - The type of service ('airtime' or 'data').
 * @returns {string} The corresponding VTpass service ID.
 * @throws {Error} If the network is unsupported.
 */
const getVtpassServiceId = (network, type) => {
    const networkMap = {
        'MTN': 'mtn',
        'Airtel': 'airtel',
        'Glo': 'glo',
        '9mobile': '9mobile'
    };
    const serviceId = networkMap[network];
    if (!serviceId) {
        throw new Error(`Unsupported network: ${network}`);
    }
    return type === 'airtime' ? serviceId : `${serviceId}-data`;
};

module.exports = {
    getVtpassServiceId
};
