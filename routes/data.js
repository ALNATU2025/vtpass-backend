const express = require('express');
const router = express.Router();
const axios = require('axios');

// GET /api/data-plans - Get data plans for a specific network
router.get('/data-plans', async (req, res) => {
  try {
    const { serviceID } = req.query;
    
    if (!serviceID) {
      return res.status(400).json({
        success: false,
        message: 'Service ID is required'
      });
    }

    // Validate service ID format
    const validServiceIDs = [
      'mtn-data', 'airtel-data', 'glo-data', 
      'glo-sme-data', 'etisalat-data'
    ];
    
    if (!validServiceIDs.includes(serviceID)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid service ID'
      });
    }

    // VTpass API configuration
    const vtpassConfig = {
      baseURL: 'https://vtpass.com/api',
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.VTPASS_API_KEY, // Your live API key
        'secret-key': process.env.VTPASS_SECRET_KEY, // Your live secret key
      }
    };

    console.log(`📡 Fetching data plans for service: ${serviceID}`);

    // Make request to VTpass API
    const response = await axios.get(
      `/service-variations?serviceID=${serviceID}`,
      vtpassConfig
    );

    const vtpassData = response.data;

    console.log(`✅ Received VTpass response for ${serviceID}`);

    // Check if VTpass API returned success
    if (vtpassData.response_description !== '000') {
      return res.status(400).json({
        success: false,
        message: vtpassData.response_description || 'Failed to fetch data plans from VTpass'
      });
    }

    // Process the variations (handle both 'variations' and 'varations' fields)
    const variations = vtpassData.content.variations || vtpassData.content.varations || [];
    
    if (!variations || variations.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No data plans available for this network'
      });
    }

    // Transform the data into a consistent format
    const processedPlans = variations.map(plan => {
      // Extract validity from name (e.g., "1.5GB Weekly Plan (7 Days)" -> "7 Days")
      let validity = '30 days'; // default
      const name = plan.name || '';
      
      // Extract validity from parentheses
      const validityMatch = name.match(/\(([^)]+)\)/);
      if (validityMatch) {
        validity = validityMatch[1];
      } else {
        // Fallback: determine validity from name patterns
        if (name.toLowerCase().includes('daily') || name.toLowerCase().includes('1 day')) {
          validity = '1 day';
        } else if (name.toLowerCase().includes('weekly') || name.toLowerCase().includes('7 days')) {
          validity = '7 days';
        } else if (name.toLowerCase().includes('monthly') || name.toLowerCase().includes('30 days')) {
          validity = '30 days';
        } else if (name.toLowerCase().includes('2-month') || name.toLowerCase().includes('60 days')) {
          validity = '60 days';
        } else if (name.toLowerCase().includes('3-month') || name.toLowerCase().includes('90 days')) {
          validity = '90 days';
        }
      }

      return {
        name: plan.name || 'Unknown Plan',
        amount: plan.variation_amount || '0',
        validity: validity,
        variation_code: plan.variation_code || '',
        serviceID: serviceID,
        fixedPrice: plan.fixedPrice === 'Yes'
      };
    });

    // Sort plans by amount (lowest to highest)
    processedPlans.sort((a, b) => parseFloat(a.amount) - parseFloat(b.amount));

    console.log(`✅ Processed ${processedPlans.length} plans for ${serviceID}`);

    res.json({
      success: true,
      service: vtpassData.content.ServiceName || serviceID,
      serviceID: serviceID,
      plans: processedPlans,
      totalPlans: processedPlans.length,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Error fetching data plans:', error.response?.data || error.message);

    let errorMessage = 'Failed to fetch data plans';
    let statusCode = 500;

    if (error.response) {
      // VTpass API error
      statusCode = error.response.status;
      errorMessage = error.response.data?.response_description || 'VTpass API error';
    } else if (error.request) {
      // Network error
      errorMessage = 'Network error: Could not connect to VTpass';
    }

    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      error: error.message,
      serviceID: req.query.serviceID
    });
  }
});

// GET /api/data-plans/all - Get all available data plans
router.get('/data-plans/all', async (req, res) => {
  try {
    const networks = [
      { name: 'MTN', serviceID: 'mtn-data' },
      { name: 'Airtel', serviceID: 'airtel-data' },
      { name: 'Glo', serviceID: 'glo-data' },
      { name: '9mobile', serviceID: 'etisalat-data' }
    ];

    const allPlans = {};
    
    // Fetch plans for all networks in parallel
    const planPromises = networks.map(async (network) => {
      try {
        const response = await axios.get(
          `http://localhost:${process.env.PORT || 3000}/api/data-plans?serviceID=${network.serviceID}`
        );
        return {
          network: network.name,
          serviceID: network.serviceID,
          plans: response.data.success ? response.data.plans : [],
          success: response.data.success
        };
      } catch (error) {
        console.error(`Error fetching ${network.name} plans:`, error.message);
        return {
          network: network.name,
          serviceID: network.serviceID,
          plans: [],
          success: false,
          error: error.message
        };
      }
    });

    const results = await Promise.all(planPromises);
    
    // Organize by network
    results.forEach(result => {
      allPlans[result.network] = result.plans;
    });

    res.json({
      success: true,
      networks: networks.map(n => n.name),
      plans: allPlans,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error fetching all data plans:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch all data plans',
      error: error.message
    });
  }
});

module.exports = router;
