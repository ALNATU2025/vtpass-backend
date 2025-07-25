// routes/appSettingsRoutes.js
const express = require('express');
const router = express.Router();
const AppSettings = require('../models/AppSettings'); // Import the new AppSettings model

// Middleware for authentication and authorization (assuming you have one)
// Example: const auth = require('../middleware/auth');
// Example: const authorizeAdmin = require('../middleware/authorizeAdmin');

// GET /api/settings - Get current application settings
// This endpoint should ideally be protected by admin authorization.
router.get('/', /* auth, authorizeAdmin, */ async (req, res) => {
  try {
    // Find the single settings document. If it doesn't exist, return default values.
    let settings = await AppSettings.findOne({ singletonId: 'app_settings_singleton' });

    if (!settings) {
      // If no settings document exists, return the default values from the schema
      // This is important for the first time the app runs or after a database reset
      settings = new AppSettings(); // Create a new instance with defaults
      // Optionally, you could save this default document to the DB here
      // await settings.save(); // Uncomment if you want to auto-create the default settings document
    }

    res.status(200).json(settings);
  } catch (error) {
    console.error('❌ Error fetching app settings:', error);
    res.status(500).json({ success: false, message: 'Server error fetching app settings.' });
  }
});

// POST /api/settings - Update application settings
// This endpoint MUST be protected by admin authorization.
router.post('/', /* auth, authorizeAdmin, */ async (req, res) => {
  try {
    const updatedSettings = req.body;

    // Use findOneAndUpdate with upsert: true to create the document if it doesn't exist,
    // or update it if it does.
    const settings = await AppSettings.findOneAndUpdate(
      { singletonId: 'app_settings_singleton' }, // Query for the single settings document
      { $set: updatedSettings }, // Update with the new values from the request body
      {
        new: true, // Return the updated document
        upsert: true, // Create the document if it doesn't exist
        runValidators: true, // Run schema validators on the update
      }
    );

    res.status(200).json({ success: true, message: 'App settings updated successfully.', settings });
  } catch (error) {
    console.error('❌ Error updating app settings:', error);
    res.status(500).json({ success: false, message: 'Server error updating app settings.' });
  }
});

module.exports = router;
