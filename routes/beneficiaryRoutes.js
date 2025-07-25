// routes/beneficiaryRoutes.js
const express = require('express');
const router = express.Router();
const Beneficiary = require('../models/Beneficiary'); // Import the new Beneficiary model
// const auth = require('../middleware/auth'); // Your authentication middleware (uncomment and use if you have one)

// Middleware to ensure user is authenticated and userId is available in req.user.id
// If you have a custom auth middleware, it should populate req.user.id
const authenticateUser = (req, res, next) => {
  // For demonstration, assuming userId is passed in headers or body for now if no auth middleware
  // In a real app, this would come from the JWT token in auth middleware
  // req.user = { id: req.headers['x-user-id'] || req.body.userId }; // Example if no auth middleware
  if (!req.user || !req.user.id) {
    return res.status(401).json({ message: 'Authentication required. Please log in.' });
  }
  next();
};

// GET /api/beneficiaries/:userId - Get all beneficiaries for a specific user
router.get('/:userId', /* auth, */ async (req, res) => { // Consider using req.user.id from auth middleware instead of req.params.userId
  try {
    const userId = req.params.userId; // Or req.user.id if using auth middleware

    const beneficiaries = await Beneficiary.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(beneficiaries);
  } catch (error) {
    console.error('❌ Error fetching beneficiaries:', error);
    res.status(500).json({ success: false, message: 'Server error fetching beneficiaries.' });
  }
});

// POST /api/beneficiaries - Add a new beneficiary
router.post('/', /* auth, */ async (req, res) => { // Ensure req.body.userId comes from auth middleware for security
  try {
    const { userId, name, type, value, network } = req.body;

    // Basic validation
    if (!userId || !name || !type || !value) {
      return res.status(400).json({ message: 'Name, type, and value are required.' });
    }
    if (type === 'phone' && !network) {
        return res.status(400).json({ message: 'Network is required for phone beneficiaries.' });
    }

    // Check for duplicate (handled by schema index, but can add explicit check for better error message)
    const existingBeneficiary = await Beneficiary.findOne({ userId, type, value });
    if (existingBeneficiary) {
      return res.status(409).json({ message: 'This beneficiary already exists for this user.' });
    }

    const newBeneficiary = new Beneficiary({
      userId,
      name,
      type,
      value,
      network: type === 'phone' ? network : undefined, // Only save network if type is phone
    });

    await newBeneficiary.save();
    res.status(201).json({ success: true, message: 'Beneficiary added successfully.', beneficiary: newBeneficiary });
  } catch (error) {
    console.error('❌ Error adding beneficiary:', error);
    res.status(500).json({ success: false, message: 'Server error adding beneficiary.' });
  }
});

// DELETE /api/beneficiaries/:id - Delete a beneficiary by ID
router.delete('/:id', /* auth, */ async (req, res) => { // Ensure user can only delete their own beneficiaries
  try {
    const beneficiaryId = req.params.id;
    // const userId = req.user.id; // Get userId from authenticated user

    // Find and delete the beneficiary, ensuring it belongs to the authenticated user
    const deletedBeneficiary = await Beneficiary.findOneAndDelete({ _id: beneficiaryId /*, userId: userId */ });

    if (!deletedBeneficiary) {
      return res.status(404).json({ message: 'Beneficiary not found or you do not have permission to delete it.' });
    }

    res.status(200).json({ success: true, message: 'Beneficiary deleted successfully.' });
  } catch (error) {
    console.error('❌ Error deleting beneficiary:', error);
    res.status(500).json({ success: false, message: 'Server error deleting beneficiary.' });
  }
});

module.exports = router;
