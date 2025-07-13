// controllers/cabletvController.js
const User = require('../models/User');
const CableTVTransaction = require('../models/CableTVTransaction');

const payCableTV = async (req, res) => {
  try {
    const { userId, serviceType, smartCardNumber, packageName, amount } = req.body;

    if (!userId || !serviceType || !smartCardNumber || !packageName || !amount) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.walletBalance < amount) {
      return res.status(400).json({ message: 'Insufficient funds in wallet' });
    }

    // Deduct the amount
    user.walletBalance -= amount;
    await user.save();

    // Save the transaction
    const transaction = new CableTVTransaction({
      userId,
      serviceType,
      smartCardNumber,
      packageName,
      amount,
    });
    await transaction.save();

    res.status(200).json({
      message: 'Cable TV payment successful',
      transaction,
      walletBalance: user.walletBalance
    });
  } catch (error) {
    console.error('CableTV payment error:', error);
    res.status(500).json({ message: 'Server error processing payment' });
  }
};

module.exports = { payCableTV };
