// controllers/transferController.js

const User = require('../models/userModel');
const Transaction = require('../models/transactionModel');

const transferMoney = async (req, res) => {
  try {
    const { senderId, receiver, bank, accountNumber, amount } = req.body;

    if (!senderId || !receiver || !bank || !accountNumber || !amount) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const sender = await User.findById(senderId);
    if (!sender) return res.status(404).json({ message: 'Sender not found.' });

    if (sender.walletBalance < amount) {
      return res.status(400).json({ message: 'Insufficient wallet balance.' });
    }

    sender.walletBalance -= amount;
    await sender.save();

    const transaction = await Transaction.create({
      userId: senderId,
      type: 'Transfer',
      amount,
      status: 'Successful',
      details: `Transferred to ${receiver} (${bank}, ${accountNumber})`,
    });

    res.status(200).json({
      message: 'Transfer successful',
      walletBalance: sender.walletBalance,
      transaction,
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// ✅ Export properly
module.exports = { transferMoney };
