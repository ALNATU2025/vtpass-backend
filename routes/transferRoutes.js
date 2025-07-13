const express = require('express');
const router = express.Router();
const Transaction = require('../models/transactionModel');

router.get('/', async (req, res) => {
  const transactions = await Transaction.find({}).populate('userId');
  res.json(transactions);
});

module.exports = router;
