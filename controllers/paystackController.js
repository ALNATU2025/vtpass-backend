// controllers/paystackController.js
const axios = require('axios');
const crypto = require('crypto'); // For webhook verification
const { v4: uuidv4 } = require('uuid'); // For generating unique references

const User = require('../models/User'); // Adjust path if necessary
const Transaction = require('../models/transactionModel'); // Adjust path if necessary

// Load environment variables (e.g., Paystack Secret Key)
// For local development, use a .env file and dotenv package
// For Render, set environment variables directly in Render dashboard
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_BASE_URL = 'https://api.paystack.co';

// Function to provision a dedicated virtual account for a user
const provisionDedicatedAccount = async (userId, userEmail, userName) => {
  try {
    if (!PAYSTACK_SECRET_KEY) {
      console.error("Paystack Secret Key is not set.");
      throw new Error("Paystack integration not configured.");
    }

    const reference = `DALABAPAY_${uuidv4().replace(/-/g, '').substring(0, 15).toUpperCase()}`; // Unique reference for Paystack

    const response = await axios.post(
      `${PAYSTACK_BASE_URL}/dedicated_account`,
      {
        customer: userEmail, // Use customer email for Paystack customer association
        preferred_bank: 'test-bank', // For testing, use 'test-bank'. For live, specify a bank (e.g., 'wema-bank')
        // You might need to pass more details like `split_code` if you use Paystack's split payment feature
        // or `account_name` if you want to explicitly set it.
        // For dynamic account names, Paystack usually derives from customer name.
        subaccount: null, // If you have subaccounts, specify here
        split_code: null, // If you have split payment, specify here
        reference: reference, // Pass your unique reference
      },
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
        },
      }
    );

    const data = response.data;
    if (data.status && data.data) {
      const accountDetails = {
        accountNumber: data.data.account_number,
        bankName: data.data.bank.name,
        accountName: data.data.account_name,
        reference: reference, // Store the reference we sent
        assigned: true,
      };

      // Update the user in your database with these details
      await User.findByIdAndUpdate(
        userId,
        { $set: { virtualAccount: accountDetails } },
        { new: true, runValidators: true }
      );

      console.log(`✅ Dedicated account provisioned for ${userEmail}: ${accountDetails.accountNumber}`);
      return accountDetails;
    } else {
      console.error('❌ Paystack API Error:', data.message || 'Unknown error from Paystack');
      throw new Error(data.message || 'Failed to provision dedicated account from Paystack.');
    }
  } catch (error) {
    console.error('❌ Error provisioning dedicated account:', error.response ? error.response.data : error.message);
    throw new Error(`Failed to provision dedicated account: ${error.response?.data?.message || error.message}`);
  }
};

// Webhook handler for Paystack
const handleWebhook = async (req, res) => {
  // 1. Verify webhook signature
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(JSON.stringify(req.body)).digest('hex');
  if (hash !== req.headers['x-paystack-signature']) {
    console.warn('⚠️ Paystack Webhook: Invalid signature. Request potentially tampered with.');
    return res.status(400).send('Invalid signature');
  }

  const event = req.body;
  console.log('🔔 Paystack Webhook Received:', event.event);

  try {
    if (event.event === 'charge.success') {
      const { data } = event;
      const {
        amount, // in kobo
        reference, // our custom reference
        status,
        customer: { email: customerEmail },
        paid_at,
        channel,
        currency,
        metadata, // Any metadata you passed during account creation
      } = data;

      // Convert amount from kobo to naira
      const actualAmount = amount / 100;

      // 2. Find the user by the `reference` we stored in their virtualAccount
      // Or by customerEmail if you prefer, but reference is more robust for virtual accounts
      const user = await User.findOne({ 'virtualAccount.reference': reference });

      if (!user) {
        console.error(`❌ Paystack Webhook: User not found for reference: ${reference}`);
        return res.status(404).send('User not found');
      }

      // 3. Check if transaction already processed (Idempotency)
      // This is crucial to prevent double-crediting
      const existingTransaction = await Transaction.findOne({
        transactionId: data.id, // Paystack's unique transaction ID
        userId: user._id,
        type: 'FundWallet',
      });

      if (existingTransaction) {
        console.warn(`⚠️ Paystack Webhook: Transaction ${data.id} already processed for user ${user._id}. Skipping.`);
        return res.status(200).send('Transaction already processed');
      }

      // 4. Update user's wallet balance
      user.walletBalance += actualAmount;
      await user.save();

      // 5. Create a transaction record
      const newTransaction = new Transaction({
        userId: user._id,
        type: 'FundWallet',
        amount: actualAmount,
        status: 'Successful',
        transactionId: data.id, // Use Paystack's transaction ID as our unique ID
        details: {
          description: `Wallet funded via Paystack virtual account.`,
          paystackReference: reference,
          paystackTransactionId: data.id,
          paidAt: paid_at,
          channel: channel,
          currency: currency,
          metadata: metadata,
          userPreviousBalance: user.walletBalance - actualAmount, // Before credit
          userNewBalance: user.walletBalance, // After credit
        },
      });
      await newTransaction.save();

      console.log(`✅ Wallet funded successfully for ${user.email}. New balance: ${user.walletBalance}`);
      res.status(200).send('Webhook received and processed');

    } else if (event.event === 'dedicated_account.assign.success') {
      // This event fires when a dedicated account is successfully assigned.
      // You might use this to confirm the account details are ready,
      // but we're already updating the user on our direct API call.
      console.log('ℹ️ Dedicated account assigned successfully event received.');
      res.status(200).send('Dedicated account assigned event processed.');
    } else {
      console.log(`ℹ️ Paystack Webhook: Event type ${event.event} received. No action taken.`);
      res.status(200).send('Event received, no action taken.');
    }
  } catch (error) {
    console.error('❌ Error processing Paystack webhook:', error);
    res.status(500).send('Error processing webhook');
  }
};

module.exports = {
  provisionDedicatedAccount,
  handleWebhook,
};
