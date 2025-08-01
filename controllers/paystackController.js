// controllers/paystackController.js
const axios = require('axios');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const User = require('../models/User'); // <<< ENSURE THIS IS '../models/User'
const Transaction = require('../models/Transaction'); // Adjust path if necessary

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_BASE_URL = 'https://api.paystack.co';

const provisionDedicatedAccount = async (userId, userEmail, userName) => {
    try {
        console.log(`DEBUG: Provisioning account for userId: ${userId}, email: ${userEmail}, name: ${userName}`);
        if (!PAYSTACK_SECRET_KEY) {
            console.error("ERROR: Paystack Secret Key is not set.");
            throw new Error("Paystack integration not configured.");
        }
        const reference = `DALABAPAY_${uuidv4().replace(/-/g, '').substring(0, 15).toUpperCase()}`;
        console.log(`DEBUG: Sending request to Paystack for dedicated account with reference: ${reference}`);
        const response = await axios.post(
            `${PAYSTACK_BASE_URL}/dedicated_account`,
            {
                customer: userEmail,
                preferred_bank: 'test-bank',
                split_code: null,
                reference: reference,
            },
            {
                headers: {
                    Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );
        console.log('DEBUG: Raw Paystack API Response:', JSON.stringify(response.data, null, 2));
        const data = response.data;
        if (data.status && data.data) {
            const accountDetails = {
                accountNumber: data.data.account_number,
                bankName: data.data.bank.name,
                accountName: data.data.account_name,
                reference: reference,
                assigned: true,
            };
            console.log('DEBUG: Constructed accountDetails object:', accountDetails);
            const updatedUser = await User.findByIdAndUpdate(
                userId,
                { $set: { virtualAccount: accountDetails } },
                { new: true, runValidators: true }
            );
            console.log('DEBUG: User after findByIdAndUpdate:', updatedUser ? updatedUser.virtualAccount : 'User not found or update failed');
            if (!updatedUser) {
                console.error(`ERROR: User with ID ${userId} not found during virtual account update.`);
                throw new Error('User not found after Paystack provisioning.');
            }
            if (!updatedUser.virtualAccount || !updatedUser.virtualAccount.assigned) {
                console.error(`ERROR: Virtual account not correctly assigned to user ${userId} after update.`);
                throw new Error('Virtual account assignment failed in database.');
            }
            console.log(`✅ Dedicated account provisioned and saved for ${userEmail}: ${accountDetails.accountNumber}`);
            return accountDetails;
        } else {
            console.error('❌ Paystack API Error (Status false):', data.message || 'Unknown error from Paystack');
            throw new Error(data.message || 'Failed to provision dedicated account from Paystack (status false).');
        }
    } catch (error) {
        console.error('❌ Error provisioning dedicated account (caught):', error.response ? JSON.stringify(error.response.data, null, 2) : error.message);
        throw new Error(`Failed to provision dedicated account: ${error.response?.data?.message || error.message}`);
    }
};

const handleWebhook = async (req, res) => {
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
                amount,
                reference,
                status,
                customer: { email: customerEmail },
                paid_at,
                channel,
                currency,
                metadata,
            } = data;
            const actualAmount = amount / 100;
            const user = await User.findOne({ 'virtualAccount.reference': reference });
            if (!user) {
                console.error(`❌ Paystack Webhook: User not found for reference: ${reference}`);
                return res.status(404).send('User not found');
            }
            const existingTransaction = await Transaction.findOne({
                transactionId: data.id,
                userId: user._id,
                type: 'FundWallet',
            });
            if (existingTransaction) {
                console.warn(`⚠️ Paystack Webhook: Transaction ${data.id} already processed for user ${user._id}. Skipping.`);
                return res.status(200).send('Transaction already processed');
            }
            user.walletBalance += actualAmount;
            await user.save();
            const newTransaction = new Transaction({
                userId: user._id,
                type: 'FundWallet',
                amount: actualAmount,
                status: 'Successful',
                transactionId: data.id,
                details: {
                    description: `Wallet funded via Paystack virtual account.`,
                    paystackReference: reference,
                    paystackTransactionId: data.id,
                    paidAt: paid_at,
                    channel: channel,
                    currency: currency,
                    metadata: metadata,
                    userPreviousBalance: user.walletBalance - actualAmount,
                    userNewBalance: user.walletBalance,
                },
            });
            await newTransaction.save();
            console.log(`✅ Wallet funded successfully for ${user.email}. New balance: ${user.walletBalance}`);
            res.status(200).send('Webhook received and processed');
        } else if (event.event === 'dedicated_account.assign.success') {
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
