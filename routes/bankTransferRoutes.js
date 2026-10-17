// routes/bankTransferRoutes.js
//
// Wallet -> bank account payouts through Paystack Transfers.
//
// Switched OFF by default. To enable, set on the server:
//   BANK_TRANSFER_ENABLED=true
//   PAYSTACK_SECRET_KEY=sk_live_...        (already used elsewhere)
// Optional:
//   BANK_TRANSFER_FEE=50                   flat fee in naira added to each transfer
//   BANK_TRANSFER_MIN=100                  minimum amount in naira
//   BANK_TRANSFER_MAX=500000               maximum amount in naira per transfer
//
// Paystack requirements: Transfers must be enabled on the Paystack business,
// the Paystack balance must be funded, and "OTP for transfers" must be turned
// OFF (Settings > Preferences) so the API can complete payouts.
//
// Money safety:
//   * The wallet is debited atomically before the payout is requested.
//   * A definite rejection from Paystack refunds the wallet immediately.
//   * Unclear outcomes (timeouts, 5xx, "pending") are kept as Processing and
//     settled by /status/:reference or the background settle job, which
//     refunds exactly once if Paystack reports failed/reversed.

const express = require('express');
const axios = require('axios');
const User = require('../models/User');
const Transaction = require('../models/Transaction');

const PAYSTACK_BASE = 'https://api.paystack.co';

function cfg() {
  const num = (v, d) => {
    const n = parseFloat(v);
    return Number.isFinite(n) ? n : d;
  };
  const enabled =
    process.env.BANK_TRANSFER_ENABLED === 'true' && !!process.env.PAYSTACK_SECRET_KEY;
  return {
    enabled,
    fee: num(process.env.BANK_TRANSFER_FEE, 50),
    minAmount: num(process.env.BANK_TRANSFER_MIN, 100),
    maxAmount: num(process.env.BANK_TRANSFER_MAX, 500000),
  };
}

function paystack() {
  return axios.create({
    baseURL: PAYSTACK_BASE,
    timeout: 30000,
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      'Content-Type': 'application/json',
    },
  });
}

const round2 = (n) => Math.round(n * 100) / 100;

// Paystack reference: 16-50 chars, lowercase letters, digits, '-' and '_'.
function paystackRef(clientReference, userId) {
  const base = String(clientReference || `${Date.now()}`)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '')
    .slice(0, 30);
  return `dlbbt_${String(userId).slice(-8)}_${base}`.slice(0, 50).padEnd(16, '0');
}

let banksCache = { at: 0, banks: [] };

async function refundOnce(tx, reason) {
  // Flip Processing/Pending -> Refunded exactly once, then credit the wallet.
  const claimed = await Transaction.findOneAndUpdate(
    { _id: tx._id, status: { $in: ['Pending', 'Processing'] } },
    { $set: { status: 'Refunded', isFailed: true, failureReason: reason } },
    { new: true }
  );
  if (!claimed) return null;
  const total = claimed.amount;
  const user = await User.findByIdAndUpdate(
    claimed.userId,
    { $inc: { walletBalance: total } },
    { new: true }
  );
  await Transaction.create({
    userId: claimed.userId,
    type: 'Refund Credit',
    amount: total,
    status: 'Successful',
    reference: `${claimed.reference}-RF`,
    description: `Refund: bank transfer to ${claimed.metadata?.customerName || 'bank account'} was not completed`,
    balanceBefore: user ? round2(user.walletBalance - total) : 0,
    balanceAfter: user ? user.walletBalance : 0,
    service: 'bank_transfer',
    gateway: 'Paystack',
    authenticationMethod: 'none',
    isSystemTransaction: true,
  });
  console.log(`💸 [BANK-TRANSFER] Refunded ₦${total} for ${claimed.reference}: ${reason}`);
  return user;
}

async function markSuccessful(tx, data) {
  await Transaction.updateOne(
    { _id: tx._id, status: { $in: ['Pending', 'Processing'] } },
    {
      $set: {
        status: 'Successful',
        gatewayResponse: data,
        lastVerifiedAt: new Date(),
      },
    }
  );
}

// Ask Paystack for the outcome of a payout and settle our record.
async function settle(tx) {
  const ref = tx.gatewayReference;
  if (!ref) return tx.status;
  try {
    const { data } = await paystack().get(`/transfer/verify/${encodeURIComponent(ref)}`);
    const st = String(data?.data?.status || '').toLowerCase();
    await Transaction.updateOne(
      { _id: tx._id },
      { $set: { lastVerifiedAt: new Date() }, $inc: { verificationAttempts: 1 } }
    );
    if (st === 'success') {
      await markSuccessful(tx, data.data);
      return 'Successful';
    }
    if (['failed', 'reversed', 'abandoned', 'rejected'].includes(st)) {
      await refundOnce(tx, `Paystack status: ${st}`);
      return 'Refunded';
    }
    return 'Processing';
  } catch (err) {
    const code = err.response?.status;
    // Paystack never received the transfer: safe to refund after a grace period.
    const ageMs = Date.now() - new Date(tx.createdAt).getTime();
    if (code === 404 && ageMs > 15 * 60 * 1000) {
      await refundOnce(tx, 'Transfer not found at Paystack');
      return 'Refunded';
    }
    console.warn(`⚠️ [BANK-TRANSFER] verify ${ref} failed: ${err.message}`);
    return tx.status;
  }
}

function startSettleJob() {
  if (startSettleJob.started) return;
  startSettleJob.started = true;
  setInterval(async () => {
    if (!cfg().enabled) return;
    try {
      const pending = await Transaction.find({
        type: 'Bank Transfer',
        status: { $in: ['Pending', 'Processing'] },
        createdAt: { $lt: new Date(Date.now() - 60 * 1000) },
      })
        .sort({ createdAt: 1 })
        .limit(20);
      for (const tx of pending) {
        // eslint-disable-next-line no-await-in-loop
        await settle(tx);
      }
    } catch (e) {
      console.warn('⚠️ [BANK-TRANSFER] settle job error:', e.message);
    }
  }, 2 * 60 * 1000).unref();
}

module.exports = function bankTransferRoutes({
  protect,
  requireApproval,
  verifyTransactionAuth,
  checkTransactionLimit,
  checkPerMinuteLimit,
}) {
  const router = express.Router();
  const passthrough = (req, res, next) => next();
  const limitTotal = checkTransactionLimit ? checkTransactionLimit('transfer') : passthrough;
  const limitRate = checkPerMinuteLimit ? checkPerMinuteLimit('transfer') : passthrough;

  startSettleJob();

  // ---------- Config ----------
  router.get('/config', protect, (req, res) => {
    const c = cfg();
    res.json({
      success: true,
      enabled: c.enabled,
      fee: c.fee,
      minAmount: c.minAmount,
      maxAmount: c.maxAmount,
      message: c.enabled
        ? null
        : 'Bank transfers are not available yet. You can still send money to another Dalabapay wallet.',
    });
  });

  // ---------- Bank list ----------
  router.get('/banks', protect, async (req, res) => {
    try {
      if (Date.now() - banksCache.at < 12 * 60 * 60 * 1000 && banksCache.banks.length) {
        return res.json({ success: true, banks: banksCache.banks });
      }
      if (!process.env.PAYSTACK_SECRET_KEY) {
        return res.status(503).json({ success: false, message: 'Bank list is unavailable' });
      }
      const { data } = await paystack().get('/bank', {
        params: { country: 'nigeria', currency: 'NGN', perPage: 200 },
      });
      const seen = new Set();
      const banks = (data?.data || [])
        .filter((b) => b.active !== false && b.code && !seen.has(b.code) && seen.add(b.code))
        .map((b) => ({ name: b.name, code: b.code }));
      banksCache = { at: Date.now(), banks };
      res.json({ success: true, banks });
    } catch (err) {
      console.error('❌ [BANK-TRANSFER] banks:', err.message);
      res.status(502).json({ success: false, message: 'Could not load banks. Please try again.' });
    }
  });

  // ---------- Account name lookup ----------
  router.post('/resolve', protect, async (req, res) => {
    const accountNumber = String(req.body.accountNumber || '').trim();
    const bankCode = String(req.body.bankCode || '').trim();
    if (!/^\d{10}$/.test(accountNumber) || !bankCode) {
      return res.status(400).json({ success: false, message: 'Enter a valid 10-digit account number and bank' });
    }
    try {
      const { data } = await paystack().get('/bank/resolve', {
        params: { account_number: accountNumber, bank_code: bankCode },
      });
      const accountName = data?.data?.account_name;
      if (!accountName) {
        return res.status(404).json({ success: false, message: 'Account not found' });
      }
      res.json({ success: true, accountName });
    } catch (err) {
      const code = err.response?.status;
      res.status(code === 422 || code === 400 ? 404 : 502).json({
        success: false,
        message:
          code === 422 || code === 400
            ? 'We could not find that account. Check the number and bank.'
            : 'Account lookup is unavailable right now. Please try again.',
      });
    }
  });

  // ---------- Wallet recipient lookup (name only) ----------
  router.get('/wallet-recipient', protect, async (req, res) => {
    const email = String(req.query.email || '').trim().toLowerCase();
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Enter a valid email' });
    }
    const user = await User.findOne({ email }).select('fullName email');
    if (!user) return res.status(404).json({ success: false, message: 'No Dalabapay account uses that email' });
    if (String(user._id) === String(req.user._id)) {
      return res.status(400).json({ success: false, message: 'You can’t send money to yourself' });
    }
    res.json({ success: true, name: user.fullName || 'Dalabapay user' });
  });

  // ---------- Send ----------
  router.post(
    '/send',
    protect,
    requireApproval,
    verifyTransactionAuth,
    limitTotal,
    limitRate,
    async (req, res) => {
      const c = cfg();
      if (!c.enabled) {
        return res.status(403).json({ success: false, message: 'Bank transfers are not available yet.' });
      }
      const userId = req.user._id;
      const accountNumber = String(req.body.accountNumber || '').trim();
      const bankCode = String(req.body.bankCode || '').trim();
      const bankName = String(req.body.bankName || '').trim().slice(0, 80);
      const narration = String(req.body.narration || '').trim().slice(0, 80);
      const amount = round2(parseFloat(req.body.amount));
      const clientReference = String(req.body.clientReference || '').slice(0, 60);

      if (!/^\d{10}$/.test(accountNumber) || !bankCode) {
        return res.status(400).json({ success: false, message: 'Enter a valid account number and bank' });
      }
      if (!Number.isFinite(amount) || amount < c.minAmount) {
        return res.status(400).json({ success: false, message: `Minimum transfer is ₦${c.minAmount}` });
      }
      if (c.maxAmount > 0 && amount > c.maxAmount) {
        return res.status(400).json({ success: false, message: `Maximum transfer is ₦${c.maxAmount}` });
      }

      const reference = `BT-${clientReference || Date.now()}`.replace(/[^A-Za-z0-9_-]/g, '');
      const existing = await Transaction.findOne({ reference, userId });
      if (existing) {
        const u = await User.findById(userId).select('walletBalance');
        return res.json({
          success: existing.status !== 'Failed' && existing.status !== 'Refunded',
          status: existing.status,
          reference,
          newBalance: u?.walletBalance,
          message: 'This transfer was already submitted.',
        });
      }

      // Verify the account name server-side; never trust the client's copy.
      let accountName;
      try {
        const { data } = await paystack().get('/bank/resolve', {
          params: { account_number: accountNumber, bank_code: bankCode },
        });
        accountName = data?.data?.account_name;
      } catch (_) {
        accountName = null;
      }
      if (!accountName) {
        return res.status(400).json({ success: false, message: 'We could not verify that account. Please check it and try again.' });
      }

      const total = round2(amount + c.fee);

      // Atomic debit.
      const debited = await User.findOneAndUpdate(
        { _id: userId, walletBalance: { $gte: total } },
        { $inc: { walletBalance: -total } },
        { new: true }
      );
      if (!debited) {
        return res.status(400).json({ success: false, message: `Insufficient balance. You need ₦${total.toFixed(2)} including the ₦${c.fee} fee.` });
      }

      const psRef = paystackRef(clientReference, userId);
      let tx;
      try {
        tx = await Transaction.create({
          userId,
          type: 'Bank Transfer',
          amount: total,
          status: 'Processing',
          reference,
          gatewayReference: psRef,
          description: `Transfer to ${accountName} · ${bankName || 'Bank'} ${accountNumber}`,
          balanceBefore: round2(debited.walletBalance + total),
          balanceAfter: debited.walletBalance,
          service: 'bank_transfer',
          gateway: 'Paystack',
          authenticationMethod: req.authenticationMethod || (req.body.useBiometric ? 'biometric' : 'pin'),
          userEmailSnapshot: debited.email,
          userNameSnapshot: debited.fullName,
          metadata: {
            customerName: accountName,
            provider: bankName,
            billersCode: accountNumber,
            note: narration,
            gatewayData: { bankCode, bankName, accountNumber, accountName, amount, fee: c.fee },
          },
        });
      } catch (err) {
        // Could not record: give the money back.
        await User.updateOne({ _id: userId }, { $inc: { walletBalance: total } });
        console.error('❌ [BANK-TRANSFER] record failed:', err.message);
        return res.status(500).json({ success: false, message: 'Transfer could not be started. You were not charged.' });
      }

      const ps = paystack();
      try {
        const rec = await ps.post('/transferrecipient', {
          type: 'nuban',
          name: accountName,
          account_number: accountNumber,
          bank_code: bankCode,
          currency: 'NGN',
        });
        const recipient = rec.data?.data?.recipient_code;
        if (!recipient) throw Object.assign(new Error('No recipient code'), { definite: true });

        const tr = await ps.post('/transfer', {
          source: 'balance',
          amount: Math.round(amount * 100),
          recipient,
          reference: psRef,
          reason: narration || 'Dalabapay transfer',
        });
        const st = String(tr.data?.data?.status || '').toLowerCase();
        await Transaction.updateOne(
          { _id: tx._id },
          { $set: { gatewayResponse: tr.data?.data, 'metadata.exchangeReference': tr.data?.data?.transfer_code } }
        );

        if (st === 'success') {
          await markSuccessful(tx, tr.data.data);
          return res.json({ success: true, status: 'Successful', reference, newBalance: debited.walletBalance });
        }
        if (st === 'otp' || st === 'failed') {
          await refundOnce(tx, st === 'otp' ? 'Paystack requires OTP for transfers' : 'Paystack rejected transfer');
          const u = await User.findById(userId).select('walletBalance');
          return res.status(502).json({
            success: false,
            status: 'Refunded',
            reference,
            newBalance: u?.walletBalance,
            message: 'The bank transfer could not be completed. Your money has been returned to your wallet.',
          });
        }
        // pending / processing / queued
        return res.json({ success: true, status: 'Pending', reference, newBalance: debited.walletBalance });
      } catch (err) {
        const code = err.response?.status;
        const definite = err.definite || (code >= 400 && code < 500);
        console.error(`❌ [BANK-TRANSFER] ${reference}:`, code, err.response?.data?.message || err.message);
        if (definite) {
          await refundOnce(tx, err.response?.data?.message || err.message);
          const u = await User.findById(userId).select('walletBalance');
          return res.status(502).json({
            success: false,
            status: 'Refunded',
            reference,
            newBalance: u?.walletBalance,
            message: 'The bank transfer could not be completed. Your money has been returned to your wallet.',
          });
        }
        // Unclear outcome: keep Processing; the settle job will finish it.
        return res.json({
          success: true,
          status: 'Pending',
          reference,
          newBalance: debited.walletBalance,
          message: 'Your transfer is processing. We will update it shortly.',
        });
      }
    }
  );

  // ---------- Status ----------
  router.get('/status/:reference', protect, async (req, res) => {
    const tx = await Transaction.findOne({
      reference: req.params.reference,
      userId: req.user._id,
      type: 'Bank Transfer',
    });
    if (!tx) return res.status(404).json({ success: false, message: 'Transfer not found' });
    let status = tx.status;
    if (status === 'Processing' || status === 'Pending') status = await settle(tx);
    const u = await User.findById(req.user._id).select('walletBalance');
    res.json({ success: true, status, reference: tx.reference, newBalance: u?.walletBalance });
  });

  return router;
};

// Exposed for tests.
module.exports._internal = { paystackRef, cfg };
