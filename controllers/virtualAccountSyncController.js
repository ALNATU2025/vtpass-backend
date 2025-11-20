// controllers/virtualAccountSyncController.js
const User = require("../models/User");
const Transaction = require("../models/Transaction");

exports.syncVirtualAccountCredit = async (req, res) => {
  try {
    // Optional: keep the internal key if you want extra security
    const internalKey = req.headers["x-internal-api-key"];
    if (process.env.MAIN_BACKEND_API_KEY && (!internalKey || internalKey !== process.env.MAIN_BACKEND_API_KEY)) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    const { userId, amount: amountKobo, reference } = req.body;

    if (!userId || !amountKobo || !reference) {
      return res.status(400).json({ error: "Missing fields: userId, amount (kobo), reference" });
    }

    // CRITICAL: Convert from kobo to naira
    const amountNaira = amountKobo / 100;

    // Prevent duplicate ONLY for virtual account deposits
    const existing = await Transaction.findOne({
      reference,
      type: "virtual_account_topup"   // or "virtual_account_deposit" — whatever you use
    });

    if (existing) {
      console.log(`Duplicate sync ignored: ₦${amountNaira} | Ref: ${reference}`);
      return res.json({ success: true, message: "Already processed", alreadySynced: true });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const balanceBefore = user.walletBalance || 0;
    user.walletBalance = balanceBefore + amountNaira;
    await user.save();

    await Transaction.create({
      userId,
      amount: amountNaira,                    // ← Save in Naira
      reference,
      type: "virtual_account_topup",          // ← Keep your type
      gateway: "paystack_virtual_account",
      status: "success",
      description: `Virtual Account Deposit • ${reference}`,
      balanceBefore,
      balanceAfter: user.walletBalance,
      metadata: { source: "automatic_webhook" }
    });

    console.log(`SYNCED & RECORDED: ₦${amountNaira} → ${user.email} | Ref: ${reference}`);

    return res.json({
      success: true,
      newBalance: user.walletBalance,
      amount: amountNaira,
      message: "Virtual account deposit synced successfully"
    });

  } catch (err) {
    console.error("VIRTUAL ACCOUNT SYNC ERROR:", err);
    return res.status(500).json({ error: "Server error", details: err.message });
  }
};
