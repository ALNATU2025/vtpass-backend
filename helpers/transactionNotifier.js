// helpers/transactionNotifier.js
// ============================================================
// SINGLE SOURCE OF TRUTH for transaction notifications.
//
// Fires HIGH-PRIORITY FCM push + DB row + Socket.IO for:
//   - PENDING
//   - FAILED
//   - REFUND
//   - STATUS CHANGE (admin overrides)
//   - SUCCESSFUL
//
// to BOTH the affected user AND every admin.
// Never fires twice. Never throws.
// ============================================================

const Notification = require('../models/Notification');
const User = require('../models/User');
const { createNotificationAndSendPush } = require('./notificationHelper');

// ---------- USER TITLE TEMPLATES ----------
const USER_TEMPLATES = {
  Pending: { title: 'Transaction Pending ⏳', type: 'transaction_pending' },
  Failed: { title: 'Transaction Failed ❌', type: 'transaction_failed' },
  Refunded: { title: 'Transaction Refunded 💰', type: 'transaction_refunded' },
  Successful: { title: 'Transaction Successful ✅', type: 'transaction' },
  StatusChanged: { title: 'Transaction Status Updated 🔄', type: 'transaction_status_update' },
};

// ---------- ADMIN TITLE TEMPLATES ----------
const ADMIN_TEMPLATES = {
  Pending: { title: '⏳ Pending Transaction' },
  Failed: { title: '❌ Failed Transaction' },
  Refunded: { title: '💰 Refund Issued' },
  Successful: { title: '✅ Successful Transaction' },
  StatusChanged: { title: '🔄 Status Changed (Admin)' },
};

// ============================================================
// MAIN FUNCTION
// ============================================================
async function notifyTransactionEvent({
  status,
  transaction,
  oldStatus = null,
  newStatus = null,
  reason = '',
  user = null,
  newBalance = null,
}) {
  const result = { userNotified: false, adminsNotified: 0, errors: [] };

  try {
    if (!transaction || !transaction.userId) {
      console.warn('⚠️ [TXN-NOTIFY] Missing transaction or userId');
      return result;
    }

    // ---------- Load user if not provided ----------
    let txnUser = user;
    if (!txnUser) {
      try {
        txnUser = await User.findById(transaction.userId)
          .select('fullName email phone fcmToken')
          .lean();
      } catch (e) {
        console.error('⚠️ [TXN-NOTIFY] User load failed:', e.message);
      }
    }

    const userName = txnUser?.fullName || 'User';
    const userEmail = txnUser?.email || '';
    const txType = transaction.type || 'Transaction';
    const txAmount = Number(transaction.amount || 0);
    const txRef = transaction.reference || transaction.transactionId || '';
    const txId = transaction._id?.toString() || '';

    // ---------- Build USER message ----------
    let userTitle;
    let userMessage;
    let userType;

    if (status === 'StatusChanged') {
      const isGood = ['Successful', 'Completed'].includes(newStatus);
      userTitle = isGood
        ? 'Good News! Transaction Successful ✅'
        : `Transaction Update: ${newStatus}`;
      userMessage =
        `Your ${txType} of ₦${txAmount.toFixed(2)} (Ref: ${txRef}) ` +
        `changed from ${oldStatus} to ${newStatus}.` +
        (reason ? ` Note: ${reason}` : '');
      userType = 'transaction_status_update';
    } else if (status === 'Pending') {
      userTitle = USER_TEMPLATES.Pending.title;
      userMessage =
        `Your ${txType} of ₦${txAmount.toFixed(2)} (Ref: ${txRef}) ` +
        `is being processed. We'll notify you once confirmed.`;
      userType = USER_TEMPLATES.Pending.type;
    } else if (status === 'Failed') {
      userTitle = USER_TEMPLATES.Failed.title;
      userMessage =
        `Your ${txType} of ₦${txAmount.toFixed(2)} (Ref: ${txRef}) failed.` +
        (reason ? ` Reason: ${reason}` : '');
      userType = USER_TEMPLATES.Failed.type;
    } else if (status === 'Refunded') {
      userTitle = USER_TEMPLATES.Refunded.title;
      userMessage =
        `Your ${txType} of ₦${txAmount.toFixed(2)} (Ref: ${txRef}) ` +
        `has been refunded to your wallet.` +
        (newBalance !== null
          ? ` New balance: ₦${Number(newBalance).toFixed(2)}`
          : '') +
        (reason ? ` Reason: ${reason}` : '');
      userType = USER_TEMPLATES.Refunded.type;
    } else if (status === 'Successful') {
      userTitle = USER_TEMPLATES.Successful.title;
      userMessage =
        `Your ${txType} of ₦${txAmount.toFixed(2)} (Ref: ${txRef}) is successful.` +
        (newBalance !== null
          ? ` New balance: ₦${Number(newBalance).toFixed(2)}`
          : '');
      userType = USER_TEMPLATES.Successful.type;
    } else {
      userTitle = `Transaction Update: ${status}`;
      userMessage = `Your ${txType} of ₦${txAmount.toFixed(2)} (Ref: ${txRef}) status: ${status}.`;
      userType = 'transaction_status_update';
    }

    // ---------- Notify USER ----------
    try {
      const userResult = await createNotificationAndSendPush({
        recipientId: transaction.userId,
        title: userTitle,
        message: userMessage,
        type: userType,
        screen: 'transaction_details',
        metadata: {
          transactionId: txId,
          transactionReference: txRef,
          transactionType: txType,
          amount: txAmount,
          status,
          oldStatus: oldStatus || null,
          newStatus: newStatus || null,
          reason: reason || null,
        },
      });
      result.userNotified = userResult?.success === true;
      console.log(
        `📨 [TXN-NOTIFY] User ${userEmail} notified (${status}) → pushSent=${userResult?.pushSent}`
      );
    } catch (e) {
      console.error('❌ [TXN-NOTIFY] User notify failed:', e.message);
      result.errors.push(`user: ${e.message}`);
    }

    // ---------- Notify ADMINS ----------
    try {
      const adminUsers = await User.find({
        $or: [
          { isAdmin: true },
          { isSuperAdmin: true },
          { role: 'admin' },
          { role: 'super_admin' },
        ],
      })
        .select('_id fullName email fcmToken')
        .lean();

      if (!adminUsers || adminUsers.length === 0) {
        console.log('ℹ️ [TXN-NOTIFY] No admins to notify');
        return result;
      }

      let adminTitle;
      let adminMessage;

      if (status === 'StatusChanged') {
        adminTitle = ADMIN_TEMPLATES.StatusChanged.title;
        adminMessage =
          `${userName} · ${txType} · ₦${txAmount.toFixed(2)} (Ref: ${txRef}) ` +
          `changed from ${oldStatus} to ${newStatus}.`;
      } else if (status === 'Pending') {
        adminTitle = ADMIN_TEMPLATES.Pending.title;
        adminMessage = `${userName} · ${txType} · ₦${txAmount.toFixed(2)} (Ref: ${txRef}) is PENDING.`;
      } else if (status === 'Failed') {
        adminTitle = ADMIN_TEMPLATES.Failed.title;
        adminMessage =
          `${userName} · ${txType} · ₦${txAmount.toFixed(2)} (Ref: ${txRef}) FAILED.` +
          (reason ? ` Reason: ${reason}` : '');
      } else if (status === 'Refunded') {
        adminTitle = ADMIN_TEMPLATES.Refunded.title;
        adminMessage = `${userName} · ${txType} · ₦${txAmount.toFixed(2)} (Ref: ${txRef}) REFUNDED.`;
      } else if (status === 'Successful') {
        adminTitle = ADMIN_TEMPLATES.Successful.title;
        adminMessage = `${userName} · ${txType} · ₦${txAmount.toFixed(2)} (Ref: ${txRef}) SUCCESSFUL.`;
      } else {
        adminTitle = `Transaction ${status}`;
        adminMessage = `${userName} · ${txType} · ₦${txAmount.toFixed(2)} (Ref: ${txRef}) → ${status}.`;
      }

      let adminsNotified = 0;
      for (const admin of adminUsers) {
        try {
          await createNotificationAndSendPush({
            recipientId: admin._id,
            title: adminTitle,
            message: adminMessage,
            type: 'admin_activity',
            screen: 'admin_notifications',
            metadata: {
              transactionId: txId,
              transactionReference: txRef,
              transactionType: txType,
              amount: txAmount,
              status,
              oldStatus: oldStatus || null,
              newStatus: newStatus || null,
              userName,
              userEmail,
              reason: reason || null,
            },
          });
          adminsNotified += 1;
        } catch (adminErr) {
          console.error(
            `⚠️ [TXN-NOTIFY] Admin ${admin.email} notify failed:`,
            adminErr.message
          );
        }
      }
      result.adminsNotified = adminsNotified;
      console.log(
        `📨 [TXN-NOTIFY] Notified ${adminsNotified}/${adminUsers.length} admins (${status})`
      );
    } catch (e) {
      console.error('❌ [TXN-NOTIFY] Admin notify loop failed:', e.message);
      result.errors.push(`admins: ${e.message}`);
    }

    return result;
  } catch (err) {
    console.error('❌ [TXN-NOTIFY] Fatal:', err.message);
    result.errors.push(err.message);
    return result;
  }
}

module.exports = { notifyTransactionEvent };
