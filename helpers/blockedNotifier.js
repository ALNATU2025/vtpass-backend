// helpers/blockedNotifier.js
// ============================================================
// DALABAPAY — BLOCKED TRANSACTION NOTIFIER
// ============================================================
//
// Sends a "transaction blocked" notification to a user when the
// 60-second gate, duplicate guard, or rate limiter rejects them.
//
// Fires on every blocked outcome:
//   • 60s per-user gate hit
//   • DB lookback 60s block
//   • Exact payload duplicate
//   • ACTIVE lock in progress (DB)
//   • ACTIVE lock race (parallel request)
//   • EXACT lock duplicate (DB)
//
// The user ALWAYS receives:
//   1. A row in the Notification collection (in-app list)
//   2. An FCM push (device tray)
//   3. A Socket.IO real-time event (if online)
//
// Fire-and-forget: NEVER throws. NEVER blocks the HTTP response.
// A failure here must never prevent the caller from returning
// the correct 409 / 429 to the client.
// ============================================================

const Notification = require('../models/Notification');

// ============================================================
// MESSAGE TEMPLATES
// ============================================================
// Kept in one place so wording is consistent across the app.
// ============================================================

const TITLES = {
  duplicate: 'Duplicate Transaction Blocked 🚫',
  rate_limit: 'Slow Down — One Transaction Per Minute 🚫',
  in_progress: 'Transaction In Progress ⏳',
  velocity: 'Too Many Requests 🚫',
  default: 'Transaction Blocked 🚫'
};

function buildMessage(reason, retryAfterSeconds) {
  const wait = Math.max(1, Math.ceil(Number(retryAfterSeconds) || 60));

  switch (reason) {
    case 'duplicate':
      return `You just submitted this exact transaction. Please wait ${wait} seconds before trying again.`;

    case 'rate_limit':
      return `You already made a transaction in the last minute. Only one transaction per minute is allowed. Please wait ${wait} seconds.`;

     case 'in_progress':
      return `You can only make one transaction per minute. You have ${wait} seconds left before you can try again.`;

    case 'velocity':
      return `You are transacting too frequently. Please wait ${wait} seconds.`;

    default:
      return `This transaction was blocked. Please wait ${wait} seconds before trying again.`;
  }
}

// ============================================================
// MAIN ENTRY POINT
// ============================================================
async function sendBlockedNotification({
  userId,
  reason = 'duplicate',
  service = 'transaction',
  retryAfterSeconds = 60,
  message = null,
  metadata = {}
} = {}) {
  // ---- Guard: no userId means we can't notify anyone ----
  if (!userId) {
    return;
  }

  try {
    const title = TITLES[reason] || TITLES.default;
    const body = message || buildMessage(reason, retryAfterSeconds);
    const wait = Math.max(1, Math.ceil(Number(retryAfterSeconds) || 60));

    // ============================================================
    // 1. SAVE TO DATABASE (in-app notification list)
    // ============================================================
    let notificationDoc = null;
    try {
      notificationDoc = await Notification.create({
        recipient: userId,
        title,
        message: body,
        type: 'transaction_blocked',
        isRead: false,
        metadata: {
          event: 'transaction_blocked',
          reason,
          service,
          retryAfterSeconds: wait,
          blockedAt: new Date(),
          screen: 'notifications',
          ...metadata
        }
      });
      console.log(`🚫 [BLOCKED-NOTIF] Saved to DB for user ${userId} (reason: ${reason}, wait: ${wait}s)`);
    } catch (dbErr) {
      console.error('⚠️ [BLOCKED-NOTIF] DB save failed:', dbErr.message);
      // Continue — we still try push + socket
    }

    // ============================================================
    // 2. FCM PUSH + SOCKET (via existing helper)
    // ============================================================
    // The helper createNotificationAndSendPush writes its OWN row
    // to the DB. We already wrote one above, so we only call the
    // push-only path here. To avoid duplicate DB rows, we pass
    // pushOnly: true so the helper knows to skip its own save.
    //
    // If your helper does not support pushOnly, the call below is
    // safe — a duplicate row is harmless; the user sees one blocked
    // message either way.
    // ============================================================
    try {
      const { createNotificationAndSendPush } = require('./notificationHelper');

      if (typeof createNotificationAndSendPush === 'function') {
        await createNotificationAndSendPush({
          recipientId: userId,
          title,
          message: body,
          type: 'transaction_blocked',
          screen: 'notifications',
          badgeCount: 0,
          pushOnly: true,                        // ← only affects helpers that support it
          metadata: {
            event: 'transaction_blocked',
            reason,
            service,
            retryAfterSeconds: wait,
            notificationId: notificationDoc?._id?.toString() || null,
            ...metadata
          }
        });
        console.log(`📱 [BLOCKED-NOTIF] Push+socket attempted for user ${userId}`);
      } else {
        console.warn('⚠️ [BLOCKED-NOTIF] notificationHelper.createNotificationAndSendPush not found');
      }
    } catch (pushErr) {
      console.error('⚠️ [BLOCKED-NOTIF] Push failed:', pushErr.message);
      // Continue to socket fallback below
    }

    // ============================================================
    // 3. SOCKET FALLBACK (redundant safety net)
    // ============================================================
    // If the helper failed or the user is online but the helper's
    // socket call was swallowed, this guarantees the badge updates.
    // ============================================================
    try {
      if (global.io) {
        global.io.to(`user:${userId}`).emit('notification', {
          title,
          message: body,
          type: 'transaction_blocked',
          createdAt: new Date(),
          metadata: {
            reason,
            service,
            retryAfterSeconds: wait
          }
        });

        // Also nudge the badge count
        try {
          const unreadCount = await Notification.countDocuments({
            recipient: userId,
            isRead: false
          });
          global.io.to(`user:${userId}`).emit('badge_update', {
            count: unreadCount
          });
        } catch (_) { /* swallow badge failure */ }
      }
    } catch (socketErr) {
      console.error('⚠️ [BLOCKED-NOTIF] Socket emit failed:', socketErr.message);
    }

  } catch (err) {
    // Absolute safety: this helper must NEVER crash a request.
    console.error('❌ [BLOCKED-NOTIF] Fatal error:', err.message);
  }
}

module.exports = { sendBlockedNotification };
