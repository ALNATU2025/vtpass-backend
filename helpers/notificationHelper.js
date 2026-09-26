const Notification = require('../models/Notification');
const { sendPushNotification } = require('../firebaseAdmin');
const User = require('../models/User');

/**
 * Create notification in database and send push notification
 *
 * ✅ FIXED: MongoDB Mixed field mutation bug
 *    - Added markModified('metadata') after mutating notification.metadata
 *    - Without this, MongoDB silently skips persisting pushSent/pushError
 *    - This was causing DB to show pushSent:false even when FCM succeeded
 */
async function createNotificationAndSendPush({
  recipientId,
  title,
  message,
  type = 'general',
  screen = 'notifications',
  metadata = {},
  badgeCount = null
}) {
  try {
    // 1. Get user's unread count for badge
    let unreadCount = badgeCount;
    if (unreadCount === null) {
      unreadCount = await Notification.countDocuments({
        recipient: recipientId,
        isRead: false
      });
      // Add 1 for this new notification
      unreadCount += 1;
    }

    // 2. Save notification to database
    const notification = new Notification({
      recipient: recipientId,
      title: title,
      message: message,
      type: type,
      isRead: false,
      metadata: {
        ...metadata,
        screen: screen,
        pushSent: false
      }
    });

    await notification.save();
    console.log('✅ Notification saved to database:', notification._id);

    // 3. Send push notification via Firebase
    let pushResult = { success: false, error: 'Not attempted' };
    try {
      pushResult = await sendPushNotification({
        userId: recipientId,
        title: title,
        message: message,
        type: type,
        screen: screen,
        badgeCount: unreadCount,
        data: {
          notificationId: notification._id.toString(),
          ...metadata
        }
      });
      console.log(`📤 [PUSH] sendPushNotification returned: success=${pushResult.success}, error=${pushResult.error || 'none'}`);
    } catch (pushCallErr) {
      console.error('❌ [PUSH] sendPushNotification threw:', pushCallErr.message);
      pushResult = { success: false, error: pushCallErr.message };
    }

    // ============================================================
    // ✅ CRITICAL FIX: Update notification with push status
    // ============================================================
    // The `metadata` field is type: Mixed in the Notification schema.
    // MongoDB does NOT track mutations on Mixed fields unless we
    // explicitly call markModified(). Without this line, the DB keeps
    // the ORIGINAL pushSent:false value forever — even when FCM works.
    // ============================================================
    notification.metadata = notification.metadata || {};
    notification.metadata.pushSent = pushResult.success === true;
    notification.metadata.pushError = pushResult.error || null;

    // ✅ THE FIX: Tell Mongoose the Mixed field changed
    notification.markModified('metadata');

    await notification.save();
    console.log(
      `📝 [PUSH-STATUS] Notification ${notification._id} updated — pushSent: ${notification.metadata.pushSent}, pushError: ${notification.metadata.pushError || 'none'}`
    );

    // 4. Emit via Socket.IO if available
    try {
      if (global.io) {
        const notificationData = notification.toJSON ? notification.toJSON() : notification;
        global.io.to(`user:${recipientId}`).emit('notification', notificationData);
        global.io.to(`user:${recipientId}`).emit('badge_update', { count: unreadCount });
        console.log('📡 Socket notification emitted for user:', recipientId);
      }
    } catch (socketError) {
      console.log('⚠️ Socket emission error:', socketError.message);
    }

    if (pushResult.success) {
      console.log('✅ Push notification sent via FCM');
    } else {
      console.log('⚠️ Push notification failed:', pushResult.error || 'Unknown error');
    }

    return {
      success: true,
      notification: notification,
      pushSent: pushResult.success || false,
      pushError: pushResult.error || null,
      unreadCount: unreadCount
    };
  } catch (error) {
    console.error('❌ Notification creation error:', error.message);
    console.error('Error stack:', error.stack);
    return {
      success: false,
      error: error.message,
      notification: null,
      pushSent: false
    };
  }
}

/**
 * Get unread notification count for a user
 */
async function getUserUnreadCount(userId) {
  try {
    return await Notification.countDocuments({
      recipient: userId,
      isRead: false
    });
  } catch (error) {
    console.error('Error getting unread count:', error.message);
    return 0;
  }
}

module.exports = {
  createNotificationAndSendPush,
  getUserUnreadCount
};
