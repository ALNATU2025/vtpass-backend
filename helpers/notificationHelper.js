const Notification = require('../models/Notification');
const { sendPushNotification } = require('../notificationSender');
const User = require('../models/User');

/**
 * Create notification in database and send push notification
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
    const pushResult = await sendPushNotification({
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

    // Update notification with push status
    notification.metadata.pushSent = pushResult.success;
    notification.metadata.pushError = pushResult.error || null;
    await notification.save();

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
