const admin = require('./firebaseAdmin');
const User = require('./models/User');

async function sendPushNotification({
  userId,
  title,
  message,
  type = 'general',
  screen = 'notifications',
  badgeCount = 0,
  data = {}
}) {
  try {
    const user = await User.findById(userId).select('fcmToken email fullName');
    
    if (!user) {
      console.log('⚠️ User not found:', userId);
      return { success: false, error: 'User not found' };
    }

    if (!user.fcmToken) {
      console.log('⚠️ No FCM token for user:', user.email);
      return { success: false, error: 'No FCM token' };
    }

    const payload = {
      notification: {
        title: title,
        body: message,
      },
      data: {
        type: type,
        screen: screen,
        badgeCount: String(badgeCount),
        notificationId: data.notificationId || '',
        transactionId: data.transactionId || '',
        click_action: 'FLUTTER_NOTIFICATION_CLICK',
      },
      android: {
        notification: {
          notificationCount: badgeCount,
          sound: 'default',
          channelId: 'dalabapay_channel',
        },
        priority: 'high',
      },
      apns: {
        payload: {
          aps: {
            badge: badgeCount,
            sound: 'default',
          },
        },
      },
      token: user.fcmToken,
    };

    const response = await admin.messaging().send(payload);
    console.log('✅ Notification sent to:', user.email, 'Response:', response);
    return { success: true, response };
  } catch (error) {
    console.error('❌ Error sending notification:', error.message);
    
    if (error.code === 'messaging/invalid-registration-token' ||
        error.code === 'messaging/registration-token-not-registered') {
      await User.findByIdAndUpdate(userId, { $unset: { fcmToken: 1 } });
      console.log('🗑️ Invalid FCM token removed for user:', userId);
    }
    
    return { success: false, error: error.message };
  }
}

module.exports = { sendPushNotification };
