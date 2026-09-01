const admin = require('firebase-admin');

// Path to your downloaded service account JSON
const serviceAccount = require('./dalabapay-937de-firebase-adminsdk-fbsvc-4deeb3f82b.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

async function sendPushNotification({ userId, title, message, type = 'general', screen = 'notifications', badgeCount = 0 }) {
  try {
    const user = await User.findById(userId).select('fcmToken');
    if (!user || !user.fcmToken) {
      console.log('⚠️ No FCM token for user:', userId);
      return false;
    }

    const payload = {
      notification: { title, body: message },
      data: { type, screen, badgeCount: String(badgeCount) },
      android: { notification: { notificationCount: badgeCount, sound: 'default' } },
      apns: { payload: { aps: { badge: badgeCount, sound: 'default' } } },
      token: user.fcmToken
    };

    await admin.messaging().send(payload);
    console.log('✅ Notification sent to:', userId);
    return true;
  } catch (error) {
    console.error('❌ FCM send error:', error.message);
    return false;
  }
}

module.exports = { sendPushNotification };
