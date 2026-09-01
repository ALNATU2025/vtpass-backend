const admin = require('firebase-admin');
const serviceAccount = require('./firebase-service-account.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

async function sendPushNotification({ userId, title, message, type = 'general', screen = 'notifications', badgeCount = 0 }) {
  try {
    const user = await User.findById(userId).select('fcmToken');
    if (!user || !user.fcmToken) return false;

    const payload = {
      notification: { title, body: message },
      data: { type, screen, badgeCount: String(badgeCount) },
      android: { notification: { notificationCount: badgeCount, sound: 'default' } },
      apns: { payload: { aps: { badge: badgeCount, sound: 'default' } } },
      token: user.fcmToken
    };

    await admin.messaging().send(payload);
    return true;
  } catch (error) {
    console.error('❌ FCM send error:', error);
    return false;
  }
}

module.exports = { sendPushNotification };
