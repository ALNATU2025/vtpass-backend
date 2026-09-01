const admin = require('firebase-admin');
// ✅ ADD THIS IMPORT
const User = require('./models/User');

// Path to your downloaded service account JSON
const serviceAccount = require('./dalabapay-937de-firebase-adminsdk-fbsvc-4deeb3f82b.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

console.log('✅ Firebase Admin initialized successfully');

/**
 * Send push notification to a user
 */
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
    // ✅ NOW User is defined!
    const user = await User.findById(userId).select('fcmToken email fullName');
    
    if (!user || !user.fcmToken) {
      console.log('⚠️ No FCM token for user:', userId);
      return { success: false, error: 'No FCM token' };
    }

    const payload = {
      notification: { 
        title: title, 
        body: message 
      },
      data: { 
        type: type, 
        screen: screen, 
        badgeCount: String(badgeCount),
        notificationId: data.notificationId || '',
        click_action: 'FLUTTER_NOTIFICATION_CLICK'
      },
      android: { 
        notification: { 
          notificationCount: badgeCount, 
          sound: 'default',
          channelId: 'dalabapay_channel'
        },
        priority: 'high'
      },
      apns: { 
        payload: { 
          aps: { 
            badge: badgeCount, 
            sound: 'default' 
          } 
        } 
      },
      token: user.fcmToken
    };

    const response = await admin.messaging().send(payload);
    console.log('✅ Notification sent to:', userId);
    return { success: true, response };
  } catch (error) {
    console.error('❌ FCM send error:', error.message);
    
    // Remove invalid token
    if (error.code === 'messaging/invalid-registration-token' ||
        error.code === 'messaging/registration-token-not-registered') {
      await User.findByIdAndUpdate(userId, { $unset: { fcmToken: 1 } });
      console.log('🗑️ Invalid FCM token removed for user:', userId);
    }
    
    return { success: false, error: error.message };
  }
}

module.exports = { sendPushNotification };
