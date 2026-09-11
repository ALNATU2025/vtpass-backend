// vtpass-backend/firebaseAdmin.js
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const User = require('./models/User');

// ==================== SAFE SERVICE ACCOUNT LOADER ====================
function loadServiceAccount() {
  // Priority order:
  // 1. Render Secret File (production)
  // 2. Local file in project root (development)
  // 3. Environment variable fallback

  const candidates = [
    '/opt/render/project/src/firebase-service-account.json', // Render Secret File
    path.join(__dirname, 'firebase-service-account.json'),   // Local dev
    path.join(__dirname, 'dalabapay-937de-firebase-adminsdk-fbsvc-4deeb3f82b.json'), // Legacy name
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        const raw = fs.readFileSync(candidate, 'utf8');
        const parsed = JSON.parse(raw);
        console.log(`✅ Loaded Firebase service account from: ${candidate}`);
        console.log(`   Project ID: ${parsed.project_id}`);
        console.log(`   Client Email: ${parsed.client_email}`);
        console.log(`   Private Key ID: ${parsed.private_key_id?.substring(0, 12)}...`);

        // Sanity check the private key
        if (!parsed.private_key || !parsed.private_key.includes('BEGIN PRIVATE KEY')) {
          throw new Error('private_key field is missing or malformed in service account JSON');
        }

        return parsed;
      } catch (err) {
        console.error(`❌ Failed to parse service account at ${candidate}:`, err.message);
      }
    }
  }

  // Last resort: environment variable
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const parsed = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      console.log('✅ Loaded Firebase service account from environment variable');
      return parsed;
    } catch (err) {
      console.error('❌ Failed to parse FIREBASE_SERVICE_ACCOUNT env var:', err.message);
    }
  }

  throw new Error(
    '❌ No valid Firebase service account found. ' +
    'Add a Secret File named "firebase-service-account.json" in Render, ' +
    'or place the JSON file in the project root for local development.'
  );
}

// ==================== INITIALIZE FIREBASE (ONCE ONLY) ====================
if (admin.apps.length === 0) {
  try {
    const serviceAccount = loadServiceAccount();
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('✅ Firebase Admin initialized successfully');
  } catch (err) {
    console.error('❌ Firebase Admin initialization FAILED:', err.message);
    // Don't crash the whole server — just log it. Push notifications will fail gracefully.
  }
} else {
  console.log('ℹ️ Firebase Admin already initialized — skipping re-init');
}

// ==================== SEND PUSH NOTIFICATION ====================
async function sendPushNotification({
  userId,
  title,
  message,
  type = 'general',
  screen = 'notifications',
  badgeCount = 0,
  data = {},
}) {
  try {
    // Guard: Firebase might not be initialized
    if (admin.apps.length === 0) {
      console.log('⚠️ Firebase not initialized — skipping push');
      return { success: false, error: 'Firebase not initialized' };
    }

    const user = await User.findById(userId).select('fcmToken email fullName');

    if (!user || !user.fcmToken) {
      console.log('⚠️ No FCM token for user:', userId);
      return { success: false, error: 'No FCM token' };
    }

    const payload = {
      notification: { title, body: message },
      data: {
        type: String(type),
        screen: String(screen),
        badgeCount: String(badgeCount),
        notificationId: String(data.notificationId || ''),
        click_action: 'FLUTTER_NOTIFICATION_CLICK',
      },
      android: {
        priority: 'high',
        notification: {
          notificationCount: badgeCount,
          sound: 'default',
          channelId: 'dalabapay_channel', // must match Flutter channel
        },
      },
      apns: {
        payload: { aps: { badge: badgeCount, sound: 'default' } },
      },
      token: user.fcmToken,
    };

    const response = await admin.messaging().send(payload);
    console.log('✅ Notification sent to:', user.email, '| Response:', response);
    return { success: true, response };
  } catch (error) {
    console.error('❌ FCM send error:', error.message, '| Code:', error.code);

    // Clean up invalid tokens
    if (
      error.code === 'messaging/invalid-registration-token' ||
      error.code === 'messaging/registration-token-not-registered'
    ) {
      await User.findByIdAndUpdate(userId, { $unset: { fcmToken: 1 } });
      console.log('🗑️ Invalid FCM token removed for user:', userId);
    }

    return { success: false, error: error.message, code: error.code };
  }
}

module.exports = { sendPushNotification };
