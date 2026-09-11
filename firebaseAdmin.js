// firebaseAdmin.js — COMPLETE REPLACEMENT
// This file initializes Firebase Admin SDK and exports a WORKING sendPushNotification function.

const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');

// ==================== SAFE SERVICE ACCOUNT LOADER ====================
function loadServiceAccount() {
  // Priority:
  // 1. Env var (Render / production)
  // 2. Secret file at /etc/secrets/
  // 3. Local file

  const envVarNames = [
    'firebase-service-account.json',
    'FIREBASE_SERVICE_ACCOUNT',
    'FIREBASE_SERVICE_ACCOUNT_JSON',
    'FIREBASE_ADMIN_CREDENTIALS',
    'FIREBASE_CREDENTIALS',
    'GOOGLE_APPLICATION_CREDENTIALS_JSON',
    'SERVICE_ACCOUNT_JSON',
  ];

  for (const varName of envVarNames) {
    const rawValue = process.env[varName];
    if (!rawValue) continue;

    try {
      console.log(`🔍 [FIREBASE] Trying env var: ${varName} (length: ${rawValue.length})`);

      let cleaned = rawValue.trim();
      if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
        cleaned = cleaned.slice(1, -1);
      }
      if (cleaned.startsWith("'") && cleaned.endsWith("'")) {
        cleaned = cleaned.slice(1, -1);
      }

      const parsed = JSON.parse(cleaned);

      // 🔥 NUCLEAR KEY REPAIR — rebuild private_key from scratch
      if (parsed.private_key) {
        const originalKey = parsed.private_key;
        const pemMatch = originalKey.match(
          /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/
        );

        if (!pemMatch) {
          throw new Error('private_key is missing PEM headers (BEGIN/END)');
        }

        let base64Body = pemMatch[1]
          .replace(/\\n/g, '')
          .replace(/\\r/g, '')
          .replace(/\s+/g, '')
          .trim();

        if (base64Body.length < 100) {
          throw new Error(`base64 body too short (${base64Body.length} chars)`);
        }

        const chunks = [];
        for (let i = 0; i < base64Body.length; i += 64) {
          chunks.push(base64Body.substring(i, i + 64));
        }

        parsed.private_key =
          '-----BEGIN PRIVATE KEY-----\n' +
          chunks.join('\n') +
          '\n-----END PRIVATE KEY-----\n';

        console.log(`🔧 [FIREBASE] private_key REBUILT (${chunks.length} lines)`);
      }

      console.log(`✅ [FIREBASE] Loaded service account from env var: ${varName}`);
      console.log(`   Project ID: ${parsed.project_id}`);
      console.log(`   Client Email: ${parsed.client_email}`);

      return parsed;
    } catch (err) {
      console.error(`❌ [FIREBASE] Failed to parse env var ${varName}:`, err.message);
    }
  }

  // File fallback
  const fileCandidates = [
    '/etc/secrets/firebase-service-account.json',
    '/opt/render/project/src/firebase-service-account.json',
    path.join(__dirname, 'firebase-service-account.json'),
  ];

  for (const filePath of fileCandidates) {
    if (!fs.existsSync(filePath)) continue;
    try {
      const raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
      const parsed = JSON.parse(raw);
      console.log(`✅ [FIREBASE] Loaded service account from file: ${filePath}`);
      return parsed;
    } catch (err) {
      console.error(`❌ [FIREBASE] Failed to parse file ${filePath}:`, err.message);
    }
  }

  throw new Error(
    '❌ No valid Firebase service account found. ' +
    'Set the "firebase-service-account.json" environment variable.'
  );
}

// ==================== INITIALIZE FIREBASE ====================
let firebaseInitialized = false;

try {
  if (!admin.apps.length) {
    const serviceAccount = loadServiceAccount();
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    firebaseInitialized = true;
    console.log('✅ [FIREBASE] Admin SDK initialized successfully');
  } else {
    firebaseInitialized = true;
    console.log('ℹ️ [FIREBASE] Admin SDK already initialized');
  }
} catch (error) {
  console.error('❌ [FIREBASE] Initialization FAILED:', error.message);
  console.error('   Push notifications will be DISABLED.');
  firebaseInitialized = false;
}

// ==================== ✅ THE EXPORTED FUNCTION (this is what index.js needs) ====================
/**
 * Send a push notification to a single user via FCM.
 *
 * @param {Object} params
 * @param {string|ObjectId} params.userId - Recipient user id (used to look up fcmToken)
 * @param {string} params.title - Notification title
 * @param {string} params.message - Notification body
 * @param {string} [params.type] - Notification type (for metadata)
 * @param {string} [params.screen] - Screen to navigate to on tap
 * @param {number} [params.badgeCount] - Badge count
 * @param {Object} [params.data] - Extra data payload
 * @returns {Promise<{success: boolean, messageId?: string, error?: string}>}
 */
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
    if (!firebaseInitialized) {
      return { success: false, error: 'Firebase not initialized' };
    }

    if (!userId) {
      return { success: false, error: 'userId is required' };
    }

    // Lazy-require User to avoid circular dependency issues
    const User = require('./models/User');
    const user = await User.findById(userId).select('fcmToken fullName email');

    if (!user) {
      return { success: false, error: 'User not found' };
    }

    if (!user.fcmToken) {
      return { success: false, error: 'User has no FCM token' };
    }

    const stringData = {};
    Object.keys(data || {}).forEach((key) => {
      if (data[key] !== undefined && data[key] !== null) {
        stringData[key] = String(data[key]);
      }
    });

    const messagePayload = {
      token: user.fcmToken,
      notification: {
        title: title || 'DalabaPay',
        body: message || '',
      },
      data: {
        type: String(type || 'general'),
        screen: String(screen || 'notifications'),
        title: String(title || ''),
        message: String(message || ''),
        ...stringData,
      },
      android: {
        priority: 'high',
        notification: {
          channelId: 'high_importance_channel',
          sound: 'default',
          clickAction: 'FLUTTER_NOTIFICATION_CLICK',
        },
      },
      apns: {
        payload: {
          aps: {
            sound: 'default',
            badge: badgeCount || 0,
            contentAvailable: true,
          },
        },
      },
    };

    const response = await admin.messaging().send(messagePayload);
    console.log(`📱 [FCM] Push sent to ${user.email}: ${response}`);

    return { success: true, messageId: response };
  } catch (error) {
    console.error('❌ [FCM] sendPushNotification error:', error.message);

    // Clean up invalid tokens
    if (
      error.code === 'messaging/invalid-registration-token' ||
      error.code === 'messaging/registration-token-not-registered'
    ) {
      try {
        const User = require('./models/User');
        await User.findByIdAndUpdate(userId, { fcmToken: null });
        console.log(`🧹 [FCM] Cleared invalid FCM token for user ${userId}`);
      } catch (e) {
        // ignore
      }
    }

    return { success: false, error: error.message };
  }
}

/**
 * Send to multiple users at once (bulk).
 */
async function sendPushNotificationToMultiple({
  userIds,
  title,
  message,
  type = 'general',
  screen = 'notifications',
  data = {},
}) {
  const results = [];
  for (const userId of userIds) {
    const result = await sendPushNotification({
      userId,
      title,
      message,
      type,
      screen,
      data,
    });
    results.push({ userId, ...result });
  }
  return results;
}

// ==================== ✅ EXPORTS — MUST BE EXACTLY LIKE THIS ====================
module.exports = {
  sendPushNotification,
  sendPushNotificationToMultiple,
  admin,
  firebaseInitialized,
};
