// firebaseAdmin.js — COMPLETE REPLACEMENT
// FIX APPLIED: Replaced brittle "key repair" regex hacks with robust Base64 decoding, 
// exactly as proposed in the architectural solution.
console.log('🚨🚨🚨 FIREBASE ADMIN FILE LOADED - VERSION 2.0 (BASE64 FIX) 🚨🚨🚨');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');

// ==================== SAFE SERVICE ACCOUNT LOADER ====================
function loadServiceAccount() {
  // Priority:
  // 1. Base64 encoded env var (Render / production) - MOST RELIABLE
  // 2. Raw JSON env var (Fallback)
  // 3. Local file or mounted secret (Local development)

  // 1. Try Base64 encoded environment variable (Recommended for Render)
  const base64EnvVar = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (base64EnvVar) {
    try {
      console.log('🔍 [FIREBASE] Attempting to load from FIREBASE_SERVICE_ACCOUNT_BASE64');
      // Trim prevents issues if Render accidentally adds a trailing newline
      const decodedJson = Buffer.from(base64EnvVar.trim(), 'base64').toString('utf8');
      const parsed = JSON.parse(decodedJson);
      
      // Validate required fields to fail fast with a clear error
      if (!parsed.project_id || !parsed.private_key || !parsed.client_email) {
        throw new Error('Decoded JSON is missing required Firebase fields (project_id, private_key, client_email)');
      }
      
      console.log(`✅ [FIREBASE] Successfully loaded and decoded Base64 service account`);
      console.log(`   Project ID: ${parsed.project_id}`);
      return parsed;
    } catch (err) {
      console.error('❌ [FIREBASE] Failed to parse FIREBASE_SERVICE_ACCOUNT_BASE64:', err.message);
      // Continue to fallbacks if Base64 fails
    }
  }

  // 2. Try raw JSON environment variables (Legacy/Alternative)
  const envVarNames = [
    'FIREBASE_SERVICE_ACCOUNT',
    'FIREBASE_SERVICE_ACCOUNT_JSON',
    'GOOGLE_APPLICATION_CREDENTIALS_JSON',
  ];

  for (const varName of envVarNames) {
    const rawValue = process.env[varName];
    if (!rawValue) continue;

    try {
      console.log(`🔍 [FIREBASE] Trying env var: ${varName}`);
      let cleaned = rawValue.trim();
      
      // Remove surrounding quotes if accidentally added by CI/CD or hosting platform
      if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || (cleaned.startsWith("'") && cleaned.endsWith("'"))) {
        cleaned = cleaned.slice(1, -1);
      }
      
      const parsed = JSON.parse(cleaned);
      if (!parsed.project_id || !parsed.private_key || !parsed.client_email) {
        throw new Error('JSON is missing required Firebase fields');
      }
      
      console.log(`✅ [FIREBASE] Loaded service account from env var: ${varName}`);
      return parsed;
    } catch (err) {
      console.error(`❌ [FIREBASE] Failed to parse env var ${varName}:`, err.message);
    }
  }

  // 3. File fallback (Local development or mounted secrets)
  const fileCandidates = [
    '/etc/secrets/firebase-service-account.json',
    '/opt/render/project/src/firebase-service-account.json',
    path.join(__dirname, 'firebase-service-account.json'),
    path.join(process.cwd(), 'firebase-service-account.json'),
  ];

  for (const filePath of fileCandidates) {
    if (!fs.existsSync(filePath)) continue;
    try {
      const raw = fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, ''); // Remove BOM if present
      const parsed = JSON.parse(raw);
      console.log(`✅ [FIREBASE] Loaded service account from file: ${filePath}`);
      return parsed;
    } catch (err) {
      console.error(`❌ [FIREBASE] Failed to parse file ${filePath}:`, err.message);
    }
  }

  throw new Error(
    '❌ No valid Firebase service account found. ' +
    'Please set the FIREBASE_SERVICE_ACCOUNT_BASE64 environment variable or provide a valid firebase-service-account.json file.'
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
  console.error('   Push notifications will be DISABLED until credentials are fixed.');
  firebaseInitialized = false;
}

// ==================== EXPORTED FUNCTIONS ====================
/**
 * Send a push notification to a single user via FCM.
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
        // ignore cleanup errors
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

// ==================== EXPORTS ====================
module.exports = {
  sendPushNotification,
  sendPushNotificationToMultiple,
  admin,
  firebaseInitialized,
};
