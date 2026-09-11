// vtpass-backend/firebaseAdmin.js
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');
const User = require('./models/User');

// ==================== SAFE SERVICE ACCOUNT LOADER ====================
function loadServiceAccount() {
  // Priority order:
  // 1. Environment variable (YOUR CURRENT SETUP) — matches how VTPASS_API_KEY is stored
  // 2. Secret File at /etc/secrets/ (alternative)
  // 3. Local file in project root (development)

  // ============================================================
  // METHOD 1: READ FROM ENVIRONMENT VARIABLE (your setup)
  // ============================================================
  // Try several common env var names — whatever you named it on Render
  const envVarNames = [
    'firebase-service-account.json',     // ← Render UI often names it this (with .json)
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
      console.log(`🔍 Trying env var: ${varName} (length: ${rawValue.length})`);

      // Sometimes the value is wrapped in outer quotes — strip them
      let cleaned = rawValue.trim();
      if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
        cleaned = cleaned.slice(1, -1);
      }
      if (cleaned.startsWith("'") && cleaned.endsWith("'")) {
        cleaned = cleaned.slice(1, -1);
      }

      const parsed = JSON.parse(cleaned);

      // ==================== KEY NORMALIZATION ====================
      if (parsed.private_key) {
        let pk = parsed.private_key;

        // Fix double-escaped \\n (from shell/JSON-in-JSON wrapping)
        if (pk.includes('\\n')) {
          console.log('🔧 Fixing double-escaped \\\\n in private_key');
          pk = pk.replace(/\\n/g, '\n');
        }

        // Normalize CRLF to LF (Windows Git can inject \r)
        pk = pk.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

        // Collapse any accidental triple newlines
        pk = pk.replace(/\n{3,}/g, '\n\n');

        // Sanity check
        if (!pk.startsWith('-----BEGIN PRIVATE KEY-----')) {
          throw new Error('private_key does not start with BEGIN PRIVATE KEY');
        }
        if (!pk.trim().endsWith('-----END PRIVATE KEY-----')) {
          throw new Error('private_key does not end with END PRIVATE KEY');
        }

        const lineCount = pk.split('\n').length;
        if (lineCount < 20) {
          throw new Error(`private_key too short (only ${lineCount} lines)`);
        }

        parsed.private_key = pk;
        console.log(`🔧 private_key normalized: ${lineCount} lines`);
      }
      // ============================================================

      console.log(`✅ Loaded Firebase service account from env var: ${varName}`);
      console.log(`   Project ID: ${parsed.project_id}`);
      console.log(`   Client Email: ${parsed.client_email}`);
      console.log(`   Private Key ID: ${parsed.private_key_id?.substring(0, 12)}...`);

      // Warn if project_id doesn't match expected
      if (parsed.project_id !== 'dalabapay-937de') {
        console.warn(`⚠️ WARNING: project_id is "${parsed.project_id}" but expected "dalabapay-937de"`);
      }

      return parsed;
    } catch (err) {
      console.error(`❌ Failed to parse env var ${varName}:`, err.message);
      // Continue to next candidate
    }
  }

  // ============================================================
  // METHOD 2: SECRET FILE (alternative if you migrate later)
  // ============================================================
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

      if (parsed.private_key) {
        let pk = parsed.private_key;
        if (pk.includes('\\n')) pk = pk.replace(/\\n/g, '\n');
        pk = pk.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        if (!pk.startsWith('-----BEGIN PRIVATE KEY-----')) {
          throw new Error('private_key malformed');
        }
        parsed.private_key = pk;
      }

      console.log(`✅ Loaded Firebase service account from file: ${filePath}`);
      return parsed;
    } catch (err) {
      console.error(`❌ Failed to parse file ${filePath}:`, err.message);
    }
  }

  // Nothing worked
  throw new Error(
    '❌ No valid Firebase service account found. ' +
    'Set the "firebase-service-account.json" environment variable on Render ' +
    '(paste the raw JSON as the value).'
  );
}

// ==================== INITIALIZE FIREBASE (ONCE ONLY) ====================
console.log('🔥 ========== FIREBASE ADMIN STARTUP ==========');
console.log(`   admin.apps.length BEFORE init: ${admin.apps.length}`);
console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'undefined'}`);

if (admin.apps.length === 0) {
  try {
    const serviceAccount = loadServiceAccount();
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('✅ Firebase Admin initialized successfully');
    console.log(`   admin.apps.length AFTER init: ${admin.apps.length}`);
  } catch (err) {
    console.error('❌❌❌ FIREBASE ADMIN INITIALIZATION FAILED ❌❌❌');
    console.error('   Error:', err.message);
    console.error('   Stack:', err.stack);
    // Do NOT throw — let the server keep running
  }
} else {
  console.log('ℹ️ Firebase Admin already initialized — skipping re-init');
}
console.log('🔥 ============================================');

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
          channelId: 'dalabapay_channel',
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
