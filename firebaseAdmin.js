// ==================== SAFE SERVICE ACCOUNT LOADER ====================
function loadServiceAccount() {
  // Priority order:
  // 1. Environment variable (YOUR CURRENT SETUP)
  // 2. Secret File at /etc/secrets/
  // 3. Local file in project root (development)

  // ============================================================
  // METHOD 1: READ FROM ENVIRONMENT VARIABLE (your setup)
  // ============================================================
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
      console.log(`🔍 Trying env var: ${varName} (length: ${rawValue.length})`);

      // Strip any outer quotes
      let cleaned = rawValue.trim();
      if (cleaned.startsWith('"') && cleaned.endsWith('"')) {
        cleaned = cleaned.slice(1, -1);
      }
      if (cleaned.startsWith("'") && cleaned.endsWith("'")) {
        cleaned = cleaned.slice(1, -1);
      }

      const parsed = JSON.parse(cleaned);

      // ============================================================
      // 🔥 NUCLEAR KEY REPAIR — rebuilds the private_key from scratch
      // Handles ALL possible corruption from env var storage
      // ============================================================
      if (parsed.private_key) {
        const originalKey = parsed.private_key;

        // Step 1: Extract ONLY the base64 body between the PEM headers
        // This regex works whether the key has real newlines, \n, \\n, or CRLF
        const pemMatch = originalKey.match(
          /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/
        );

        if (!pemMatch) {
          throw new Error('private_key is missing PEM headers (BEGIN/END)');
        }

        // Step 2: Get the base64 body, remove EVERYTHING that isn't base64
        let base64Body = pemMatch[1]
          .replace(/\\n/g, '')   // remove literal \n (2 chars)
          .replace(/\\r/g, '')   // remove literal \r (2 chars)
          .replace(/\s+/g, '')   // remove ALL whitespace (spaces, tabs, real newlines)
          .trim();

        if (base64Body.length < 100) {
          throw new Error(`base64 body too short (${base64Body.length} chars)`);
        }

        // Step 3: Re-chunk into 64-character lines (standard PEM format)
        const chunks = [];
        for (let i = 0; i < base64Body.length; i += 64) {
          chunks.push(base64Body.substring(i, i + 64));
        }

        // Step 4: Rebuild the PEM with real newlines
        const rebuiltKey =
          '-----BEGIN PRIVATE KEY-----\n' +
          chunks.join('\n') +
          '\n-----END PRIVATE KEY-----\n';

        parsed.private_key = rebuiltKey;

        console.log(`🔧 private_key REBUILT from scratch:`);
        console.log(`   Original length: ${originalKey.length} chars`);
        console.log(`   Base64 body length: ${base64Body.length} chars`);
        console.log(`   Final PEM length: ${rebuiltKey.length} chars`);
        console.log(`   Final line count: ${rebuiltKey.split('\n').length} lines`);
      }
      // ============================================================

      console.log(`✅ Loaded Firebase service account from env var: ${varName}`);
      console.log(`   Project ID: ${parsed.project_id}`);
      console.log(`   Client Email: ${parsed.client_email}`);
      console.log(`   Private Key ID: ${parsed.private_key_id?.substring(0, 12)}...`);

      if (parsed.project_id !== 'dalabapay-937de') {
        console.warn(`⚠️ WARNING: project_id is "${parsed.project_id}" but expected "dalabapay-937de"`);
      }

      return parsed;
    } catch (err) {
      console.error(`❌ Failed to parse env var ${varName}:`, err.message);
    }
  }

  // ============================================================
  // METHOD 2: SECRET FILE
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
        const pemMatch = parsed.private_key.match(
          /-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/
        );
        if (!pemMatch) throw new Error('private_key is missing PEM headers');

        const base64Body = pemMatch[1]
          .replace(/\\n/g, '')
          .replace(/\\r/g, '')
          .replace(/\s+/g, '')
          .trim();

        const chunks = [];
        for (let i = 0; i < base64Body.length; i += 64) {
          chunks.push(base64Body.substring(i, i + 64));
        }

        parsed.private_key =
          '-----BEGIN PRIVATE KEY-----\n' +
          chunks.join('\n') +
          '\n-----END PRIVATE KEY-----\n';

        console.log(`🔧 private_key REBUILT from file (${chunks.length} lines)`);
      }

      console.log(`✅ Loaded Firebase service account from file: ${filePath}`);
      return parsed;
    } catch (err) {
      console.error(`❌ Failed to parse file ${filePath}:`, err.message);
    }
  }

  throw new Error(
    '❌ No valid Firebase service account found. ' +
    'Set the "firebase-service-account.json" environment variable on Render.'
  );
}
