// index.js (or server.js/app.js)

require('dotenv').config();
console.log("🛠️ .env loaded...");

const express = require('express');
const cors = require('cors');
const http = require('http'); // Import http module
const admin = require('firebase-admin'); // Import firebase-admin

const connectDB = require('./db');
const { setupChatService, initializeFirebase } = require('./services/chatService'); // Import chatService

// --- Import all route modules ---
let emailRoutes, userRoutes, transactionRoutes, fundWalletRoutes, transferRoutes,
    cabletvRoutes, vtpassRoutes, appSettingsRoutes, beneficiaryRoutes,
    notificationRoutes, airtimeRoutes, dataRoutes;

try {
    emailRoutes = require('./routes/emailRoutes');
    console.log('✅ routes/emailRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/emailRoutes:', e.message); }

try {
    userRoutes = require('./routes/userRoutes');
    console.log('✅ routes/userRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/userRoutes:', e.message); }

try {
    transactionRoutes = require('./routes/transactionRoutes');
    console.log('✅ routes/transactionRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/transactionRoutes:', e.message); }

try {
    fundWalletRoutes = require('./routes/fundWalletRoutes');
    console.log('✅ routes/fundWalletRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/fundWalletRoutes:', e.message); }

try {
    transferRoutes = require('./routes/transferRoutes');
    console.log('✅ routes/transferRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/transferRoutes:', e.message); }

try {
    cabletvRoutes = require('./routes/cabletvRoutes');
    console.log('✅ routes/cabletvRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/cabletvRoutes:', e.message); }

try {
    vtpassRoutes = require("./routes/vtpassRoutes");
    console.log('✅ routes/vtpassRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/vtpassRoutes:', e.message); }

try {
    appSettingsRoutes = require('./routes/appSettingsRoutes');
    console.log('✅ routes/appSettingsRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/appSettingsRoutes:', e.message); }

try {
    beneficiaryRoutes = require('./routes/beneficiaryRoutes');
    console.log('✅ routes/beneficiaryRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/beneficiaryRoutes:', e.message); }

try {
    notificationRoutes = require('./routes/notificationRoutes');
    console.log('✅ routes/notificationRoutes loaded.');
} catch (e) { console.error('❌ Failed to load routes/notificationRoutes:', e.message); }

try {
    airtimeRoutes = require('./routes/airtime');
    console.log('✅ routes/airtime loaded.');
} catch (e) { console.error('❌ Failed to load routes/airtime:', e.message); }

try {
    dataRoutes = require('./routes/data');
    console.log('✅ routes/data loaded.');
} catch (e) { console.error('❌ Failed to load routes/data:', e.message); }


const paystackController = require('./controllers/paystackController');

// --- Firebase Admin SDK Initialization ---
try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    
    // IMPORTANT CHANGE: Removed storageBucket from initialization
    // Firebase Storage requires a project to be on the Blaze (pay-as-you-go) plan.
    // If you need Firebase Storage, please upgrade your Firebase project's billing plan.
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        // storageBucket: process.env.FIREBASE_STORAGE_BUCKET_URL // <-- This line is now commented out/removed
    });
    console.log('✅ Firebase Admin SDK initialized successfully (without Storage bucket).');

    // Pass null for the storage bucket if it's not configured or not needed
    // This assumes initializeFirebase in chatService.js can handle a null/undefined bucket.
    initializeFirebase(admin.firestore(), null); // Pass null for storage bucket

} catch (error) {
    console.error('❌ Failed to initialize Firebase Admin SDK:', error);
    console.error('Please ensure FIREBASE_SERVICE_ACCOUNT environment variable is set and valid JSON.');
    process.exit(1);
}
// --- End Firebase Admin SDK Initialization ---


// Connect to the database
connectDB();

// Initialize Express app
const app = express();
const httpServer = http.createServer(app); // Create HTTP server for Socket.IO

// Middleware
app.use(cors());
app.use(express.json());

// --- Route Definitions ---
if (emailRoutes) app.use('/api/email', emailRoutes);
if (userRoutes) app.use('/api/users', userRoutes);
if (transactionRoutes) app.use('/api/transactions', transactionRoutes);
if (fundWalletRoutes) app.use('/api/fund-wallet', fundWalletRoutes);
if (transferRoutes) app.use('/api/transfer', transferRoutes);
if (cabletvRoutes) app.use('/api/cabletv', cabletvRoutes);
if (vtpassRoutes) app.use("/api", vtpassRoutes); // Your existing VTpass router
if (appSettingsRoutes) app.use('/api/settings', appSettingsRoutes);
if (beneficiaryRoutes) app.use('/api/beneficiaries', beneficiaryRoutes);
if (notificationRoutes) app.use('/api/notifications', notificationRoutes);
app.post('/api/paystack-webhook', paystackController.handleWebhook);

// NEW: Mount the new airtime and data routes separately
if (airtimeRoutes) app.use('/api/airtime', airtimeRoutes);
if (dataRoutes) app.use('/api/data', dataRoutes);

app.get('/', (req, res) => {
    res.send('DalabaPay Backend Running');
});

// Generic error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// --- Setup Chat Service (Socket.IO) ---
setupChatService(httpServer);
// --- End Setup Chat Service ---

const PORT = process.env.PORT || 5000;

httpServer.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
