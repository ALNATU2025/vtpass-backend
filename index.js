// index.js (or server.js/app.js)

require('dotenv').config();
console.log("🛠️ .env loaded...");

const express = require('express');
const cors = require('cors');
const http = require('http'); // Import http module

const connectDB = require('./db');

// --- Import all route modules ---
let emailRoutes, userRoutes, transactionRoutes, fundWalletRoutes, transferRoutes,
    vtpassRoutes, appSettingsRoutes, beneficiaryRoutes, notificationRoutes;

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
    // Only load the single, comprehensive vtpassRoutes file
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

// Note: The redundant routes (cabletv, airtime, data) have been removed
// as they are now all handled by the single vtpassRoutes file.

const paystackController = require('./controllers/paystackController');

// --- Connect to the database ---
connectDB();

// --- Initialize Express app ---
const app = express();
const httpServer = http.createServer(app);

// Middleware
app.use(cors());
app.use(express.json());

// --- Route Definitions ---
if (emailRoutes) app.use('/api/email', emailRoutes);
if (userRoutes) app.use('/api/users', userRoutes);
if (transactionRoutes) app.use('/api/transactions', transactionRoutes);
if (fundWalletRoutes) app.use('/api/fund-wallet', fundWalletRoutes);
if (transferRoutes) app.use('/api/transfer', transferRoutes);
if (vtpassRoutes) app.use("/api/vtpass", vtpassRoutes); // Updated mount path
if (appSettingsRoutes) app.use('/api/settings', appSettingsRoutes);
if (beneficiaryRoutes) app.use('/api/beneficiaries', beneficiaryRoutes);
if (notificationRoutes) app.use('/api/notifications', notificationRoutes);
app.post('/api/paystack-webhook', paystackController.handleWebhook);


app.get('/', (req, res) => {
    res.send('DalabaPay Backend Running');
});

// Generic error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});


const PORT = process.env.PORT || 5000;

httpServer.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
