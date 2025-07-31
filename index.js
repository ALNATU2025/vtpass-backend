// index.js (or server.js/app.js)

require('dotenv').config();
console.log("🛠️ .env loaded...");

const express = require('express');
const cors = require('cors');
const http = require('http');
const connectDB = require('./db');

// --- Import all route modules ---
const emailRoutes = require('./routes/emailRoutes');
const userRoutes = require('./routes/userRoutes');
const transactionRoutes = require('./routes/transactionRoutes');
const fundWalletRoutes = require('./routes/fundWalletRoutes');
const transferRoutes = require('./routes/transferRoutes');
const vtpassRoutes = require("./routes/vtpassRoutes");
const appSettingsRoutes = require('./routes/appSettingsRoutes');
const beneficiaryRoutes = require('./routes/beneficiaryRoutes');
const notificationRoutes = require('./routes/notificationRoutes');
const paystackController = require('./controllers/paystackController');

// --- Connect to the database ---
connectDB();

// --- Initialize Express app ---
const app = express();
const httpServer = http.createServer(app);

// Middleware
app.use(cors());
app.use(express.json());

// Main router for all API endpoints
const apiRouter = express.Router();

// --- Mount all routes on the API router ---
apiRouter.use('/email', emailRoutes);
apiRouter.use('/users', userRoutes);
apiRouter.use('/transactions', transactionRoutes);
apiRouter.use('/fund-wallet', fundWalletRoutes);
apiRouter.use('/transfer', transferRoutes);
apiRouter.use('/vtpass', vtpassRoutes); // All VTpass endpoints are now under /api/vtpass
apiRouter.use('/settings', appSettingsRoutes);
apiRouter.use('/beneficiaries', beneficiaryRoutes);
apiRouter.use('/notifications', notificationRoutes);
apiRouter.post('/paystack-webhook', paystackController.handleWebhook);

// Mount the main API router at /api
app.use('/api', apiRouter);

// Root route
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
