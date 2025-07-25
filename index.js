// index.js (or server.js/app.js)

require('dotenv').config();
console.log("🛠️ .env loaded...");

const express = require('express');
const cors = require('cors');
const connectDB = require('./db');

// Import all route modules.
const authRoutes = require('./routes/authRoutes');
const emailRoutes = require('./routes/emailRoutes');
const userRoutes = require('./routes/userRoutes');
const transactionRoutes = require('./routes/transactionRoutes');
const fundWalletRoutes = require('./routes/fundWalletRoutes');
const transferRoutes = require('./routes/transferRoutes');
const cabletvRoutes = require('./routes/cabletvRoutes');
const vtpassRoutes = require("./routes/vtpassRoutes");
const appSettingsRoutes = require('./routes/appSettingsRoutes');
const beneficiaryRoutes = require('./routes/beneficiaryRoutes');
const notificationRoutes = require('./routes/notificationRoutes'); // <<< NEW: Import Notification Routes

// Connect to the database
connectDB();

// Initialize Express app
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// --- Route Definitions ---
app.use('/api/auth', authRoutes);
app.use('/api/email', emailRoutes);
app.use('/api/users', userRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/fund-wallet', fundWalletRoutes);
app.use('/api/transfer', transferRoutes);
app.use('/api/cabletv', cabletvRoutes);
app.use("/api", vtpassRoutes);
app.use('/api/settings', appSettingsRoutes);
app.use('/api/beneficiaries', beneficiaryRoutes);
app.use('/api/notifications', notificationRoutes); // <<< NEW: Mount Notification Routes

// Basic route for testing server status
app.get('/', (req, res) => {
    res.send('VTpass Backend Running');
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});
