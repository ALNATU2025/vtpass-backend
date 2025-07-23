// index.js (or server.js/app.js)

// Load environment variables from .env file for local development.
// On Render, environment variables are automatically provided, so this line
// will not load a local .env file but will ensure process.env is populated.
require('dotenv').config();
console.log("🛠️ .env loaded...");

const express = require('express');
const cors = require('cors');
const connectDB = require('./db'); // Assuming this connects to your MongoDB

// Import all route modules. Ensure these files exist in your 'routes' directory.
const authRoutes = require('./routes/authRoutes'); // This file was missing, now added.
const emailRoutes = require('./routes/emailRoutes');
const userRoutes = require('./routes/userRoutes');
const transactionRoutes = require('./routes/transactionRoutes');
const fundWalletRoutes = require('./routes/fundWalletRoutes');
const transferRoutes = require('./routes/transferRoutes');
const cabletvRoutes = require('./routes/cabletvRoutes');
const vtpassRoutes = require("./routes/vtpassRoutes");

// Connect to the database
connectDB();

// Initialize Express app
const app = express();

// Middleware
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Built-in middleware to parse JSON request bodies

// --- Route Definitions ---
// Mount your route handlers to specific API paths.
app.use('/api/auth', authRoutes); // Authentication routes (e.g., /api/auth/register, /api/auth/login)
app.use('/api/email', emailRoutes); // Email sending routes (e.g., /api/email/send-transaction-email)
app.use('/api/users', userRoutes); // User-related routes
app.use('/api/transactions', transactionRoutes); // Transaction-related routes
app.use('/api/fund-wallet', fundWalletRoutes); // Wallet funding routes
app.use('/api/transfer', transferRoutes); // Fund transfer routes
app.use('/api/cabletv', cabletvRoutes); // Cable TV payment routes
app.use("/api", vtpassRoutes); // VTpass general routes (e.g., /api/data, /api/airtime)

// Basic route for testing server status
app.get('/', (req, res) => {
    res.send('VTpass Backend Running');
});

// Define the port the server will listen on.
// It prioritizes the PORT environment variable (set by Render) or defaults to 5000.
const PORT = process.env.PORT || 5000;

// Start the server
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});

// Optional: Basic error handling middleware (add more sophisticated handling as needed)
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});
