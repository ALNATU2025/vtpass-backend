// index.js (or server.js/app.js)

require('dotenv').config();
console.log("🛠️ .env loaded...");
// console.log("📦 MONGO_URI:", process.env.MONGO_URI); // ⚠️ Suggestion: Comment out or remove this line in production for security

const express = require('express');
const cors = require('cors');
// const bodyParser = require('body-parser'); // ⚠️ Suggestion: body-parser is often not needed for JSON parsing with modern Express
const connectDB = require('./db'); // Assuming this connects to your MongoDB
const authRoutes = require('./routes/authRoutes');
const emailRoutes = require('./routes/emailRoutes');
const userRoutes = require('./routes/userRoutes'); // Explicitly import other routes for clarity
const transactionRoutes = require('./routes/transactionRoutes');
const fundWalletRoutes = require('./routes/fundWalletRoutes');
const transferRoutes = require('./routes/transferRoutes');
const cabletvRoutes = require('./routes/cabletvRoutes');
const vtpassRoutes = require("./routes/vtpassRoutes"); // Assuming this is your main VTpass route

// Connect to the database
connectDB();

// Initialize Express app - ✅ ONLY ONE DECLARATION
const app = express();

// Middleware
app.use(cors());
// ✅ Use express.json() for parsing JSON bodies. It's built-in and preferred over body-parser for JSON.
app.use(express.json());
// If you still need body-parser for other types (e.g., URL-encoded), you can keep:
// app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: true }));


// ✅ All routes
app.use('/api/users', userRoutes); // Using the imported variable
app.use('/api/transactions', transactionRoutes); // Using the imported variable
app.use('/api/fund-wallet', fundWalletRoutes); // Using the imported variable
app.use('/api/transfer', transferRoutes); // Using the imported variable
app.use('/api/cabletv', cabletvRoutes); // Using the imported variable
app.use("/api", vtpassRoutes); // Using the imported variable
app.use('/api/auth', authRoutes); // Using the imported variable
app.use('/api/email', emailRoutes); // Using the imported variable

// Basic route for testing server status
app.get('/', (req, res) => {
  res.send('VTpass Backend Running');
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
