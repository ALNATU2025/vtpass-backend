require('dotenv').config();
console.log("🛠️ .env loaded...");
console.log("📦 MONGO_URI:", process.env.MONGO_URI);


const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const connectDB = require('./db');

connectDB();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ✅ All routes
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/transactions', require('./routes/transactionRoutes'));
app.use('/api/fund-wallet', require('./routes/fundWalletRoutes'));
app.use('/api/transfer', require('./routes/transferRoutes'));
app.use('/api/cabletv', require('./routes/cabletvRoutes'));

app.get('/', (req, res) => {
  res.send('VTpass Backend Running');
});

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
