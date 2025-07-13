const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const User = require('./models/User');
const connectDB = require('./db');

dotenv.config();
connectDB();

const seedUsers = async () => {
  try {
    await User.deleteMany();

    const users = [
      {
        fullName: 'Test User 1',
        email: 'user1@example.com',
        phone: '08000000001',
        password: await bcrypt.hash('password123', 10)
      },
      {
        fullName: 'Test User 2',
        email: 'user2@example.com',
        phone: '08000000002',
        password: await bcrypt.hash('password123', 10)
      }
    ];

    await User.insertMany(users);
    console.log('✅ Seed data inserted successfully!');
    process.exit();
  } catch (error) {
    console.error('❌ Error seeding users:', error.message);
    process.exit(1);
  }
};

seedUsers();
