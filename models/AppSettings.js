// models/AppSettings.js
const mongoose = require('mongoose');

const appSettingsSchema = new mongoose.Schema({
  // Service Availability Toggles
  isAirtimeEnabled: { type: Boolean, default: true },
  isDataEnabled: { type: Boolean, default: true },
  isCableTvEnabled: { type: Boolean, default: true },
  isElectricityEnabled: { type: Boolean, default: true },
  isTransferEnabled: { type: Boolean, default: true },

  // Commission/Fee Management
  airtimeCommissionRate: { type: Number, default: 1.5 }, // Percentage
  dataCommissionRate: { type: Number, default: 1.0 },    // Percentage
  transferFee: { type: Number, default: 50.0 },          // Fixed amount or percentage value
  isTransferFeePercentage: { type: Boolean, default: false }, // True if transferFee is a percentage

  // User Management Defaults
  newUserDefaultWalletBalance: { type: Number, default: 0.0 },
  minTransactionAmount: { type: Number, default: 100.0 },
  maxTransactionAmount: { type: Number, default: 100000.0 },

  // System Settings
  isMaintenanceMode: { type: Boolean, default: false },

  // To ensure only one settings document exists
  singletonId: { type: String, required: true, unique: true, default: 'app_settings_singleton' },
}, { timestamps: true });

// Ensure only one document can exist for app settings
appSettingsSchema.index({ singletonId: 1 }, { unique: true });

module.exports = mongoose.models.AppSettings || mongoose.model('AppSettings', appSettingsSchema);
