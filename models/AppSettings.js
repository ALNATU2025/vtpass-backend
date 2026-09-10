// models/AppSettings.js
const mongoose = require('mongoose');

const appSettingsSchema = new mongoose.Schema({
  // ==================== SYSTEM SETTINGS ====================
  isMaintenanceMode: { type: Boolean, default: false },
  maintenanceMessage: { type: String, default: '' },
  appVersion: { type: String, default: '1.0.0' },

  // ==================== SERVICE AVAILABILITY TOGGLES ====================
  isAirtimeEnabled: { type: Boolean, default: true },
  isDataEnabled: { type: Boolean, default: true },
  isCableTvEnabled: { type: Boolean, default: true },
  isElectricityEnabled: { type: Boolean, default: true },
  isTransferEnabled: { type: Boolean, default: true },
  isInternationalAirtimeEnabled: { type: Boolean, default: true },
  isEducationEnabled: { type: Boolean, default: true },
  isInsuranceEnabled: { type: Boolean, default: true },

  // ==================== COMMISSION/FEE MANAGEMENT ====================
  airtimeCommissionRate: { type: Number, default: 0.005 },
  dataCommissionRate: { type: Number, default: 0.005 },
  electricityCommissionRate: { type: Number, default: 0.004 },
  cableTvCommissionRate: { type: Number, default: 0.005 },
  educationCommissionRate: { type: Number, default: 0.005 },
  insuranceCommissionRate: { type: Number, default: 0.004 },
  commissionRate: { type: Number, default: 0.003 },
  transferFee: { type: Number, default: 0 },
  isTransferFeePercentage: { type: Boolean, default: false },
  vtpassCommission: { type: Number, default: 0 },

  // ==================== TRANSACTION LIMITS ====================
  minTransactionAmount: { type: Number, default: 100.0 },
  maxTransactionAmount: { type: Number, default: 1000000.0 },

  // ==================== USER MANAGEMENT DEFAULTS ====================
  newUserDefaultWalletBalance: { type: Number, default: 0.0 },

  // ==================== NOTIFICATION SETTINGS ====================
  emailNotificationsEnabled: { type: Boolean, default: true },
  pushNotificationsEnabled: { type: Boolean, default: true },
  smsNotificationsEnabled: { type: Boolean, default: false },
  notificationMessage: { type: String, default: '' },

  // ==================== SECURITY SETTINGS ====================
  twoFactorAuthRequired: { type: Boolean, default: false },
  autoLogoutEnabled: { type: Boolean, default: false },
  sessionTimeout: { type: Number, default: 60 },
  transactionPinRequired: { type: Boolean, default: true },
  biometricAuthEnabled: { type: Boolean, default: true },

  // ==================== API RATE LIMITING ====================
  apiRateLimit: { type: Number, default: 100 },
  apiTimeWindow: { type: Number, default: 15 },

  // ==================== SINGLETON GUARD ====================
  singletonId: {
    type: String,
    required: true,
    unique: true,
    default: 'app_settings_singleton'
  },
}, { timestamps: true });

// Ensure only one settings document can exist
appSettingsSchema.index({ singletonId: 1 }, { unique: true });

module.exports = mongoose.models.AppSettings || mongoose.model('AppSettings', appSettingsSchema);
