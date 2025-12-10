const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    type: {
        type: String,
        enum: [
            'Airtime Purchase',
            'Data Purchase',
            'Cable TV Subscription',
            'Electricity Payment',
            'Education Payment',
            'Insurance Purchase',
            'Wallet Funding',
            'Transfer Sent',
            'Transfer Received',
            'Commission Credit',
            'Commission Withdrawal',
            'debit',
            'credit'
        ],
        required: true
    },
    amount: { type: Number, required: true, min: 0 },
    status: {
        type: String,
        enum: ['Successful', 'Pending', 'Failed'],
        default: 'Pending'
    },
    transactionId: { type: String, unique: true, sparse: true },
    reference: { type: String, unique: true, sparse: true, index: true },
    description: { type: String, required: true },
    balanceBefore: { type: Number, default: 0 },
    balanceAfter: { type: Number, default: 0 },
    metadata: { 
        type: mongoose.Schema.Types.Mixed, 
        default: {},
        // ADD THESE SPECIFIC FIELDS TO METADATA
        phone: { type: String, default: '' },
        smartcardNumber: { type: String, default: '' },
        billersCode: { type: String, default: '' },
        variation_code: { type: String, default: '' }, // ADD THIS
        packageName: { type: String, default: '' }, // ADD THIS
        serviceID: { type: String, default: '' },
        selectedPackage: { type: String, default: '' } // ADD THIS
    },
    isCommission: { type: Boolean, default: false, index: true },
    service: { type: String, default: '', index: true },
    authenticationMethod: {
        type: String,
        enum: ['pin', 'biometric', 'none', 'paystack', 'manual'],
        default: 'none'
    }
}, {
    timestamps: true,
    versionKey: false
});
