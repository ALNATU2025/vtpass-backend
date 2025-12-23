// routes/referralRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { protect } = require('../middleware/authMiddleware');

// @desc    Get referral statistics for a user
// @route   GET /api/referral/stats
// @access  Private
router.get('/stats', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get user
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get all users referred by this user
    const referredUsers = await User.find({ referrerId: userId })
      .select('fullName email phone createdAt isActive walletBalance')
      .sort({ createdAt: -1 });
    
    // Calculate total commission earned from referrals
    const commissionAggregation = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          type: 'Commission Credit',
          'metadata.commissionSource': 'referral'
        }
      },
      {
        $group: {
          _id: null,
          totalEarned: { $sum: '$amount' }
        }
      }
    ]);
    
    const totalEarned = commissionAggregation[0]?.totalEarned || 0;
    
    // Calculate pending earnings (referrals who haven't made purchases yet)
    // We'll assume a referral hasn't made a purchase if they have 0 wallet transactions
    const pendingReferrals = [];
    for (const referredUser of referredUsers) {
      const hasPurchases = await Transaction.findOne({
        userId: referredUser._id,
        type: { $in: ['Purchase', 'Airtime Purchase', 'Data Purchase', 'Cable TV Subscription', 'Electricity Payment'] },
        status: 'Successful'
      });
      
      if (!hasPurchases) {
        pendingReferrals.push({
          _id: referredUser._id,
          fullName: referredUser.fullName,
          email: referredUser.email,
          joinedAt: referredUser.createdAt
        });
      }
    }
    
    // Estimate potential earnings (0.005% of average purchase amount)
    const averagePurchase = 1000; // Assume average ₦1000 purchase
    const potentialCommissionRate = 0.00005; // 0.005%
    const pendingEarnings = pendingReferrals.length * (averagePurchase * potentialCommissionRate);
    
    res.json({
      success: true,
      referralStats: {
        referralCode: user.referralCode || 'N/A',
        totalReferrals: referredUsers.length,
        activeReferrals: referredUsers.filter(u => u.isActive).length,
        totalEarned: totalEarned,
        pendingEarnings: pendingEarnings,
        referralLink: `https://vtpass-backend.onrender.com/api/auth/register?ref=${user.referralCode || 'N/A'}`,
        referrals: referredUsers.map(user => ({
          _id: user._id,
          fullName: user.fullName,
          email: user.email,
          phone: user.phone,
          joinedAt: user.createdAt,
          isActive: user.isActive,
          walletBalance: user.walletBalance
        }))
      }
    });
    
  } catch (error) {
    console.error('❌ Get referral stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get referral statistics'
    });
  }
});

module.exports = router;
