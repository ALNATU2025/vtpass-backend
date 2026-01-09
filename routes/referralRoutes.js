// routes/referralRoutes.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Notification = require('../models/Notification');
const { protect } = require('../middleware/authMiddleware');
const mongoose = require('mongoose');

// Helper function to check if user has made first deposit
const checkFirstDeposit = async (userId) => {
  try {
    const deposit = await Transaction.findOne({
      userId: userId,
      type: 'credit',
      status: 'Successful',
      'metadata.isDeposit': true
    });
    return !!deposit;
  } catch (error) {
    console.error('❌ Error checking first deposit:', error);
    return false;
  }
};

// @desc    Get comprehensive referral statistics
// @route   GET /api/referral/stats
// @access  Private
router.get('/stats', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get user with commission balance
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get all users referred by this user
    const referredUsers = await User.find({ referrerId: userId })
      .select('fullName email phone createdAt isActive walletBalance commissionBalance referralBonusAwarded')
      .sort({ createdAt: -1 });
    
    // Calculate total commission earned from ALL referral sources
    const commissionAggregation = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          status: 'Successful'
        }
      },
      {
        $group: {
          _id: null,
          totalEarned: { $sum: '$amount' },
          directReferralEarnings: {
            $sum: {
              $cond: [
                { $regexMatch: { input: '$description', regex: /Direct Referral Bonus|direct referral/i } },
                '$amount',
                0
              ]
            }
          },
          indirectReferralEarnings: {
            $sum: {
              $cond: [
                { $regexMatch: { input: '$description', regex: /Indirect Referral Bonus|indirect referral/i } },
                '$amount',
                0
              ]
            }
          },
          welcomeBonusEarnings: {
            $sum: {
              $cond: [
                { $regexMatch: { input: '$description', regex: /Welcome Bonus|welcome bonus/i } },
                '$amount',
                0
              ]
            }
          },
          serviceCommissionEarnings: {
            $sum: {
              $cond: [
                { $regexMatch: { input: '$description', regex: /Commission Credit|commission credit/i } },
                '$amount',
                0
              ]
            }
          }
        }
      }
    ]);
    
    const stats = commissionAggregation[0] || {
      totalEarned: 0,
      directReferralEarnings: 0,
      indirectReferralEarnings: 0,
      welcomeBonusEarnings: 0,
      serviceCommissionEarnings: 0
    };
    
    // Get all commission transactions for detailed breakdown
    const commissionTransactions = await Transaction.find({
      userId: userId,
      isCommission: true,
      status: 'Successful'
    }).sort({ createdAt: -1 }).limit(20);
    
    // Get pending earnings (users who joined but haven't made deposit)
    const pendingEarningsDetails = [];
    let totalPotentialEarnings = 0;
    
    for (const referredUser of referredUsers) {
      const hasDeposit = await checkFirstDeposit(referredUser._id);
      
      if (!hasDeposit && !referredUser.referralBonusAwarded) {
        // Potential ₦200 direct bonus + ₦20 indirect bonus (if applicable)
        const potentialEarnings = 200; // Direct bonus
        
        // Check if this user has a referrer (for indirect bonus calculation)
        if (referredUser.referrerId) {
          const referrer = await User.findById(referredUser.referrerId);
          if (referrer && referrer.referrerId) {
            // Add potential ₦20 indirect bonus for level 2
            potentialEarnings += 20;
          }
        }
        
        pendingEarningsDetails.push({
          user: {
            _id: referredUser._id,
            fullName: referredUser.fullName,
            email: referredUser.email,
            joinedAt: referredUser.createdAt
          },
          potentialBonus: potentialEarnings,
          status: 'Waiting for first deposit'
        });
        
        totalPotentialEarnings += potentialEarnings;
      }
    }
    
    // Get level 2 referrals (indirect referrals)
    let indirectReferrals = [];
    let totalIndirectPotential = 0;
    
    for (const directRef of referredUsers) {
      const level2Refs = await User.find({ referrerId: directRef._id })
        .select('fullName email phone createdAt isActive');
      
      for (const level2Ref of level2Refs) {
        const hasDeposit = await checkFirstDeposit(level2Ref._id);
        
        if (!hasDeposit) {
          totalIndirectPotential += 20; // ₦20 indirect bonus
        }
        
        indirectReferrals.push({
          _id: level2Ref._id,
          fullName: level2Ref.fullName,
          email: level2Ref.email,
          joinedAt: level2Ref.createdAt,
          via: directRef.fullName,
          hasDeposit: hasDeposit,
          potentialBonus: 20
        });
      }
    }
    
    // Calculate bonuses that have been awarded but not yet withdrawn
    const unwithdrawnCommission = await Transaction.aggregate([
      {
        $match: {
          userId: userId,
          isCommission: true,
          status: 'Successful'
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    const totalUnwithdrawn = unwithdrawnCommission[0]?.total || 0;
    const availableForWithdrawal = user.commissionBalance || 0;
    
    res.json({
      success: true,
      referralStats: {
        // Basic Info
        referralCode: user.referralCode || 'N/A',
        totalReferralEarnings: user.totalReferralEarnings || 0,
        commissionBalance: user.commissionBalance || 0,
        availableForWithdrawal: availableForWithdrawal,
        
        // Referral Counts
        totalReferrals: referredUsers.length,
        activeReferrals: referredUsers.filter(u => u.isActive).length,
        directReferrals: referredUsers.length,
        indirectReferrals: indirectReferrals.length,
        
        // Earnings Breakdown
        earnings: {
          totalEarned: stats.totalEarned,
          directReferralEarnings: stats.directReferralEarnings,
          indirectReferralEarnings: stats.indirectReferralEarnings,
          welcomeBonusEarnings: stats.welcomeBonusEarnings,
          serviceCommissionEarnings: stats.serviceCommissionEarnings,
          unwithdrawn: totalUnwithdrawn
        },
        
        // Potential Earnings
        potentialEarnings: {
          totalPotential: totalPotentialEarnings + totalIndirectPotential,
          directPotential: totalPotentialEarnings,
          indirectPotential: totalIndirectPotential,
          pendingReferrals: pendingEarningsDetails.length,
          pendingDetails: pendingEarningsDetails
        },
        
        // Links
        referralLink: `https://dalabapay.com/register?ref=${user.referralCode || 'N/A'}`,
        shareMessage: `Join DalabaPay using my referral code ${user.referralCode} and get ₦200 welcome bonus on your first deposit!`,
        
        // Bonus Structure
        bonusStructure: {
          directBonus: '₦200 to both referrer and referred user',
          indirectBonus: '₦20 to original referrer (level 2)',
          conditions: 'First deposit of ₦1,000 or more required',
          serviceCommission: '0.3%-0.5% on service purchases'
        },
        
        // Lists
        referrals: referredUsers.map(user => ({
          _id: user._id,
          fullName: user.fullName,
          email: user.email,
          phone: user.phone,
          joinedAt: user.createdAt,
          isActive: user.isActive,
          walletBalance: user.walletBalance,
          commissionBalance: user.commissionBalance,
          hasReceivedBonus: user.referralBonusAwarded || false
        })),
        
        indirectReferrals: indirectReferrals,
        
        // Recent Commission Transactions
        recentCommissions: commissionTransactions.map(tx => ({
          _id: tx._id,
          amount: tx.amount,
          description: tx.description,
          date: tx.createdAt,
          type: tx.type,
          metadata: tx.metadata || {}
        }))
      }
    });
    
  } catch (error) {
    console.error('❌ Get referral stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get referral statistics',
      error: error.message
    });
  }
});

// @desc    Get referral leaderboard
// @route   GET /api/referral/leaderboard
// @access  Private
router.get('/leaderboard', protect, async (req, res) => {
  try {
    // Get top referrers by total referral earnings
    const leaderboard = await User.aggregate([
      {
        $match: {
          totalReferralEarnings: { $gt: 0 }
        }
      },
      {
        $project: {
          fullName: 1,
          email: 1,
          referralCount: 1,
          totalReferralEarnings: 1,
          commissionBalance: 1,
          createdAt: 1
        }
      },
      {
        $sort: { totalReferralEarnings: -1 }
      },
      {
        $limit: 50
      }
    ]);
    
    // Get current user's position
    const currentUser = await User.findById(req.user._id);
    const userPosition = leaderboard.findIndex(user => 
      user._id.toString() === req.user._id.toString()
    );
    
    res.json({
      success: true,
      leaderboard: leaderboard.map((user, index) => ({
        rank: index + 1,
        ...user
      })),
      currentUserPosition: userPosition !== -1 ? userPosition + 1 : 'Not ranked',
      currentUserStats: {
        referralCount: currentUser.referralCount || 0,
        totalReferralEarnings: currentUser.totalReferralEarnings || 0,
        commissionBalance: currentUser.commissionBalance || 0
      },
      updatedAt: new Date()
    });
    
  } catch (error) {
    console.error('❌ Get referral leaderboard error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get leaderboard'
    });
  }
});

// @desc    Get detailed commission history
// @route   GET /api/referral/commission-history
// @access  Private
router.get('/commission-history', protect, async (req, res) => {
  try {
    const { page = 1, limit = 20, type } = req.query;
    const skip = (page - 1) * limit;
    
    const query = {
      userId: req.user._id,
      isCommission: true
    };
    
    if (type) {
      query.type = type;
    }
    
    const commissionHistory = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    // Group by month for chart data
    const monthlyEarnings = await Transaction.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(req.user._id),
          isCommission: true,
          status: 'Successful'
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          totalEarned: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': -1, '_id.month': -1 }
      },
      {
        $limit: 12
      }
    ]);
    
    res.json({
      success: true,
      commissionHistory,
      monthlyEarnings,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit),
        totalItems: total
      }
    });
    
  } catch (error) {
    console.error('❌ Get commission history error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get commission history'
    });
  }
});

// @desc    Check if referral code is valid
// @route   GET /api/referral/check-code/:code
// @access  Public
router.get('/check-code/:code', async (req, res) => {
  try {
    const { code } = req.params;
    
    if (!code || code.trim() === '') {
      return res.json({
        success: false,
        valid: false,
        message: 'Referral code is required'
      });
    }
    
    const user = await User.findOne({ 
      referralCode: code.toUpperCase().trim() 
    }).select('fullName email phone');
    
    if (!user) {
      return res.json({
        success: false,
        valid: false,
        message: 'Invalid referral code'
      });
    }
    
    res.json({
      success: true,
      valid: true,
      message: 'Valid referral code',
      referrer: {
        fullName: user.fullName,
        email: user.email,
        phone: user.phone
      }
    });
    
  } catch (error) {
    console.error('❌ Check referral code error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check referral code'
    });
  }
});

// @desc    Withdraw commission to wallet
// @route   POST /api/referral/withdraw-commission
// @access  Private
router.post('/withdraw-commission', protect, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { amount } = req.body;
    const userId = req.user._id;
    
    if (!amount || amount <= 0) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: 'Valid withdrawal amount is required'
      });
    }
    
    const user = await User.findById(userId).session(session);
    if (!user) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Check if user has enough commission balance
    if (user.commissionBalance < amount) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: `Insufficient commission balance. Available: ₦${user.commissionBalance.toFixed(2)}`,
        availableBalance: user.commissionBalance
      });
    }
    
    // Minimum withdrawal amount
    const minWithdrawal = 100; // ₦100 minimum
    if (amount < minWithdrawal) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        message: `Minimum withdrawal amount is ₦${minWithdrawal}`,
        minWithdrawal: minWithdrawal
      });
    }
    
    // Update balances
    const commissionBefore = user.commissionBalance;
    const walletBefore = user.walletBalance;
    
    user.commissionBalance -= amount;
    user.walletBalance += amount;
    
    await user.save({ session });
    
    // Create commission withdrawal transaction
    const withdrawalTransaction = new Transaction({
      userId: userId,
      amount: amount,
      type: 'Commission Withdrawal',
      status: 'Successful',
      description: `Commission withdrawal to wallet`,
      balanceBefore: commissionBefore,
      balanceAfter: user.commissionBalance,
      isCommission: true,
      metadata: {
        withdrawalType: 'commission_to_wallet',
        walletBalanceBefore: walletBefore,
        walletBalanceAfter: user.walletBalance,
        commissionBalanceBefore: commissionBefore,
        commissionBalanceAfter: user.commissionBalance
      }
    });
    
    await withdrawalTransaction.save({ session });
    
    // Create wallet credit transaction
    const walletTransaction = new Transaction({
      userId: userId,
      amount: amount,
      type: 'credit',
      status: 'Successful',
      description: `Commission withdrawal from commission balance`,
      balanceBefore: walletBefore,
      balanceAfter: user.walletBalance,
      isCommission: false,
      metadata: {
        source: 'commission_withdrawal',
        commissionTransactionId: withdrawalTransaction._id,
        originalCommissionBalance: commissionBefore
      }
    });
    
    await walletTransaction.save({ session });
    
    // Create notification
    await Notification.create([{
      recipient: userId,
      title: "Commission Withdrawal Successful 💰",
      message: `₦${amount.toFixed(2)} has been transferred from your commission balance to your wallet. New wallet balance: ₦${user.walletBalance.toFixed(2)}`,
      type: 'commission_withdrawal',
      isRead: false,
      metadata: {
        amount: amount,
        newWalletBalance: user.walletBalance,
        newCommissionBalance: user.commissionBalance,
        transactionId: withdrawalTransaction._id
      }
    }], { session });
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `₦${amount.toFixed(2)} successfully transferred to your wallet`,
      balances: {
        newWalletBalance: user.walletBalance,
        newCommissionBalance: user.commissionBalance,
        withdrawalAmount: amount
      },
      transactionId: withdrawalTransaction._id
    });
    
  } catch (error) {
    await session.abortTransaction();
    console.error('❌ Withdraw commission error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to withdraw commission',
      error: error.message
    });
  } finally {
    session.endSession();
  }
});

// @desc    Test referral bonus for specific user (Admin only)
// @route   POST /api/referral/test-bonus
// @access  Private (Admin)
router.post('/test-bonus', protect, async (req, res) => {
  try {
    const { userId, depositAmount = 2000 } = req.body;
    
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Get referrer info
    let referrerInfo = null;
    if (user.referrerId) {
      const referrer = await User.findById(user.referrerId);
      if (referrer) {
        referrerInfo = {
          _id: referrer._id,
          email: referrer.email,
          commissionBefore: referrer.commissionBalance,
          totalReferralEarningsBefore: referrer.totalReferralEarnings || 0
        };
      }
    }
    
    // Get indirect referrer (level 2)
    let indirectReferrerInfo = null;
    if (user.referrerId) {
      const directReferrer = await User.findById(user.referrerId);
      if (directReferrer && directReferrer.referrerId) {
        const indirectReferrer = await User.findById(directReferrer.referrerId);
        if (indirectReferrer) {
          indirectReferrerInfo = {
            _id: indirectReferrer._id,
            email: indirectReferrer.email,
            commissionBefore: indirectReferrer.commissionBalance,
            totalReferralEarningsBefore: indirectReferrer.totalReferralEarnings || 0
          };
        }
      }
    }
    
    // Simulate the bonus process
    const bonusStructure = {
      directBonus: {
        referrer: 200,
        referredUser: 200,
        conditions: 'First deposit of ₦1,000+',
        awarded: depositAmount >= 1000
      },
      indirectBonus: {
        amount: 20,
        conditions: 'Level 2 referral',
        awarded: !!indirectReferrerInfo
      },
      test: {
        depositAmount: depositAmount,
        meetsMinimum: depositAmount >= 1000,
        hasReferrer: !!user.referrerId,
        hasIndirectReferrer: !!indirectReferrerInfo
      }
    };
    
    res.json({
      success: true,
      message: 'Referral bonus test completed',
      testResults: {
        user: {
          _id: user._id,
          email: user.email,
          referrerId: user.referrerId,
          referralBonusAwarded: user.referralBonusAwarded || false,
          indirectBonusAwardedLevel2: user.indirectBonusAwardedLevel2 || false
        },
        referrer: referrerInfo,
        indirectReferrer: indirectReferrerInfo,
        bonusStructure,
        expectedBonuses: {
          ifFirstDeposit: {
            directToReferrer: depositAmount >= 1000 ? 200 : 0,
            directToUser: depositAmount >= 1000 ? 200 : 0,
            indirectToLevel2: indirectReferrerInfo ? 20 : 0,
            total: (depositAmount >= 1000 ? 400 : 0) + (indirectReferrerInfo ? 20 : 0)
          }
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Test referral bonus error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to test referral bonus',
      error: error.message
    });
  }
});

// @desc    Get referral guide and FAQ
// @route   GET /api/referral/guide
// @access  Public
router.get('/guide', async (req, res) => {
  try {
    const guide = {
      title: "DalabaPay Referral Program Guide",
      sections: [
        {
          title: "How It Works",
          points: [
            "Share your unique referral link/code with friends",
            "Friend signs up using your link/code",
            "Friend makes their first deposit of ₦1,000 or more",
            "You earn ₦200 commission instantly!",
            "Your friend also gets ₦200 welcome bonus"
          ]
        },
        {
          title: "Bonus Structure",
          points: [
            "Direct Referral Bonus: ₦200 (for you and your friend)",
            "Indirect Referral Bonus: ₦20 (when your referral refers someone)",
            "Service Commission: 0.3%-0.5% on all service purchases"
          ]
        },
              {
          title: "Bonus Requirements",
          points: [
            "First deposit must be ₦5,000 or more to qualify for bonuses",
            "Smaller deposits work but no bonus awarded",
            "Only FIRST deposit qualifies for referral bonus",
            "Bonuses credited to COMMISSION WALLET instantly"
          ]
        },
        {
          title: "Earning Scenarios",
          points: [
            "First deposit ₦3,000 → No bonus",
            "First deposit ₦5,000 → ₦200 bonus for both",
            "First deposit ₦10,000 → ₦200 bonus for both",
            "Second deposit (any amount) → No bonus"
          ]
        },
        {
          title: "Frequently Asked Questions",
          questions: [
            {
              q: "When do I get my referral bonus?",
              a: "Instantly when your referred friend makes their first deposit of ₦1,000+"
            },
            {
              q: "Where does the bonus go?",
              a: "All bonuses go to your COMMISSION WALLET"
            },
            {
              q: "How do I withdraw my commission?",
              a: "Go to Commission Wallet → Withdraw to Main Wallet"
            },
            {
              q: "Is there a limit to how many people I can refer?",
              a: "No limit! Refer as many as you want"
            },
            {
              q: "Do I earn on every purchase my referrals make?",
              a: "Yes! You earn 0.3%-0.5% commission on all their service purchases"
            }
          ]
        }
      ],
      contact: {
        email: "support@dalabapay.com",
        phone: "+234-XXX-XXX-XXXX",
        hours: "Mon-Fri, 9AM-6PM"
      }
    };
    
    res.json({
      success: true,
      guide,
      lastUpdated: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Get referral guide error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get referral guide'
    });
  }
});

module.exports = router;
