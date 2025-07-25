// routes/notificationRoutes.js
const express = require('express');
const router = express.Router();
const Notification = require('../models/Notification'); // Import the new Notification model
// const auth = require('../middleware/auth'); // Your authentication middleware
// const authorizeAdmin = require('../middleware/authorizeAdmin'); // Your admin authorization middleware

// POST /api/notifications/send - Admin sends a new notification
// This endpoint MUST be protected by admin authorization.
router.post('/send', /* auth, authorizeAdmin, */ async (req, res) => {
  try {
    const { recipientId, title, message } = req.body; // recipientId can be null for general

    if (!title || !message) {
      return res.status(400).json({ success: false, message: 'Title and message are required.' });
    }

    const newNotification = new Notification({
      recipient: recipientId || null, // If recipientId is provided, use it, otherwise null for general
      title,
      message,
    });

    await newNotification.save();
    res.status(201).json({ success: true, message: 'Notification sent successfully.', notification: newNotification });
  } catch (error) {
    console.error('❌ Error sending notification:', error);
    res.status(500).json({ success: false, message: 'Server error sending notification.' });
  }
});

// GET /api/notifications/:userId - Get notifications for a specific user
// This endpoint should be protected by authentication middleware.
router.get('/:userId', /* auth, */ async (req, res) => { // Ensure req.params.userId matches req.user.id for security
  try {
    const userId = req.params.userId; // Or req.user.id if using auth middleware

    // Fetch general notifications AND notifications specifically for this user
    const notifications = await Notification.find({
      $or: [
        { recipient: null }, // General notifications
        { recipient: userId }, // Notifications specific to this user
      ],
    }).sort({ createdAt: -1 }); // Newest first

    res.status(200).json(notifications);
  } catch (error) {
    console.error('❌ Error fetching user notifications:', error);
    res.status(500).json({ success: false, message: 'Server error fetching notifications.' });
  }
});

// POST /api/notifications/:notificationId/read - Mark a notification as read
// This endpoint should be protected by authentication middleware.
router.post('/:notificationId/read', /* auth, */ async (req, res) => {
  try {
    const notificationId = req.params.notificationId;
    const userId = req.body.userId; // Or req.user.id if using auth middleware

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    const notification = await Notification.findById(notificationId);

    if (!notification) {
      return res.status(404).json({ success: false, message: 'Notification not found.' });
    }

    // Add userId to readBy array if not already present
    if (!notification.readBy.includes(userId)) {
      notification.readBy.push(userId);
      await notification.save();
    }

    res.status(200).json({ success: true, message: 'Notification marked as read.' });
  } catch (error) {
    console.error('❌ Error marking notification as read:', error);
    res.status(500).json({ success: false, message: 'Server error marking notification as read.' });
  }
});

// GET /api/notifications/unread-count/:userId - Get count of unread notifications for a user
// This endpoint should be protected by authentication middleware.
router.get('/unread-count/:userId', /* auth, */ async (req, res) => {
  try {
    const userId = req.params.userId; // Or req.user.id if using auth middleware

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID is required.' });
    }

    const unreadCount = await Notification.countDocuments({
      $or: [
        { recipient: null, readBy: { $ne: userId } }, // General notifications not read by user
        { recipient: userId, readBy: { $ne: userId } }, // Specific notifications not read by user
      ],
    });

    res.status(200).json({ unreadCount });
  } catch (error) {
    console.error('❌ Error fetching unread notification count:', error);
    res.status(500).json({ success: false, message: 'Server error fetching unread count.' });
  }
});


module.exports = router;
