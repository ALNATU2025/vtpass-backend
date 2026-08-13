// socket-server.js

const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const Notification = require('./models/Notification');

let io;

function initSocketServer(server) {
  io = new Server(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST'],
    },
    transports: ['websocket', 'polling'],
    path: '/socket.io',
  });

  // ==================== AUTHENTICATION MIDDLEWARE ====================
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
      return next(new Error('Authentication required'));
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.id;
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return next(new Error('Token expired'));
      }
      next(new Error('Invalid token'));
    }
  });

  // ==================== CONNECTION HANDLER ====================
  io.on('connection', (socket) => {
    const userId = socket.userId;
    console.log(`🔌 User ${userId} connected - Socket ID: ${socket.id}`);

    // Join user's personal room
    socket.join(`user:${userId}`);
    console.log(`✅ User ${userId} joined room: user:${userId}`);

    // ==================== EVENT HANDLERS ====================
    
    // 1. Authenticate (re-auth if needed)
    socket.on('authenticate', async (data) => {
      try {
        const { userId: clientUserId, token } = data;
        const userIdToUse = clientUserId || socket.userId;
        
        if (!userIdToUse) {
          socket.emit('error', { message: 'User ID required' });
          return;
        }

        // Verify token if provided
        if (token) {
          try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            if (decoded.id !== userIdToUse) {
              socket.emit('error', { message: 'Token does not match user' });
              return;
            }
          } catch (err) {
            socket.emit('error', { message: 'Invalid token' });
            return;
          }
        }

        socket.userId = userIdToUse;
        socket.join(`user:${userIdToUse}`);
        
        console.log(`✅ User ${userIdToUse} authenticated via socket`);
        
        // Send unread count
        const count = await getUnreadCount(userIdToUse);
        socket.emit('badge_update', { count });
        
        // Send connection success
        socket.emit('authenticated', { 
          success: true, 
          userId: userIdToUse,
          message: 'Connected successfully'
        });
      } catch (error) {
        console.error('❌ Auth error:', error);
        socket.emit('error', { message: 'Authentication failed' });
      }
    });

    // 2. Get unread count
    socket.on('get_badge_count', async (data) => {
      try {
        const userId = data?.userId || socket.userId;
        if (!userId) {
          socket.emit('error', { message: 'User ID required' });
          return;
        }
        const count = await getUnreadCount(userId);
        socket.emit('badge_update', { count });
      } catch (error) {
        console.error('❌ Badge count error:', error);
        socket.emit('error', { message: 'Failed to get badge count' });
      }
    });

    // 3. Mark notification as read (sync with server)
    socket.on('mark_read', async (data) => {
      try {
        const { notificationId } = data;
        if (!notificationId) {
          socket.emit('error', { message: 'Notification ID required' });
          return;
        }

        const notification = await Notification.findById(notificationId);
        if (!notification) {
          socket.emit('error', { message: 'Notification not found' });
          return;
        }

        const userId = socket.userId;
        
        // Check permission
        if (notification.recipient && notification.recipient.toString() !== userId) {
          socket.emit('error', { message: 'Access denied' });
          return;
        }

        // Mark as read
        if (notification.recipient === null) {
          // General notification - add user to readBy
          if (!notification.readBy.includes(userId)) {
            notification.readBy.push(userId);
            await notification.save();
          }
        } else {
          // Personal notification
          if (!notification.isRead) {
            notification.isRead = true;
            await notification.save();
          }
        }

        // Send updated badge count
        const count = await getUnreadCount(userId);
        socket.emit('badge_update', { count });
        
        socket.emit('mark_read_success', { notificationId });
      } catch (error) {
        console.error('❌ Mark read error:', error);
        socket.emit('error', { message: 'Failed to mark as read' });
      }
    });

    // 4. Mark all as read
    socket.on('mark_all_read', async (data) => {
      try {
        const userId = socket.userId;
        
        await Notification.updateMany(
          { 
            recipient: userId, 
            isRead: false 
          },
          { $set: { isRead: true } }
        );

        const count = await getUnreadCount(userId);
        socket.emit('badge_update', { count });
        
        socket.emit('mark_all_read_success', { success: true });
      } catch (error) {
        console.error('❌ Mark all read error:', error);
        socket.emit('error', { message: 'Failed to mark all as read' });
      }
    });

    // 5. Get notifications (paginated)
    socket.on('get_notifications', async (data) => {
      try {
        const { page = 1, limit = 20 } = data || {};
        const userId = socket.userId;
        const skip = (page - 1) * limit;

        const query = { recipient: userId };
        
        const [notifications, total] = await Promise.all([
          Notification.find(query)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean(),
          Notification.countDocuments(query)
        ]);

        socket.emit('notifications_list', {
          notifications,
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit)
        });
      } catch (error) {
        console.error('❌ Get notifications error:', error);
        socket.emit('error', { message: 'Failed to get notifications' });
      }
    });

    // 6. Send notification (admin only)
    socket.on('send_notification', async (payload) => {
      try {
        // Check if user is admin (verify from database)
        const user = await User.findById(socket.userId);
        if (!user || !user.isAdmin) {
          socket.emit('error', { message: 'Admin access required' });
          return;
        }

        const { 
          title, 
          message, 
          recipientId, 
          type = 'general', 
          screen = 'notifications',
          data: notificationData = {},
          sendToAll = false
        } = payload;

        if (!title || !message) {
          socket.emit('error', { message: 'Title and message are required' });
          return;
        }

        const notification = new Notification({
          title,
          message,
          type: type,
          screen: screen,
          data: notificationData,
          sender: socket.userId,
          recipient: sendToAll ? null : (recipientId || null),
          readBy: [],
        });

        await notification.save();

        // Broadcast to specific user or all
        if (!sendToAll && recipientId) {
          io.to(`user:${recipientId}`).emit('notification', notification.toJSON());
          const count = await getUnreadCount(recipientId);
          io.to(`user:${recipientId}`).emit('badge_update', { count });
          console.log(`📨 Sent notification to user: ${recipientId}`);
        } else {
          // Send to all connected users
          io.emit('notification', notification.toJSON());
          // Update badges for all users
          const allUsers = await User.find({}, '_id');
          for (const userObj of allUsers) {
            const count = await getUnreadCount(userObj._id);
            io.to(`user:${userObj._id}`).emit('badge_update', { count });
          }
          console.log(`📨 Sent broadcast notification to all users`);
        }

        socket.emit('notification_sent', { 
          success: true, 
          notificationId: notification._id 
        });
      } catch (error) {
        console.error('❌ Send notification error:', error);
        socket.emit('error', { message: 'Failed to send notification' });
      }
    });

    // 7. Disconnect
    socket.on('disconnect', () => {
      console.log(`🔌 User ${socket.userId} disconnected - Socket ID: ${socket.id}`);
    });
  });

  return io;
}

// ==================== HELPER FUNCTIONS ====================

async function getUnreadCount(userId) {
  try {
    return await Notification.countDocuments({
      $or: [
        { recipient: userId, isRead: false },
        { recipient: null, readBy: { $ne: userId } }
      ]
    });
  } catch (error) {
    console.error('❌ Get unread count error:', error);
    return 0;
  }
}

async function emitNotificationToUser(userId, notification) {
  try {
    io.to(`user:${userId}`).emit('notification', notification);
    const count = await getUnreadCount(userId);
    io.to(`user:${userId}`).emit('badge_update', { count });
  } catch (error) {
    console.error('❌ Emit notification error:', error);
  }
}

async function emitBadgeUpdate(userId) {
  try {
    const count = await getUnreadCount(userId);
    io.to(`user:${userId}`).emit('badge_update', { count });
  } catch (error) {
    console.error('❌ Badge update error:', error);
  }
}

// ==================== EXPORT ====================

module.exports = { 
  initSocketServer, 
  get io() { return io; },
  emitNotificationToUser,
  emitBadgeUpdate,
  getUnreadCount
};
