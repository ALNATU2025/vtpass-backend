// services/chatService.js
const { Server } = require('socket.io');
const admin = require('firebase-admin');

let db; // Firestore database instance
let bucket; // Firebase Storage bucket instance

const initializeFirebase = (firestoreDb, storageBucket) => {
  db = firestoreDb;
  bucket = storageBucket;
};

const setupChatService = (httpServer) => {
  const io = new Server(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  io.on('connection', (socket) => {
    const userId = socket.handshake.headers.userid;
    const fullName = socket.handshake.headers.fullname;
    const userEmail = socket.handshake.headers.email;

    console.log(`⚡️ User Connected: ${userId || 'Anonymous'} (Socket ID: ${socket.id})`);

    if (!userId) {
      console.warn(`⚠️ Socket connection from unauthenticated user. Disconnecting ${socket.id}`);
      socket.disconnect(true);
      return;
    }

    socket.join(userId);
    console.log(`User ${userId} joined room ${userId}`);

    socket.emit('systemMessage', { message: 'Welcome to DalabaPay Support! How can we help you?' });

    socket.on('message', async (message) => {
      console.log(`Received message from ${userId}:`, message);

      if (message.userId !== userId || !message.content || !message.messageType) {
        console.warn(`Invalid message received from ${userId}:`, message);
        return;
      }

      const chatMessage = {
        userId: userId,
        senderId: userId,
        senderName: fullName,
        senderEmail: userEmail,
        content: message.content,
        messageType: message.messageType, // 'text', 'image', 'file'
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        fileName: message.fileName || null,
      };

      try {
        await db.collection('chats').add(chatMessage);
        console.log(`Message saved to Firestore for user ${userId}`);

        io.to(userId).emit('message', {
          ...chatMessage,
          timestamp: new Date().toISOString(),
        });

        if (chatMessage.messageType === 'text') {
            setTimeout(async () => {
                const supportResponse = {
                    userId: userId,
                    senderId: 'support_agent_id_123',
                    senderName: 'DalabaPay Support',
                    senderEmail: 'support@dalabapay.com',
                    content: `Thank you for your message: "${chatMessage.content}". A support agent will be with you shortly.`,
                    messageType: 'text',
                    timestamp: admin.firestore.FieldValue.serverTimestamp(),
                };
                await db.collection('chats').add(supportResponse);
                io.to(userId).emit('message', {
                    ...supportResponse,
                    timestamp: new Date().toISOString(),
                });
                console.log(`Simulated support response sent to ${userId}`);
            }, 2000);
        }

      } catch (error) {
        console.error(`Error saving message to Firestore for ${userId}:`, error);
        socket.emit('systemMessage', { message: 'Failed to send message. Please try again.' });
      }
    });

    socket.on('clearChatHistory', async (targetUserId) => {
      if (targetUserId !== userId) {
        console.warn(`Unauthorized clearChatHistory attempt by ${userId} for ${targetUserId}`);
        return;
      }

      console.log(`Attempting to clear chat history for user: ${targetUserId}`);
      try {
        const chatDocs = await db.collection('chats')
          .where('userId', '==', targetUserId)
          .get();

        const batch = db.batch();
        chatDocs.forEach(doc => {
          batch.delete(doc.ref);
        });
        await batch.commit();

        io.to(userId).emit('systemMessage', { message: 'Your chat history has been cleared.' });
        console.log(`Chat history cleared for user: ${targetUserId}`);
      } catch (error) {
        console.error(`Error clearing chat history for ${targetUserId}:`, error);
        io.to(userId).emit('systemMessage', { message: 'Failed to clear chat history.' });
      }
    });

    socket.on('disconnect', () => {
      console.log(`User Disconnected: ${userId || 'Anonymous'} (Socket ID: ${socket.id})`);
    });
  });
};

module.exports = {
  setupChatService,
  initializeFirebase,
};
