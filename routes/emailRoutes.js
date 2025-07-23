// routes/emailRoutes.js
// This file defines API endpoints for sending various types of emails.

const express = require('express');
const router = express.Router();
const { sendEmail } = require('../utils/emailService'); // Adjust path if your utils folder is elsewhere

/**
 * @route POST /api/email/send-transaction-email
 * @description Sends a transaction confirmation email to a user.
 * @access Public (or add authentication/authorization as needed)
 * @body {string} userEmail - The email address of the recipient.
 * @body {object} transactionDetails - Details of the transaction (id, amount, date).
 */
router.post('/send-transaction-email', async (req, res) => {
  const { userEmail, transactionDetails } = req.body;

  if (!userEmail || !transactionDetails) {
    return res.status(400).json({ message: 'Missing required fields: userEmail or transactionDetails' });
  }

  // Basic validation for transactionDetails structure
  if (!transactionDetails.id || !transactionDetails.amount || !transactionDetails.date) {
    return res.status(400).json({ message: 'Missing required transactionDetails: id, amount, or date' });
  }

  const subject = 'DalabaPay Transaction Confirmation';
  const text = `Dear DalabaPay User,\n\nYour transaction for ₦${transactionDetails.amount} on ${transactionDetails.date} was successful. Transaction ID: ${transactionDetails.id}\n\nThank you for using DalaPay!`;
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9; }
            .header { background-color: #007bff; color: white; padding: 10px 20px; border-radius: 8px 8px 0 0; text-align: center; }
            .content { padding: 20px; }
            .footer { text-align: center; font-size: 0.9em; color: #777; margin-top: 20px; }
            .button { display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            .highlight { font-weight: bold; color: #007bff; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>DalabaPay Transaction Confirmation</h2>
            </div>
            <div class="content">
                <p>Dear DalaPay User,</p>
                <p>Your recent transaction has been successfully processed!</p>
                <p><strong>Transaction ID:</strong> <span class="highlight">${transactionDetails.id}</span></p>
                <p><strong>Amount:</strong> <span class="highlight">₦${transactionDetails.amount}</span></p>
                <p><strong>Date:</strong> ${transactionDetails.date}</p>
                <p>Thank you for choosing DalaPay for your digital payments!</p>
                <p>If you have any questions, please don't hesitate to contact our support team.</p>
                <p>Best regards,<br>The DalaPay Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} DalaPay. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
  `;

  try {
    await sendEmail(userEmail, subject, text, html);
    res.status(200).json({ message: 'Transaction email sent successfully' });
  } catch (error) {
    console.error('Error sending transaction email:', error);
    res.status(500).json({ message: 'Failed to send transaction email', error: error.message });
  }
});

/**
 * @route POST /api/email/send-welcome-email
 * @description Sends a welcome email to a new user.
 * @access Public (or add authentication/authorization as needed)
 * @body {string} userEmail - The email address of the new user.
 * @body {string} userName - The name of the new user.
 */
router.post('/send-welcome-email', async (req, res) => {
  const { userEmail, userName } = req.body;

  if (!userEmail || !userName) {
    return res.status(400).json({ message: 'Missing required fields: userEmail or userName' });
  }

  const subject = 'Welcome to DalabaPay!';
  const text = `Hello ${userName},\n\nWelcome to DalaPay! We're excited to have you on board. You can now easily pay bills, buy airtime, and more.\n\nBest regards,\nThe DalaPay Team`;
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9; }
            .header { background-color: #007bff; color: white; padding: 10px 20px; border-radius: 8px 8px 0 0; text-align: center; }
            .content { padding: 20px; }
            .footer { text-align: center; font-size: 0.9em; color: #777; margin-top: 20px; }
            .button { display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            .highlight { font-weight: bold; color: #007bff; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>Welcome to DalabaPay!</h2>
            </div>
            <div class="content">
                <p>Hello ${userName},</p>
                <p>We're thrilled to welcome you to the DalabaPay family! 🎉</p>
                <p>With DalabaPay, you can conveniently manage all your digital payments in one place:</p>
                <ul>
                    <li>Effortless bill payments</li>
                    <li>Instant airtime and data top-ups</li>
                    <li>Seamless utility payments</li>
                    <li>And much more!</li>
                </ul>
                <p>Start exploring our services today and experience the ease of DalabaPay.</p>
                <p>If you have any questions or need assistance, our support team is always here to help.</p>
                <p>Best regards,<br>The DalaPay Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} DalaPay. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
  `;

  try {
    await sendEmail(userEmail, subject, text, html);
    res.status(200).json({ message: 'Welcome email sent successfully' });
  } catch (error) {
    console.error('Error sending welcome email:', error);
    res.status(500).json({ message: 'Failed to send welcome email', error: error.message });
  }
});

module.exports = router;