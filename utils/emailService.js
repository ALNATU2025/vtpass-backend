// utils/emailService.js
// This file handles sending emails using SendGrid.

const sgMail = require('@sendgrid/mail');

// Set the SendGrid API Key from environment variables.
// IMPORTANT: Ensure SENDGRID_API_KEY is set in your .env file and on Render.
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Sends an email using SendGrid.
 * @param {string} to - The recipient's email address.
 * @param {string} subject - The subject line of the email.
 * @param {string} text - The plain text content of the email.
 * @param {string} html - The HTML content of the email (for rich formatting).
 */
const sendEmail = async (to, subject, text, html) => {
  const msg = {
    to,
    from: process.env.SENDER_EMAIL, // Your verified sender email (e.g., no-reply@yourdomain.com)
    subject,
    text,
    html,
  };

  try {
    await sgMail.send(msg);
    console.log(`Email sent successfully to: ${to}`);
  } catch (error) {
    console.error('Error sending email:');
    // Log the full error response from SendGrid for debugging
    if (error.response) {
      console.error(error.response.body);
    } else {
      console.error(error);
    }
    throw new Error('Failed to send email. Check backend logs for details.');
  }
};

module.exports = { sendEmail };