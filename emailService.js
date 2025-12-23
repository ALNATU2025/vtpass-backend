const nodemailer = require('nodemailer');

const sendVerificationEmail = async (email, otp, userName = 'User', purpose = 'verification') => {
  try {
    // Create transporter
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: process.env.SMTP_PORT || 587,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      },
      tls: {
        rejectUnauthorized: false
      }
    });

    // HTML Email Template
    const htmlTemplate = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; background:#f8f9fa; padding:20px; }
            .container { max-width:600px; margin:auto; background:white; border-radius:12px; overflow:hidden; box-shadow:0 4px 20px rgba(0,0,0,0.1); }
            .header { background:#001F99; padding:30px; text-align:center; color:white; }
            .content { padding:40px; text-align:center; }
            .otp-box { background:#f8f9ff; border:2px solid #e0e7ff; padding:20px; font-size:42px; font-weight:bold; letter-spacing:8px; margin:30px 0; color:#001F99; border-radius:8px; }
            .footer { background:#f9fafb; padding:20px; text-align:center; color:#666; font-size:12px; }
            .warning { color:#ff6b6b; margin:20px 0; padding:15px; background:#fff5f5; border-radius:6px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>DalabaPay</h2>
                <p>Email Verification</p>
            </div>
            <div class="content">
                <h3>Hi ${userName},</h3>
                <p>Your verification code is:</p>
                <div class="otp-box">${otp}</div>
                <p>Enter this code in the app to verify your email.</p>
                <div class="warning">
                    ⚠️ This code expires in 10 minutes.<br>
                    ⚠️ Never share this code with anyone.
                </div>
            </div>
            <div class="footer">
                <p>© 2025 DalabaPay. All rights reserved.</p>
                <p>This is an automated email, please do not reply.</p>
            </div>
        </div>
    </body>
    </html>
    `;

    // Email options
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_ADDRESS}>`,
      to: email,
      subject: 'Your DalabaPay Verification Code',
      html: htmlTemplate,
      text: `Your DalabaPay verification code is: ${otp}. This code expires in 10 minutes. Do not share this code with anyone.`
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${email}: ${info.messageId}`);
    
    return { success: true, messageId: info.messageId };

  } catch (error) {
    console.error(`❌ Failed to send email to ${email}:`, error.message);
    
    // If email fails, still allow OTP to work (user can request again)
    return { 
      success: false, 
      error: error.message,
      // For development, you can return the OP in development mode
      otp: process.env.NODE_ENV === 'development' ? otp : undefined
    };
  }
};

module.exports = { sendVerificationEmail };
