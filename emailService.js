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

    // Determine email subject and purpose text
    const isPasswordReset = purpose === 'password_reset';
    const subject = isPasswordReset 
      ? 'Your DalabaPay Password Reset Code' 
      : 'Your DalabaPay Verification Code';
    
    const purposeText = isPasswordReset 
      ? 'password reset' 
      : 'account verification';
    
    const actionText = isPasswordReset 
      ? 'to reset your password' 
      : 'to verify your email address';

    // Professional HTML Email Template
    const htmlTemplate = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${subject}</title>
        <style>
            /* Reset and Base Styles */
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                background-color: #f8fafc;
                line-height: 1.6;
                color: #334155;
                padding: 20px;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }
            
            /* Main Container */
            .email-container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                overflow: hidden;
                box-shadow: 0 10px 40px rgba(0, 31, 153, 0.08);
                border: 1px solid #e2e8f0;
            }
            
            /* Header */
            .header {
                background: linear-gradient(135deg, #001F99 0%, #304ffe 100%);
                padding: 40px 30px;
                text-align: center;
                color: white;
            }
            
            .logo {
                font-size: 32px;
                font-weight: 700;
                letter-spacing: -0.5px;
                margin-bottom: 8px;
            }
            
            .logo-subtitle {
                font-size: 14px;
                opacity: 0.9;
                font-weight: 400;
                letter-spacing: 1px;
                text-transform: uppercase;
            }
            
            /* Content Area */
            .content {
                padding: 48px 40px;
                text-align: center;
            }
            
            .greeting {
                font-size: 24px;
                font-weight: 600;
                color: #0f172a;
                margin-bottom: 16px;
            }
            
            .message {
                font-size: 16px;
                color: #475569;
                margin-bottom: 32px;
                line-height: 1.7;
            }
            
            /* OTP Display */
            .otp-container {
                margin: 40px 0;
                padding: 32px 20px;
                background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
                border-radius: 16px;
                border: 1px solid #e2e8f0;
            }
            
            .otp-label {
                font-size: 14px;
                color: #64748b;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 16px;
                font-weight: 600;
            }
            
            .otp-code {
                font-family: 'SF Mono', Monaco, 'Courier New', monospace;
                font-size: 48px;
                font-weight: 700;
                letter-spacing: 8px;
                color: #001F99;
                margin: 0;
                line-height: 1;
            }
            
            /* Instructions */
            .instructions {
                background: #fef3f2;
                border: 1px solid #fee2e2;
                border-radius: 12px;
                padding: 24px;
                margin: 32px 0;
                text-align: left;
            }
            
            .instructions-title {
                display: flex;
                align-items: center;
                gap: 8px;
                color: #dc2626;
                font-size: 14px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 12px;
            }
            
            .instructions-list {
                list-style: none;
                padding-left: 0;
            }
            
            .instructions-list li {
                padding: 8px 0;
                color: #475569;
                font-size: 14px;
                display: flex;
                align-items: flex-start;
                gap: 8px;
            }
            
            .instructions-list li:before {
                content: "•";
                color: #dc2626;
                font-weight: bold;
                flex-shrink: 0;
            }
            
            /* Footer */
            .footer {
                background: #f8fafc;
                padding: 32px 40px;
                text-align: center;
                border-top: 1px solid #e2e8f0;
            }
            
            .footer-text {
                color: #64748b;
                font-size: 13px;
                line-height: 1.6;
                margin-bottom: 16px;
            }
            
            .security-notice {
                background: #f1f5f9;
                border-radius: 8px;
                padding: 16px;
                margin-top: 24px;
                border-left: 4px solid #001F99;
            }
            
            .security-notice strong {
                color: #0f172a;
            }
            
            .company-info {
                color: #94a3b8;
                font-size: 12px;
                margin-top: 24px;
                padding-top: 24px;
                border-top: 1px solid #e2e8f0;
            }
            
            /* Responsive */
            @media (max-width: 640px) {
                .content, .footer {
                    padding: 32px 24px;
                }
                
                .header {
                    padding: 32px 24px;
                }
                
                .otp-code {
                    font-size: 36px;
                    letter-spacing: 6px;
                }
                
                .greeting {
                    font-size: 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="email-container">
            <!-- Header -->
            <div class="header">
                <div class="logo">DalabaPay</div>
                <div class="logo-subtitle">${isPasswordReset ? 'Security Verification' : 'Email Verification'}</div>
            </div>
            
            <!-- Content -->
            <div class="content">
                <h1 class="greeting">Hi ${userName},</h1>
                
                <p class="message">
                    ${isPasswordReset 
                      ? 'You requested to reset your DalabaPay account password. Use the verification code below to complete the process.' 
                      : 'Welcome to DalabaPay! Use the verification code below to complete your account setup.'
                    }
                </p>
                
                <!-- OTP Display -->
                <div class="otp-container">
                    <div class="otp-label">Your Verification Code</div>
                    <div class="otp-code">${otp}</div>
                </div>
                
                <p class="message">
                    Enter this code in the DalabaPay app ${actionText}. 
                    <strong>This code expires in 10 minutes.</strong>
                </p>
                
                <!-- Security Instructions -->
                <div class="instructions">
                    <div class="instructions-title">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                        Security Guidelines
                    </div>
                    <ul class="instructions-list">
                        <li>This code is valid for 10 minutes only</li>
                        <li>Never share this code with anyone</li>
                        <li>DalabaPay will never ask for your verification code</li>
                        <li>If you didn't request this ${purposeText}, please ignore this email</li>
                        <li>Contact support immediately if you suspect any suspicious activity</li>
                    </ul>
                </div>
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p class="footer-text">
                    For your security, this code will expire in 10 minutes. Please do not reply to this automated message.
                </p>
                
                <div class="security-notice">
                    <strong>Important:</strong> If you didn't request this ${purposeText}, 
                    your account may be at risk. Please secure your account immediately by 
                    changing your password and enabling two-factor authentication.
                </div>
                
                <div class="company-info">
                    © 2025 DalabaPay Financial Services Ltd.<br>
                    All rights reserved. Licensed by the Central Bank of Nigeria.<br>
                    This email was sent from our secure notification system.
                </div>
            </div>
        </div>
    </body>
    </html>
    `;

    // Plain text version for email clients that don't support HTML
    const textTemplate = `
DalabaPay ${isPasswordReset ? 'Password Reset' : 'Verification'}

Hi ${userName},

${isPasswordReset 
  ? 'You requested to reset your DalabaPay account password.' 
  : 'Welcome to DalabaPay! To complete your account setup,'
}

Your verification code is: ${otp}

Enter this code in the DalabaPay app ${actionText}.

This code expires in 10 minutes.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SECURITY GUIDELINES:
• This code is valid for 10 minutes only
• Never share this code with anyone
• DalabaPay will never ask for your verification code
• If you didn't request this ${purposeText}, please ignore this email
• Contact support immediately if you suspect any suspicious activity
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPORTANT: If you didn't request this ${purposeText}, your account may be at risk. 
Please secure your account immediately.

© 2025 DalabaPay Financial Services Ltd.
All rights reserved. Licensed by the Central Bank of Nigeria.

This is an automated email. Please do not reply.
    `;

    // Email options
    const mailOptions = {
      from: `"DalabaPay Security" <${process.env.EMAIL_FROM_ADDRESS}>`,
      to: email,
      subject: subject,
      html: htmlTemplate,
      text: textTemplate,
      headers: {
        'X-Priority': '1',
        'X-MSMail-Priority': 'High',
        'Importance': 'high',
        'X-Mailer': 'DalabaPay Secure Mailer'
      }
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ ${isPasswordReset ? 'Password Reset' : 'Verification'} email sent to ${email}: ${info.messageId}`);
    
    return { 
      success: true, 
      messageId: info.messageId,
      purpose: purpose
    };

  } catch (error) {
    console.error(`❌ Failed to send ${purpose} email to ${email}:`, error.message);
    
    return { 
      success: false, 
      error: error.message,
      // For development only
      ...(process.env.NODE_ENV === 'development' && { otp: otp })
    };
  }
};

module.exports = { sendVerificationEmail };
