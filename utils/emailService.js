import nodemailer from 'nodemailer';
import fetch from 'node-fetch';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

// Initialize email transporter
export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Checking email configuration...');
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log('❌ Email credentials not configured, using simulation mode');
      emailServiceStatus = 'simulation';
      return true;
    }

    // For production, use Mailjet API directly
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      console.log('✅ Mailjet API configuration ready');
      emailServiceStatus = 'ready';
      return true;
    }

    // Fallback to nodemailer with Gmail
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    await emailTransporter.verify();
    console.log('✅ Email transporter ready');
    emailServiceStatus = 'ready';
    return true;
    
  } catch (error) {
    console.error('❌ Email service initialization failed:', error.message);
    emailServiceStatus = 'simulation';
    return true;
  }
};

export const getEmailServiceStatus = () => emailServiceStatus;

// Send verification email with LINK instead of token
export const sendVerificationEmail = async (user, verificationToken) => {
  try {
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const verificationUrl = `${process.env.API_URL || 'http://localhost:3001'}/api/auth/verify-email/${verificationToken}`;
    
    const email = user.email || user;
    const name = user.name || 'User';

    console.log('📧 Sending verification email to:', email);
    console.log('🔗 Verification URL:', verificationUrl);

    // Use Mailjet API if configured
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      return await sendVerificationEmailViaMailjet(user, verificationUrl);
    }

    // Use nodemailer as fallback
    if (emailTransporter) {
      const mailOptions = {
        from: {
          name: 'HomeHero',
          address: process.env.EMAIL_USER
        },
        to: email,
        subject: 'Verify Your HomeHero Account',
        html: generateVerificationEmailHTML(name, verificationUrl),
        text: generateVerificationEmailText(name, verificationUrl)
      };

      const result = await emailTransporter.sendMail(mailOptions);
      console.log('✅ Verification email sent via nodemailer');
      
      return {
        success: true,
        messageId: result.messageId,
        simulated: false
      };
    }

    // Simulation mode - log the verification URL
    console.log('🔄 SIMULATION MODE - Verification URL:', verificationUrl);
    
    return {
      success: true,
      simulated: true,
      verificationUrl: verificationUrl
    };

  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    
    // Final fallback - just log the URL
    const verificationUrl = `${process.env.API_URL || 'http://localhost:3001'}/api/auth/verify-email/${verificationToken}`;
    console.log('🔑 FALLBACK - Verification URL:', verificationUrl);
    
    return {
      success: true,
      simulated: true,
      verificationUrl: verificationUrl
    };
  }
};

// Mailjet API integration
const sendVerificationEmailViaMailjet = async (user, verificationUrl) => {
  try {
    const email = user.email || user;
    const name = user.name || 'User';

    console.log('📧 Sending verification via Mailjet API to:', email);

    const response = await fetch('https://api.mailjet.com/v3.1/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(`${process.env.MAILJET_API_KEY}:${process.env.MAILJET_SECRET_KEY}`).toString('base64')
      },
      body: JSON.stringify({
        Messages: [
          {
            From: {
              Email: process.env.EMAIL_USER || "noreply@homehero.com",
              Name: "HomeHero"
            },
            To: [
              {
                Email: email,
                Name: name
              }
            ],
            Subject: "Verify Your HomeHero Account",
            HTMLPart: generateVerificationEmailHTML(name, verificationUrl),
            TextPart: generateVerificationEmailText(name, verificationUrl)
          }
        ]
      })
    });

    if (!response.ok) {
      throw new Error(`Mailjet API error: ${response.status} ${response.statusText}`);
    }

    const result = await response.json();
    console.log('✅ Verification email sent via Mailjet API');
    
    return {
      success: true,
      messageId: result.Messages[0].To[0].MessageID,
      simulated: false
    };

  } catch (error) {
    console.error('❌ Failed to send email via Mailjet API:', error.message);
    throw error;
  }
};

// HTML email template
const generateVerificationEmailHTML = (name, verificationUrl) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
        .verification-url { background: #f4f4f4; padding: 15px; border-radius: 5px; word-break: break-all; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Welcome to HomeHero!</h1>
        <p>Verify your email address to get started</p>
      </div>
      <div class="content">
        <p>Hello <strong>${name}</strong>,</p>
        <p>Thank you for signing up for HomeHero! To complete your registration and start using your account, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center;">
          <a href="${verificationUrl}" class="button">Verify Email Address</a>
        </div>
        
        <p>Or copy and paste this link in your browser:</p>
        <div class="verification-url">
          ${verificationUrl}
        </div>
        
        <p><strong>This link will expire in 24 hours.</strong></p>
        
        <p>If you didn't create an account with HomeHero, you can safely ignore this email.</p>
        
        <div class="footer">
          <p>This is an automated message. Please do not reply to this email.</p>
          <p>© ${new Date().getFullYear()} HomeHero. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Plain text email template
const generateVerificationEmailText = (name, verificationUrl) => {
  return `
Welcome to HomeHero!

Hello ${name},

Thank you for signing up for HomeHero! To complete your registration and start using your account, please verify your email address by visiting the following link:

${verificationUrl}

This link will expire in 24 hours.

If you didn't create an account with HomeHero, you can safely ignore this email.

This is an automated message. Please do not reply to this email.

© ${new Date().getFullYear()} HomeHero. All rights reserved.
  `;
};