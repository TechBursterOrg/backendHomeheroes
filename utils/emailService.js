// utils/emailService.js - UPDATED VERSION
import nodemailer from 'nodemailer';

const getEmailConfig = () => {
  const config = {
    service: 'gmail',
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
    connectionTimeout: 30000,
    greetingTimeout: 30000,
    socketTimeout: 30000,
    logger: true,
    debug: true,
    tls: {
      rejectUnauthorized: false
    }
  };
  return config;
};

let emailTransporter = null;

export const initializeEmailTransporter = async () => {
  console.log('🔧 Initializing email transporter for:', process.env.NODE_ENV);
  
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.error('❌ Email credentials missing in production');
    return false;
  }

  try {
    emailTransporter = nodemailer.createTransporter(getEmailConfig());
    
    // Test connection
    await emailTransporter.verify();
    console.log('✅ SMTP connection verified successfully');
    
    return true;
  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error);
    
    // More detailed error logging
    if (error.code === 'EAUTH') {
      console.error('🔐 Authentication failed - check email credentials');
    } else if (error.code === 'ECONNECTION') {
      console.error('🌐 Connection failed - check network/SMTP settings');
    } else {
      console.error('🔧 Other error:', error);
    }
    
    return false;
  }
};

export const sendVerificationEmail = async (user, verificationToken) => {
  // Force re-initialization on each send
  const initialized = await initializeEmailTransporter();
  
  if (!initialized || !emailTransporter) {
    console.error('❌ Cannot send email - transporter not ready');
    return { success: false, error: 'Email service unavailable' };
  }

  try {
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
    const mailOptions = {
      from: {
        name: 'HomeHero',
        address: process.env.EMAIL_USER
      },
      to: user.email,
      subject: 'Verify Your HomeHero Account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Verify Your HomeHero Account</h2>
          <p>Hello ${user.name},</p>
          <p>Please click the link below to verify your email address:</p>
          <a href="${verificationUrl}" style="display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">
            Verify Email
          </a>
          <p>Or copy this URL into your browser:</p>
          <p>${verificationUrl}</p>
          <p>This link will expire in 24 hours.</p>
        </div>
      `,
      text: `Verify your HomeHero account: ${verificationUrl}`
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Verification email sent successfully:', result.messageId);
    
    return { 
      success: true, 
      messageId: result.messageId 
    };
  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    return { 
      success: false, 
      error: error.message 
    };
  }
};

export const getEmailTransporter = () => emailTransporter;