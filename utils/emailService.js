// utils/emailService.js - COMPLETE FIX
import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Initializing email transporter...');
    
    // Check if credentials exist
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.warn('⚠️ Email credentials not configured. Running in simulation mode.');
      emailServiceStatus = 'simulation';
      return false;
    }

    // Create transporter with production-optimized settings
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      // Production timeout settings
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 5,
      connectionTimeout: 30000, // 30 seconds
      greetingTimeout: 30000,
      socketTimeout: 45000,
      secure: true,
      tls: {
        rejectUnauthorized: false
      },
      debug: process.env.NODE_ENV === 'development',
      logger: process.env.NODE_ENV === 'development'
    });

    // Verify connection
    await emailTransporter.verify();
    console.log('✅ Email transporter initialized and verified');
    emailServiceStatus = 'ready';
    return true;

  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error.message);
    emailServiceStatus = 'failed';
    emailTransporter = null;
    return false;
  }
};

export const getEmailTransporter = () => emailTransporter;
export const getEmailServiceStatus = () => emailServiceStatus;

export const sendVerificationEmail = async (user, verificationToken) => {
  try {
    // If email service is not ready, simulate success in development
    if (!emailTransporter || emailServiceStatus !== 'ready') {
      console.log('📧 SIMULATION: Email verification would be sent to:', user.email);
      console.log('🔑 Verification token:', verificationToken);
      
      if (process.env.NODE_ENV === 'production') {
        return { 
          success: false, 
          error: 'Email service unavailable',
          simulated: true 
        };
      }
      
      return { 
        success: true, 
        simulated: true,
        message: 'Email simulation mode'
      };
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
    
    const mailOptions = {
      from: {
        name: 'HomeHero',
        address: process.env.EMAIL_USER
      },
      to: user.email,
      subject: 'Verify Your HomeHero Account',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
            .code { background: #f4f4f4; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 18px; text-align: center; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Welcome to HomeHero!</h1>
              <p>Verify your email address to get started</p>
            </div>
            <div class="content">
              <p>Hello ${user.name},</p>
              <p>Thank you for signing up for HomeHero! To complete your registration, please verify your email address by clicking the button below:</p>
              
              <div style="text-align: center;">
                <a href="${verificationUrl}" class="button">Verify Email Address</a>
              </div>
              
              <p>Or use this verification code:</p>
              <div class="code">${verificationToken}</div>
              
              <p>If you didn't create an account with HomeHero, you can safely ignore this email.</p>
              
              <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>© 2024 HomeHero. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `Welcome to HomeHero! Please verify your email by visiting: ${verificationUrl} or using this code: ${verificationToken}`
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Verification email sent successfully to:', user.email);
    
    return {
      success: true,
      messageId: result.messageId,
      simulated: false
    };

  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    return {
      success: false,
      error: error.message,
      simulated: false
    };
  }
};