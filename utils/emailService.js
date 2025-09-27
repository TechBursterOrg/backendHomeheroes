import nodemailer from 'nodemailer';
import crypto from 'crypto';

const FRONTEND_URL = process.env.FRONTEND_URL || 'https://homeheroes.help';

// Enhanced email configuration with better error handling
const getEmailConfig = () => {
  const config = {
    service: 'gmail',
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
    // Add connection timeout and better error handling
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 10000,
    logger: process.env.NODE_ENV === 'development',
    debug: process.env.NODE_ENV === 'development'
  };

  console.log('🔧 Email Configuration:', {
    user: process.env.EMAIL_USER ? 'Set' : 'Not set',
    password: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set',
    host: config.host,
    port: config.port,
    environment: process.env.NODE_ENV
  });

  return config;
};

let emailTransporter = null;
let isTransporterInitialized = false;

export const initializeEmailTransporter = async () => {
  console.log('🚀 Initializing email transporter for production...');
  
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.error('❌ Email credentials missing:', {
      EMAIL_USER: process.env.EMAIL_USER ? 'Set' : 'Not set',
      EMAIL_PASSWORD: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set'
    });
    return false;
  }

  try {
    // Create test configuration first
    const testTransporter = nodemailer.createTransporter(getEmailConfig());
    
    // Verify connection
    await testTransporter.verify();
    console.log('✅ SMTP connection verified successfully');
    
    emailTransporter = testTransporter;
    isTransporterInitialized = true;
    
    // Test email sending capability
    await sendTestEmail();
    return true;
  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error);
    console.error('🔧 Error details:', {
      code: error.code,
      command: error.command,
      response: error.response
    });
    
    emailTransporter = null;
    isTransporterInitialized = false;
    return false;
  }
};

const sendTestEmail = async () => {
  if (!emailTransporter) return;
  
  try {
    const testMailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER, // Send to yourself for testing
      subject: 'HomeHero Production Email Test',
      text: `This is a test email from HomeHero production server sent at ${new Date().toISOString()}`,
      html: `<p>HomeHero production email test - ${new Date().toISOString()}</p>`
    };

    const result = await emailTransporter.sendMail(testMailOptions);
    console.log('✅ Production email test successful:', result.messageId);
    return true;
  } catch (error) {
    console.error('❌ Production email test failed:', error);
    return false;
  }
};

export const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

const getVerificationEmailTemplate = (name, verificationUrl) => {
  return {
    subject: 'Verify Your HomeHero Account',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email - HomeHero</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #3B82F6 0%, #10B981 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Verify Your HomeHero Account</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
          <h2 style="color: #2c3e50; margin-top: 0;">Hi ${name},</h2>
          
          <p style="font-size: 16px; margin-bottom: 25px;">
            Thank you for joining HomeHero! Please verify your email address to activate your account.
          </p>
          
          <div style="text-align: center; margin: 35px 0;">
            <a href="${verificationUrl}" 
               style="display: inline-block; background: linear-gradient(135deg, #3B82F6 0%, #10B981 100%); color: white; text-decoration: none; padding: 15px 40px; border-radius: 8px; font-weight: bold; font-size: 16px;">
              Verify Email Address
            </a>
          </div>
          
          <p style="font-size: 14px; color: #6c757d;">
            Or copy this link into your browser:<br>
            <span style="word-break: break-all; color: #3B82F6;">${verificationUrl}</span>
          </p>
          
          <p style="font-size: 14px; color: #6c757d; margin-bottom: 0;">
            This link expires in 24 hours.
          </p>
        </div>
      </body>
      </html>
    `,
    text: `Verify your HomeHero account: ${verificationUrl}`
  };
};

export const sendVerificationEmail = async (user, verificationToken) => {
  console.log('📧 Sending verification email in production environment...');
  console.log('🔧 Environment:', process.env.NODE_ENV);
  console.log('👤 Recipient:', user.email);

  try {
  console.log('📧 Attempting to send verification email...');
  
  const emailResult = await sendVerificationEmail(savedUser, verificationToken);
  
  if (emailResult.success) {
    console.log('✅ Email sent successfully:', emailResult.messageId);
  } else {
    console.warn('⚠️ Email sending failed, but user was created:', emailResult.error);
    // Don't fail the signup process - just log the error
  }
} catch (emailError) {
  console.error('❌ Email sending critical error:', emailError);
  // Still don't fail the signup process
}
  
  if (!emailTransporter || !isTransporterInitialized) {
    console.error('❌ Email transporter not initialized. Attempting to initialize...');
    const initialized = await initializeEmailTransporter();
    
    if (!initialized) {
      console.log('📧 SIMULATION MODE: Email transporter not available');
      console.log('🔗 Verification URL would be:', `${FRONTEND_URL}/verify-email?token=${verificationToken}`);
      return { success: true, simulated: true, message: 'Email simulation mode' };
    }
  }

  try {
    const verificationUrl = `${FRONTEND_URL}/verify-email?token=${verificationToken}`;
    const emailTemplate = getVerificationEmailTemplate(user.name, verificationUrl);

    const mailOptions = {
      from: {
        name: 'HomeHero',
        address: process.env.EMAIL_USER
      },
      to: user.email,
      subject: emailTemplate.subject,
      html: emailTemplate.html,
      text: emailTemplate.text,
      // Add headers for better deliverability
      headers: {
        'X-Priority': '1',
        'X-Mailer': 'HomeHero'
      }
    };

    console.log('📤 Sending email with options:', {
      from: mailOptions.from,
      to: mailOptions.to,
      subject: mailOptions.subject
    });

    const result = await emailTransporter.sendMail(mailOptions);
    
    console.log('✅ Verification email sent successfully:', {
      messageId: result.messageId,
      response: result.response
    });
    
    return { 
      success: true, 
      messageId: result.messageId,
      response: result.response 
    };
  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    console.error('🔧 Full error details:', {
      name: error.name,
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response
    });
    
    // Don't throw error - just log it and continue
    return { 
      success: false, 
      error: error.message,
      simulated: true 
    };
  }
};

// Export transporter for debugging
export const getEmailTransporter = () => emailTransporter;
export const getTransporterStatus = () => ({
  initialized: isTransporterInitialized,
  hasCredentials: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
  environment: process.env.NODE_ENV
});