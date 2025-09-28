import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'not_initialized';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Initializing email transporter...');
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log('❌ Email credentials missing - running in simulation mode');
      console.log('   EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'Not set');
      console.log('   EMAIL_PASSWORD:', process.env.EMAIL_PASSWORD ? 'Set' : 'Not set');
      emailServiceStatus = 'simulation_mode';
      return false;
    }

    console.log('📧 Creating Gmail transporter...');
    
    // FIXED: Changed createTransporter to createTransport
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      connectionTimeout: 10000,
      socketTimeout: 15000,
      logger: true,
      debug: process.env.NODE_ENV === 'development'
    });

    console.log('🔍 Verifying email connection...');
    await emailTransporter.verify();
    
    console.log('✅ Email transporter initialized successfully!');
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
    if (emailServiceStatus !== 'ready' || !emailTransporter) {
      console.log('📧 SIMULATION MODE: Would send verification email to:', user.email);
      console.log('📧 Verification token:', verificationToken);
      console.log('🔗 Verification URL:', `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`);
      return { success: true, simulated: true };
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
    
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
            .code { background: #f4f4f4; padding: 10px; border-radius: 5px; font-family: monospace; margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Welcome to HomeHero! 🎉</h1>
              <p>Verify your email address to get started</p>
            </div>
            <div class="content">
              <p>Hello <strong>${user.name}</strong>,</p>
              <p>Thank you for signing up for HomeHero! To complete your registration, please verify your email address by clicking the button below:</p>
              
              <div style="text-align: center;">
                <a href="${verificationUrl}" class="button">Verify Email Address</a>
              </div>
              
              <p>Or copy and paste this link in your browser:</p>
              <div class="code">${verificationUrl}</div>
              
              <p>This verification link will expire in 24 hours.</p>
              
              <p>If you didn't create an account with HomeHero, please ignore this email.</p>
              
              <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>© 2024 HomeHero. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `
    };

    console.log('📤 Sending verification email to:', user.email);
    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Verification email sent successfully! Message ID:', result.messageId);
    
    return { success: true, messageId: result.messageId };

  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    return { success: false, error: error.message };
  }
};