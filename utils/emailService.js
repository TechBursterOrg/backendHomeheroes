import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Initializing email transporter...');
    console.log('📧 Email config check:', {
      emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
      emailPassword: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set',
      environment: process.env.NODE_ENV
    });

    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log('❌ Email credentials not configured');
      emailServiceStatus = 'missing_credentials';
      return false;
    }

    // ✅ CORRECT: Use createTransport (not createTransporter)
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 10000
    });

    // Verify connection
    console.log('🔍 Verifying email connection...');
    await emailTransporter.verify();
    
    console.log('✅ Email transporter initialized successfully');
    emailServiceStatus = 'ready';
    return true;
    
  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error.message);
    emailServiceStatus = 'failed';
    return false;
  }
};

export const getEmailTransporter = () => emailTransporter;
export const getEmailServiceStatus = () => emailServiceStatus;

export const sendVerificationEmail = async (user, verificationToken) => {
  try {
    const email = user.email || user;
    const name = user.name || 'User';

    console.log(`📧 Attempting to send verification to: ${email}`);
    console.log(`🔑 Token: ${verificationToken}`);

    if (!emailTransporter || emailServiceStatus !== 'ready') {
      console.log('🔄 Email service not available - running in simulation mode');
      console.log('🔑 SIMULATION: Verification token:', verificationToken);
      
      return { 
        success: true, 
        simulated: true,
        message: 'Email sent in simulation mode'
      };
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    const mailOptions = {
      from: {
        name: 'HomeHero',
        address: process.env.EMAIL_USER
      },
      to: email,
      subject: 'Verify Your HomeHero Account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Welcome to HomeHero!</h2>
          <p>Hello ${name},</p>
          <p>Please verify your email address using this code:</p>
          <div style="background: #f4f4f4; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${verificationToken}
          </div>
          <p>Or click the link below:</p>
          <a href="${verificationUrl}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
            Verify Email Address
          </a>
        </div>
      `,
      text: `Verify your HomeHero account using this code: ${verificationToken} or visit: ${verificationUrl}`
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Verification email sent successfully to:', email);
    
    return {
      success: true,
      messageId: result.messageId,
      simulated: false
    };

  } catch (error) {
    console.error('❌ Failed to send verification email:', error.message);
    return {
      success: false,
      error: error.message,
      simulated: false,
      fallbackToken: verificationToken
    };
  }
};