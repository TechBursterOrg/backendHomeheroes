import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log('❌ Email credentials not configured');
      return false;
    }

    console.log('🔧 Initializing email transporter...');
    
    // Create transporter with better timeout settings
    const transporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      connectionTimeout: 10000, // 10 seconds
      greetingTimeout: 10000,
      socketTimeout: 10000,
      logger: true,
      debug: true
    });

    // Verify connection with timeout
    const verifyPromise = transporter.verify();
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Email verification timeout')), 15000);
    });

    await Promise.race([verifyPromise, timeoutPromise]);
    console.log('✅ Email transporter initialized successfully');
    return true;
    
  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error.message);
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
    console.log(`📡 Email service status: ${emailServiceStatus}`);

    // If email service is not ready, simulate success
    if (!emailTransporter || emailServiceStatus !== 'ready') {
      console.log('🔄 Email service not available - running in simulation mode');
      
      // In simulation mode, we still "successfully" send the email
      // but just log the token for development purposes
      console.log('📧 SIMULATION: Verification email would be sent to:', email);
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
    
    // Even if email fails, we don't want to break the signup flow
    // Log the token so users can still verify
    console.log('🔑 Verification token (for manual use):', verificationToken);
    
    return {
      success: false,
      error: error.message,
      simulated: false,
      fallbackToken: verificationToken // Provide token for manual verification
    };
  }
};