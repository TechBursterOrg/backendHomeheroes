import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Initializing email transporter...');
    
    // Debug: Check what credentials are available
    console.log('🔍 Environment check:');
    console.log('   MAILJET_API_KEY:', process.env.MAILJET_API_KEY ? `Set (length: ${process.env.MAILJET_API_KEY.length})` : 'Not set');
    console.log('   MAILJET_SECRET_KEY:', process.env.MAILJET_SECRET_KEY ? `Set (length: ${process.env.MAILJET_SECRET_KEY.length})` : 'Not set');
    console.log('   EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'Not set');
    
    // Try Mailjet first
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      console.log('📧 Using Mailjet configuration');
      
      emailTransporter = nodemailer.createTransport({
        host: 'in-v3.mailjet.com',
        port: 587,
        secure: false,
        auth: {
          user: process.env.MAILJET_API_KEY,
          pass: process.env.MAILJET_SECRET_KEY
        },
        connectionTimeout: 15000,
        greetingTimeout: 15000,
        socketTimeout: 15000
      });
    } 
    // Fallback to Gmail
    else if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      console.log('📧 Using Gmail configuration');
      
      emailTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD
        }
      });
    } else {
      console.log('❌ No email credentials configured');
      emailServiceStatus = 'missing_credentials';
      return false;
    }

    console.log('🔍 Verifying email connection...');
    await emailTransporter.verify();
    console.log('✅ Email transporter initialized successfully');
    emailServiceStatus = 'ready';
    return true;
    
  } catch (error) {
    console.error('❌ Email transporter initialization failed:', error.message);
    console.log('🔧 Falling back to simulation mode');
    emailServiceStatus = 'simulation';
    return true;
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

    // Simulation mode or no transporter
    if (emailServiceStatus === 'simulation' || !emailTransporter) {
      console.log('🔄 Running in simulation mode');
      console.log('🔑 VERIFICATION TOKEN:', verificationToken);
      console.log('📧 Would send to:', email);
      
      return { 
        success: true, 
        simulated: true,
        message: 'Email simulation mode - check server logs for verification token',
        debugToken: verificationToken
      };
    }

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    const fromEmail = process.env.MAILJET_API_KEY 
      ? 'techbursterdev@gmail.com'  // Use your verified Mailjet sender
      : process.env.EMAIL_USER;

    const mailOptions = {
      from: {
        name: 'HomeHero',
        address: fromEmail
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
    console.log('📨 Message ID:', result.messageId);
    
    return {
      success: true,
      messageId: result.messageId,
      simulated: false
    };

  } catch (error) {
    console.error('❌ Failed to send verification email:', error.message);
    
    // Fallback to simulation mode
    console.log('🔑 FALLBACK - Verification token:', verificationToken);
    
    return {
      success: true, // Still return success but simulated
      simulated: true,
      fallbackToken: verificationToken,
      error: error.message
    };
  }
};