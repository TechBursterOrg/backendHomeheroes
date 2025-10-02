import { sendVerificationEmailViaAPI } from './mailjetApi.js';

let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Checking Mailjet API configuration...');
    
    if (!process.env.MAILJET_API_KEY || !process.env.MAILJET_SECRET_KEY) {
      console.log('❌ Mailjet credentials not configured');
      emailServiceStatus = 'missing_credentials';
      return false;
    }

    console.log('✅ Mailjet API configuration ready');
    emailServiceStatus = 'ready';
    return true;
    
  } catch (error) {
    console.error('❌ Email service initialization failed:', error.message);
    emailServiceStatus = 'simulation';
    return true;
  }
};

export const getEmailServiceStatus = () => emailServiceStatus;

export const sendVerificationEmail = async (user, verificationToken) => {
  try {
    // Use Mailjet API directly (bypasses SMTP blocking)
    if (emailServiceStatus === 'ready') {
      return await sendVerificationEmailViaAPI(user, verificationToken);
    }
    
    // Fallback to simulation
    console.log('🔄 Running in simulation mode');
    console.log('🔑 VERIFICATION TOKEN:', verificationToken);

    emailTransporter = nodemailer.createTransport({
  host: 'smtp.elasticemail.com',
  port: 2525, // This port is often not blocked
  auth: {
    user: 'your@email.com',
    pass: 'your_elastic_email_api_key'
  }
});
    
    return { 
      success: true, 
      simulated: true,
      debugToken: verificationToken
    };

  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    
    // Final fallback
    console.log('🔑 FALLBACK - Verification token:', verificationToken);

    
    return {
      success: true,
      simulated: true,
      fallbackToken: verificationToken
    };
  }
};

