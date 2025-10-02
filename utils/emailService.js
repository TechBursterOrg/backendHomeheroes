import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Initializing Mailjet email transporter...');
    
    // Debug: Check what credentials are available
    console.log('🔍 Environment check:');
    console.log('   MAILJET_API_KEY:', process.env.MAILJET_API_KEY ? `Set (length: ${process.env.MAILJET_API_KEY.length})` : 'Not set');
    console.log('   MAILJET_SECRET_KEY:', process.env.MAILJET_SECRET_KEY ? `Set (length: ${process.env.MAILJET_SECRET_KEY.length})` : 'Not set');
    console.log('   EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'Not set');
    
    if (!process.env.MAILJET_API_KEY || !process.env.MAILJET_SECRET_KEY) {
      console.log('❌ Mailjet credentials not configured in environment variables');
      emailServiceStatus = 'missing_credentials';
      return false;
    }

    console.log('📧 Creating Mailjet transporter...');
    
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

    console.log('🔍 Verifying Mailjet connection...');
    await emailTransporter.verify();
    console.log('✅ Mailjet transporter initialized successfully');
    emailServiceStatus = 'ready';
    return true;
    
  } catch (error) {
    console.error('❌ Mailjet transporter initialization failed:', error.message);
    console.error('🔍 Full error:', error);
    emailServiceStatus = 'failed';
    return false;
  }
};

export const getEmailTransporter = () => emailTransporter;
export const getEmailServiceStatus = () => emailServiceStatus;

// ... rest of your sendVerificationEmail function remains the same