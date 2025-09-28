// In your emailService.js or server.js
import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'not_initialized';

export const initializeEmailTransporter = async () => {
  try {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log('⚠️ Email credentials not configured - running in simulation mode');
      emailServiceStatus = 'simulation_mode';
      return false;
    }

    // Create transporter with better timeout settings
    emailTransporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      pool: true,
      maxConnections: 5,
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 5,
      socketTimeout: 30000, // 30 seconds
      connectionTimeout: 10000, // 10 seconds
      logger: true,
      debug: false
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