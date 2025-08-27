import nodemailer from 'nodemailer';
import crypto from 'crypto';

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

const EMAIL_CONFIG = {
  service: 'gmail',
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
};

let emailTransporter = null;

export const initializeEmailTransporter = () => {
  if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
    try {
      emailTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
      });
      
      // Verify connection configuration
      emailTransporter.verify(function (error, success) {
        if (error) {
          console.error('❌ Email transporter verification failed:', error.message);
          console.log('⚠️ Email sending will be simulated');
          emailTransporter = null; // Fall back to simulation mode
        } else {
          console.log('✅ Email transporter is ready to send messages');
        }
      });
    } catch (error) {
      console.error('❌ Failed to initialize email transporter:', error.message);
      emailTransporter = null; // Fall back to simulation mode
    }
  } else {
    console.warn('⚠️ Email credentials not configured. Email verification will be simulated.');
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
        <div style="text-align: center; padding: 20px; background: linear-gradient(135deg, #3B82F6 0%, #10B981 100%); border-radius: 10px; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to HomeHero!</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 10px; border: 1px solid #e9ecef;">
          <h2 style="color: #2c3e50; margin-top: 0;">Hi ${name},</h2>
          
          <p style="font-size: 16px; margin-bottom: 25px;">
            Thank you for joining HomeHero! We're excited to have you as part of our community of homeowners and service providers.
          </p>
          
          <p style="font-size: 16px; margin-bottom: 30px;">
            To complete your registration and start using all features, please verify your email address by clicking the button below:
          </p>
          
          <div style="text-align: center; margin: 35px 0;">
            <a href="${verificationUrl}" 
               style="display: inline-block; background: linear-gradient(135deg, #3B82F6 0%, #10B981 100%); color: white; text-decoration: none; padding: 15px 40px; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
              Verify My Email
            </a>
          </div>
          
          <p style="font-size: 14px; color: #6c757d; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6;">
            If the button doesn't work, you can copy and paste this link into your browser:<br>
            <span style="word-break: break-all; color: #3B82F6;">${verificationUrl}</span>
          </p>
          
          <p style="font-size: 14px; color: #6c757d; margin-bottom: 0;">
            This verification link will expire in 24 hours. If you didn't create this account, please ignore this email.
          </p>
        </div>
        
        <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef;">
          <p style="color: #6c757d; font-size: 14px; margin: 0;">
            Questions? Contact us at <a href="mailto:support@homehero.com" style="color: #3B82F6;">support@homehero.com</a>
          </p>
        </div>
      </body>
      </html>
    `,
    text: `
      Hi ${name},
      
      Welcome to HomeHero! Thank you for joining our community.
      
      To complete your registration, please verify your email address by visiting this link:
      ${verificationUrl}
      
      This link will expire in 24 hours.
      
      If you didn't create this account, please ignore this email.
      
      Questions? Contact us at support@homehero.com
      
      Best regards,
      The HomeHero Team
    `
  };
};

export const sendVerificationEmail = async (user, verificationToken) => {
  if (!emailTransporter) {
    console.log('📧 Simulated verification email sent to:', user.email);
    console.log('🔗 Verification URL:', `${FRONTEND_URL}/verify-email?token=${verificationToken}`);
    return { success: true, simulated: true };
  }

  try {
    const verificationUrl = `${FRONTEND_URL}/verify-email?token=${verificationToken}`;
    const emailTemplate = getVerificationEmailTemplate(user.name, verificationUrl);

    const mailOptions = {
      from: {
        name: 'HomeHero Team',
        address: process.env.EMAIL_USER
      },
      to: user.email,
      subject: emailTemplate.subject,
      html: emailTemplate.html,
      text: emailTemplate.text
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('📧 Verification email sent successfully to:', user.email);
    return { success: true, messageId: result.messageId };
  } catch (error) {
    console.error('❌ Failed to send verification email:', error);
    throw error;
  }
};