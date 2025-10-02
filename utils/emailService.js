import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Initializing email transporter...');
    
    // Priority 1: Try Mailjet
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      console.log('📧 Using Mailjet configuration');
      
      emailTransporter = nodemailer.createTransport({
        host: 'in-v3.mailjet.com',
        port: 587,
        secure: false, // Use TLS
        auth: {
          user: process.env.MAILJET_API_KEY,
          pass: process.env.MAILJET_SECRET_KEY
        },
        connectionTimeout: 15000,
        greetingTimeout: 15000,
        socketTimeout: 15000
      });
      
    } 
    // Priority 2: Fallback to Gmail with multiple port attempts
    else if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      console.log('📧 Using Gmail configuration as fallback');
      
      const gmailConfigs = [
        { port: 465, secure: true, description: 'SSL (465)' },
        { port: 587, secure: false, requireTLS: true, description: 'TLS (587)' },
        { port: 25, secure: false, description: 'Standard (25)' }
      ];
      
      for (const config of gmailConfigs) {
        try {
          console.log(`Testing Gmail ${config.description}...`);
          emailTransporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            ...config,
            auth: {
              user: process.env.EMAIL_USER,
              pass: process.env.EMAIL_PASSWORD
            },
            connectionTimeout: 10000
          });
          
          await emailTransporter.verify();
          console.log(`✅ Gmail ${config.description} works!`);
          break;
        } catch (error) {
          console.log(`❌ Gmail ${config.description} failed: ${error.message}`);
          emailTransporter = null;
        }
      }
    } else {
      console.log('❌ No email credentials configured');
      emailServiceStatus = 'missing_credentials';
      return false;
    }

    if (!emailTransporter) {
      console.log('🔧 All email configurations failed, using simulation mode');
      emailServiceStatus = 'simulation';
      return true;
    }

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

    // Determine sender email based on service
    const fromEmail = process.env.MAILJET_API_KEY 
      ? 'noreply@homeheroes.help'  // You can use any verified email with Mailjet
      : process.env.EMAIL_USER;

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;
    
    const mailOptions = {
      from: {
        name: 'HomeHero',
        address: fromEmail
      },
      to: email,
      subject: 'Verify Your HomeHero Account',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .token { background: white; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 20px 0; border-radius: 8px; border: 2px dashed #dee2e6; }
            .button { display: inline-block; padding: 15px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>Welcome to HomeHero! 🏠</h1>
            <p>Your home services platform</p>
          </div>
          <div class="content">
            <p>Hello <strong>${name}</strong>,</p>
            <p>Thank you for joining HomeHero! To get started, please verify your email address using the code below:</p>
            
            <div class="token">${verificationToken}</div>
            
            <p style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </p>
            
            <p style="color: #666; font-size: 14px;">
              If the button doesn't work, copy and paste this link in your browser:<br>
              <span style="color: #667eea; word-break: break-all;">${verificationUrl}</span>
            </p>
            
            <div class="footer">
              <p>This verification code will expire in 24 hours.</p>
              <p>If you didn't create this account, please ignore this email.</p>
            </div>
          </div>
        </body>
        </html>
      `,
      text: `
Welcome to HomeHero!

Hello ${name},

Thank you for joining HomeHero! To get started, please verify your email address using this code:

${verificationToken}

Or visit this link to verify:
${verificationUrl}

This verification code will expire in 24 hours.

If you didn't create this account, please ignore this email.
      `
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Verification email sent successfully to:', email);
    console.log('📨 Message ID:', result.messageId);
    
    return {
      success: true,
      messageId: result.messageId,
      simulated: false,
      provider: 'mailjet'
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