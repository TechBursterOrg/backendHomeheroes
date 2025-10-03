import nodemailer from 'nodemailer';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Checking email configuration...');
    
    if (!process.env.MAILJET_API_KEY || !process.env.MAILJET_SECRET_KEY) {
      console.log('❌ Mailjet credentials not configured, using simulation mode');
      emailServiceStatus = 'simulation';
      return true;
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
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
    
    console.log('🔗 Verification URL:', verificationUrl);

    if (emailServiceStatus === 'ready' && process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      // Use Mailjet API
      return await sendVerificationEmailViaMailjet(user, verificationToken, verificationUrl);
    } else {
      // Simulation mode - log the link
      console.log('🔄 Running in simulation mode');
      console.log('📧 Verification email would be sent to:', user.email);
      console.log('🔗 Verification link:', verificationUrl);
      
      return { 
        success: true, 
        simulated: true,
        debugLink: verificationUrl
      };
    }

  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    
    // Fallback to simulation
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
    console.log('🔑 FALLBACK - Verification link:', verificationUrl);
    
    return {
      success: true,
      simulated: true,
      fallbackLink: verificationUrl
    };
  }
};

const sendVerificationEmailViaMailjet = async (user, verificationToken, verificationUrl) => {
  try {
    const response = await fetch('https://api.mailjet.com/v3.1/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(`${process.env.MAILJET_API_KEY}:${process.env.MAILJET_SECRET_KEY}`).toString('base64')
      },
      body: JSON.stringify({
        Messages: [
          {
            From: {
              Email: "noreply@homeheroes.help",
              Name: "HomeHero"
            },
            To: [
              {
                Email: user.email,
                Name: user.name
              }
            ],
            Subject: "Verify Your HomeHero Account",
            HTMLPart: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
                <div style="text-align: center; margin-bottom: 30px;">
                  <h1 style="color: #2563eb; margin: 0;">HomeHero</h1>
                  <p style="color: #6b7280; margin: 5px 0 0 0;">Home Services Hub</p>
                </div>
                
                <h2 style="color: #1f2937; text-align: center;">Verify Your Email Address</h2>
                
                <p style="color: #4b5563; line-height: 1.6;">Hello ${user.name},</p>
                
                <p style="color: #4b5563; line-height: 1.6;">Thank you for creating an account with HomeHero! To complete your registration and start using our services, please verify your email address by clicking the button below:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${verificationUrl}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
                    Verify Email Address
                  </a>
                </div>
                
                <p style="color: #4b5563; line-height: 1.6; font-size: 14px;">Or copy and paste this link in your browser:</p>
                <p style="color: #2563eb; word-break: break-all; font-size: 14px; background: #f3f4f6; padding: 10px; border-radius: 5px;">${verificationUrl}</p>
                
                <p style="color: #4b5563; line-height: 1.6; font-size: 14px;">This verification link will expire in 24 hours.</p>
                
                <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center;">
                  <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                    If you didn't create an account with HomeHero, please ignore this email.
                  </p>
                </div>
              </div>
            `,
            TextPart: `
              Verify Your HomeHero Account\n\n
              Hello ${user.name},\n\n
              Thank you for creating an account with HomeHero! To complete your registration, please verify your email address by visiting the following link:\n\n
              ${verificationUrl}\n\n
              This verification link will expire in 24 hours.\n\n
              If you didn't create an account with HomeHero, please ignore this email.
            `
          }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Mailjet API error: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const result = await response.json();
    console.log('✅ Verification email sent via Mailjet API');
    
    return {
      success: true,
      messageId: result.Messages[0].To[0].MessageID,
      simulated: false
    };

  } catch (error) {
    console.error('❌ Failed to send email via Mailjet API:', error.message);
    throw error;
  }
};