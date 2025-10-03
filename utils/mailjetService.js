import fetch from 'node-fetch';

export class MailjetService {
  constructor() {
    this.apiKey = process.env.MAILJET_API_KEY;
    this.secretKey = process.env.MAILJET_SECRET_KEY;
    this.fromEmail = process.env.MAILJET_FROM_EMAIL || "noreply@homeheroes.help";
    this.fromName = process.env.MAILJET_FROM_NAME || "HomeHero";
  }

  async sendVerificationEmail(user, verificationToken) {
    try {
      console.log('📧 Sending verification via Mailjet API to:', user.email);
      
      if (!this.apiKey || !this.secretKey) {
        throw new Error('Mailjet API credentials not configured');
      }

      const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`;
      
      const response = await fetch('https://api.mailjet.com/v3.1/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + Buffer.from(`${this.apiKey}:${this.secretKey}`).toString('base64')
        },
        body: JSON.stringify({
          Messages: [
            {
              From: {
                Email: this.fromEmail,
                Name: this.fromName
              },
              To: [
                {
                  Email: user.email,
                  Name: user.name || 'User'
                }
              ],
              Subject: "Verify Your HomeHero Account",
              HTMLPart: `
                <!DOCTYPE html>
                <html>
                <head>
                  <style>
                    body { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
                    .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
                    .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
                  </style>
                </head>
                <body>
                  <div class="header">
                    <h1>Welcome to HomeHero! 🏠</h1>
                  </div>
                  <div class="content">
                    <h2>Verify Your Email Address</h2>
                    <p>Hello ${user.name || 'User'},</p>
                    <p>Thank you for signing up for HomeHero! To complete your registration and start using our services, please verify your email address by clicking the button below:</p>
                    
                    <div style="text-align: center;">
                      <a href="${verificationUrl}" class="button">Verify Email Address</a>
                    </div>
                    
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; background: #f0f0f0; padding: 10px; border-radius: 5px;">
                      ${verificationUrl}
                    </p>
                    
                    <p><strong>This link will expire in 24 hours.</strong></p>
                    
                    <p>If you didn't create an account with HomeHero, please ignore this email.</p>
                    
                    <div class="footer">
                      <p>This is an automated message. Please do not reply to this email.</p>
                      <p>© 2024 HomeHero. All rights reserved.</p>
                    </div>
                  </div>
                </body>
                </html>
              `,
              TextPart: `Verify your HomeHero account by visiting: ${verificationUrl}\n\nThis link expires in 24 hours.`
            }
          ]
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Mailjet API error:', response.status, errorText);
        throw new Error(`Mailjet API error: ${response.status}`);
      }

      const result = await response.json();
      console.log('✅ Verification email sent via Mailjet API');
      
      return {
        success: true,
        messageId: result.Messages[0].To[0].MessageID,
        provider: 'mailjet'
      };

    } catch (error) {
      console.error('❌ Mailjet API error:', error.message);
      
      // Fallback: Log the verification token for development
      console.log('🔑 DEVELOPMENT MODE - Verification token:', verificationToken);
      console.log('🔗 Verification URL would be:', `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(user.email)}`);
      
      return {
        success: true, // Still return success to not block user registration
        simulated: true,
        debugToken: verificationToken,
        error: error.message
      };
    }
  }
}

export const mailjetService = new MailjetService();