import fetch from 'node-fetch';

export const sendVerificationEmailViaAPI = async (user, verificationToken) => {
  try {
    const email = user.email || user;
    const name = user.name || 'User';

    console.log(`📧 Sending verification via Mailjet API to: ${email}`);
    console.log(`🔑 Token: ${verificationToken}`);

    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`;

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
              Email: "techbursterdev@gmail.com",
              Name: "HomeHeroes"
            },
            To: [
              {
                Email: email,
                Name: name
              }
            ],
            Subject: "Verify Your HomeHero Account",
            HTMLPart: `
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
            TextPart: `Verify your HomeHero account using this code: ${verificationToken} or visit: ${verificationUrl}`
          }
        ]
      })
    });

    if (!response.ok) {
      throw new Error(`Mailjet API error: ${response.status} ${response.statusText}`);
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
    
    // Fallback to simulation
    console.log('🔑 FALLBACK - Verification token:', verificationToken);
    
    return {
      success: true,
      simulated: true,
      fallbackToken: verificationToken,
      error: error.message
    };
  }
};