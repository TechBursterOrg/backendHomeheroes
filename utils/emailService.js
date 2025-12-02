import nodemailer from 'nodemailer';
import fetch from 'node-fetch';

let emailTransporter = null;
let emailServiceStatus = 'initializing';

// Get correct URLs based on environment
const getApiUrl = () => {
  return process.env.API_URL || 
    (process.env.NODE_ENV === 'production' 
      ? 'https://backendhomeheroes.onrender.com' 
      : 'http://localhost:3001');
};

const getFrontendUrl = () => {
  return process.env.FRONTEND_URL || 
    (process.env.NODE_ENV === 'production'
      ? 'https://homeheroes.help'
      : 'http://localhost:5173');
};

// Initialize email transporter
export const initializeEmailTransporter = async () => {
  try {
    console.log('🔧 Checking email configuration...');
    console.log('🌐 Environment:', process.env.NODE_ENV);
    console.log('🔗 API URL:', getApiUrl());
    console.log('🔗 Frontend URL:', getFrontendUrl());
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      console.log('❌ Email credentials not configured, using simulation mode');
      emailServiceStatus = 'simulation';
      return true;
    }

    // For production, use Mailjet API directly
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      console.log('✅ Mailjet API configuration ready');
      emailServiceStatus = 'ready';
      return true;
    }

    // Fallback to nodemailer with Gmail
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    await emailTransporter.verify();
    console.log('✅ Email transporter ready');
    emailServiceStatus = 'ready';
    return true;
    
  } catch (error) {
    console.error('❌ Email service initialization failed:', error.message);
    emailServiceStatus = 'simulation';
    return true;
  }
};



export const getEmailServiceStatus = () => emailServiceStatus;

// Send verification email with correct URLs
export const sendVerificationEmail = async (user, verificationToken) => {
  try {
    const apiUrl = getApiUrl();
    const verificationUrl = `${apiUrl}/api/auth/verify-email/${verificationToken}`;
    
    const email = user.email || user;
    const name = user.name || 'User';

    console.log('📧 Sending verification email to:', email);
    console.log('🌐 Using API URL:', apiUrl);
    console.log('🔗 Verification URL:', verificationUrl);

    // Use Mailjet API if configured
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      return await sendVerificationEmailViaMailjet(user, verificationUrl);
    }

    // Use nodemailer as fallback
    if (emailTransporter) {
      const mailOptions = {
        from: {
          name: 'HomeHero',
          address: process.env.EMAIL_USER
        },
        to: email,
        subject: 'Verify Your HomeHero Account',
        html: generateVerificationEmailHTML(name, verificationUrl),
        text: generateVerificationEmailText(name, verificationUrl)
      };

      const result = await emailTransporter.sendMail(mailOptions);
      console.log('✅ Verification email sent via nodemailer');
      
      return {
        success: true,
        messageId: result.messageId,
        simulated: false
      };
    }

    // Simulation mode - log the verification URL
    console.log('🔄 SIMULATION MODE - Verification URL:', verificationUrl);
    
    return {
      success: true,
      simulated: true,
      verificationUrl: verificationUrl
    };

  } catch (error) {
    console.error('❌ Email sending failed:', error.message);
    
    // Final fallback - just log the URL
    const apiUrl = getApiUrl();
    const verificationUrl = `${apiUrl}/api/auth/verify-email/${verificationToken}`;
    console.log('🔑 FALLBACK - Verification URL:', verificationUrl);
    
    return {
      success: true,
      simulated: true,
      verificationUrl: verificationUrl
    };
  }
};

// Mailjet API integration
const sendVerificationEmailViaMailjet = async (user, verificationUrl) => {
  try {
    const email = user.email || user;
    const name = user.name || 'User';

    console.log('📧 Sending verification via Mailjet API to:', email);
    console.log('🔗 Verification URL:', verificationUrl);

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
              Name: "HomeHeroes"
            },
            To: [
              {
                Email: email,
                Name: name
              }
            ],
            Subject: "Verify Your HomeHero Account",
            HTMLPart: generateVerificationEmailHTML(name, verificationUrl),
            TextPart: generateVerificationEmailText(name, verificationUrl)
          }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Mailjet API error:', response.status, errorText);
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
    throw error;
  }
};

export const sendBookingNotificationToProvider = async (providerEmail, bookingData, customerInfo) => {
  try {
    console.log('📧 Sending booking notification to provider:', providerEmail);
    
    // Use Mailjet API if configured
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      return await sendBookingEmailViaMailjet(providerEmail, bookingData, customerInfo);
    }

    // Fallback to nodemailer
    if (emailTransporter) {
      const mailOptions = {
        from: {
          name: 'HomeHero Bookings',
          address: process.env.EMAIL_USER
        },
        to: providerEmail,
        subject: `New Booking Request - ${bookingData.serviceType}`,
        html: generateBookingNotificationHTML(bookingData, customerInfo),
        text: generateBookingNotificationText(bookingData, customerInfo)
      };

      const result = await emailTransporter.sendMail(mailOptions);
      console.log('✅ Booking notification sent via nodemailer');
      
      return {
        success: true,
        messageId: result.messageId,
        simulated: false
      };
    }

    // Simulation mode
    console.log('🔄 SIMULATION MODE - Booking notification for:', providerEmail);
    
    return {
      success: true,
      simulated: true
    };

  } catch (error) {
    console.error('❌ Booking notification failed:', error.message);
    
    return {
      success: false,
      error: error.message,
      simulated: false
    };
  }
};

const sendBookingEmailViaMailjet = async (providerEmail, bookingData, customerInfo) => {
  try {
    console.log('📧 [MAILJET] Sending booking notification to:', providerEmail);

    const response = await fetch('https://api.mailjet.com/v3.1/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(
          `${process.env.MAILJET_API_KEY}:${process.env.MAILJET_SECRET_KEY}`
        ).toString('base64')
      },
      body: JSON.stringify({
        Messages: [
          {
            From: {
              Email: process.env.MAILJET_FROM_EMAIL || "bookings@homeheroes.help",
              Name: process.env.MAILJET_FROM_NAME || "HomeHero Bookings"
            },
            To: [
              {
                Email: providerEmail,
                Name: bookingData.providerName || 'Service Provider'
              }
            ],
            Subject: `New Booking Request - ${bookingData.serviceType}`,
            HTMLPart: generateBookingNotificationHTML(bookingData, customerInfo),
            TextPart: generateBookingNotificationText(bookingData, customerInfo),
            CustomID: `booking_${Date.now()}`
          }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Mailjet API error:', response.status, errorText);
      
      // Don't throw error, return failure so booking still gets created
      return {
        success: false,
        error: `Mailjet API error: ${response.status}`,
        provider: 'mailjet-failed'
      };
    }

    const result = await response.json();
    console.log('✅ [MAILJET] Booking notification sent successfully');
    
    return {
      success: true,
      messageId: result.Messages?.[0]?.To?.[0]?.MessageID,
      provider: 'mailjet'
    };

  } catch (error) {
    console.error('❌ [MAILJET] Failed to send booking email:', error.message);
    
    return {
      success: false,
      error: error.message,
      provider: 'mailjet-error'
    };
  }
};

export const sendBookingAcceptedNotificationToCustomer = async (customerEmail, bookingData, providerInfo) => {
  try {
    console.log('📧 Sending booking acceptance notification to customer:', customerEmail);
    
    // Use Mailjet API if configured
    if (process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY) {
      return await sendBookingAcceptedEmailViaMailjet(customerEmail, bookingData, providerInfo);
    }

    // Fallback to nodemailer
    if (emailTransporter) {
      const mailOptions = {
        from: {
          name: 'HomeHero Bookings',
          address: process.env.EMAIL_USER || 'noreply@homeheroes.help'
        },
        to: customerEmail,
        subject: `Booking Confirmed! - ${bookingData.serviceType}`,
        html: generateBookingAcceptedHTML(bookingData, providerInfo),
        text: generateBookingAcceptedText(bookingData, providerInfo)
      };

      const result = await emailTransporter.sendMail(mailOptions);
      console.log('✅ Booking acceptance notification sent via nodemailer');
      
      return {
        success: true,
        messageId: result.messageId,
        simulated: false
      };
    }

    // Simulation mode
    console.log('🔄 SIMULATION MODE - Booking acceptance notification would be sent to:', customerEmail);
    
    return {
      success: true,
      simulated: true
    };

  } catch (error) {
    console.error('❌ Booking acceptance notification failed:', error.message);
    
    return {
      success: false,
      error: error.message,
      simulated: false
    };
  }
};

// Mailjet API for booking acceptance notifications
const sendBookingAcceptedEmailViaMailjet = async (customerEmail, bookingData, providerInfo) => {
  try {
    console.log('📧 [MAILJET] Sending booking acceptance notification to:', customerEmail);

    const response = await fetch('https://api.mailjet.com/v3.1/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(
          `${process.env.MAILJET_API_KEY}:${process.env.MAILJET_SECRET_KEY}`
        ).toString('base64')
      },
      body: JSON.stringify({
        Messages: [
          {
            From: {
              Email: process.env.MAILJET_FROM_EMAIL || "bookings@homeheroes.help",
              Name: process.env.MAILJET_FROM_NAME || "HomeHero Bookings"
            },
            To: [
              {
                Email: customerEmail,
                Name: bookingData.customerName || 'Customer'
              }
            ],
            Subject: `Booking Confirmed! - ${bookingData.serviceType}`,
            HTMLPart: generateBookingAcceptedHTML(bookingData, providerInfo),
            TextPart: generateBookingAcceptedText(bookingData, providerInfo),
            CustomID: `booking_accepted_${Date.now()}`
          }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Mailjet API error:', response.status, errorText);
      
      return {
        success: false,
        error: `Mailjet API error: ${response.status}`,
        provider: 'mailjet-failed'
      };
    }

    const result = await response.json();
    console.log('✅ [MAILJET] Booking acceptance notification sent successfully');
    
    return {
      success: true,
      messageId: result.Messages?.[0]?.To?.[0]?.MessageID,
      provider: 'mailjet'
    };

  } catch (error) {
    console.error('❌ [MAILJET] Failed to send booking acceptance email:', error.message);
    
    return {
      success: false,
      error: error.message,
      provider: 'mailjet-error'
    };
  }
};



const sendRatingPromptViaMailjet = async (booking) => {
  try {
    console.log('📧 [MAILJET] Sending rating prompt to:', booking.customerEmail);

    const response = await fetch('https://api.mailjet.com/v3.1/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(
          `${process.env.MAILJET_API_KEY}:${process.env.MAILJET_SECRET_KEY}`
        ).toString('base64')
      },
      body: JSON.stringify({
        Messages: [
          {
            From: {
              Email: process.env.MAILJET_FROM_EMAIL || "noreply@homeheroes.help",
              Name: process.env.MAILJET_FROM_NAME || "HomeHero"
            },
            To: [
              {
                Email: booking.customerEmail,
                Name: booking.customerName || 'Customer'
              }
            ],
            Subject: 'Rate Your Service Experience - HomeHero',
            HTMLPart: generateRatingPromptHTML(booking),
            TextPart: generateRatingPromptText(booking),
            CustomID: `rating_prompt_${Date.now()}`
          }
        ]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Mailjet API error:', response.status, errorText);
      
      return {
        success: false,
        error: `Mailjet API error: ${response.status}`,
        provider: 'mailjet-failed'
      };
    }

    const result = await response.json();
    console.log('✅ [MAILJET] Rating prompt sent successfully');
    
    return {
      success: true,
      messageId: result.Messages?.[0]?.To?.[0]?.MessageID,
      provider: 'mailjet'
    };

  } catch (error) {
    console.error('❌ [MAILJET] Failed to send rating prompt:', error.message);
    
    return {
      success: false,
      error: error.message,
      provider: 'mailjet-error'
    };
  }
};





export const sendNewRatingNotificationToProvider = async (providerEmail, rating, booking) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: providerEmail,
      subject: 'New Rating Received - HomeHero',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .rating { color: #f59e0b; font-size: 24px; text-align: center; margin: 20px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>⭐ New Rating Received</h1>
              <p>You've received a new rating from a customer</p>
            </div>
            <div class="content">
              <p>Great news! You've received a new ${rating}/5 star rating.</p>
              
              <div class="rating">
                ${'⭐'.repeat(rating)}${'☆'.repeat(5 - rating)}
                <br>
                <strong>${rating} out of 5 stars</strong>
              </div>

              <p><strong>Service:</strong> ${booking.serviceType}</p>
              <p><strong>Customer:</strong> ${booking.customerName}</p>
              
              <p>Keep up the great work! Your ratings help build trust with potential customers.</p>
              
              <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>© 2024 HomeHero. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ New rating notification sent to provider:', providerEmail);
    return { success: true, messageId: result.messageId };
  } catch (error) {
    console.error('❌ Failed to send new rating notification:', error);
    return { success: false, error: error.message };
  }
};



const generateBookingAcceptedHTML = (bookingData, providerInfo) => {
  const frontendUrl = getFrontendUrl();
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .booking-details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981; }
        .button { display: inline-block; padding: 12px 30px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
        .detail-row { margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #eee; }
        .detail-label { font-weight: bold; color: #555; }
        .provider-info { background: #e6f3ff; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #3b82f6; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>✅ Booking Confirmed!</h1>
        <p>Your service provider has accepted your booking request</p>
      </div>
      <div class="content">
        <p>Hello <strong>${bookingData.customerName}</strong>,</p>
        <p>Great news! <strong>${providerInfo.name}</strong> has accepted your booking request and is looking forward to helping you.</p>
        
        <div class="provider-info">
          <h3>👨‍🔧 Your Service Provider</h3>
          <div class="detail-row">
            <span class="detail-label">Provider:</span>
            <span>${providerInfo.name}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Contact:</span>
            <span>${providerInfo.phone || 'Will contact you shortly'}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Email:</span>
            <span>${providerInfo.email}</span>
          </div>
        </div>
        
        <div class="booking-details">
          <h3>📋 Booking Details</h3>
          
          <div class="detail-row">
            <span class="detail-label">Service Type:</span>
            <span>${bookingData.serviceType}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Location:</span>
            <span>${bookingData.location}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Preferred Time:</span>
            <span>${bookingData.timeframe}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Budget:</span>
            <span>${bookingData.budget}</span>
          </div>
          
          ${bookingData.description ? `
          <div class="detail-row">
            <span class="detail-label">Description:</span>
            <span>${bookingData.description}</span>
          </div>
          ` : ''}
          
          ${bookingData.specialRequests ? `
          <div class="detail-row">
            <span class="detail-label">Special Requests:</span>
            <span>${bookingData.specialRequests}</span>
          </div>
          ` : ''}
        </div>

        <p><strong>Next Steps:</strong></p>
        <ol>
          <li>Your provider will contact you within 24 hours to confirm details</li>
          <li>Discuss any specific requirements or timing preferences</li>
          <li>Be available at the scheduled time for the service</li>
        </ol>
        
        <div style="text-align: center;">
          <a href="${frontendUrl}/customer/dashboard" class="button">View Booking in Dashboard</a>
        </div>
        
        <p>If you have any questions or need to make changes, please contact your provider directly.</p>
        
        <div class="footer">
          <p>This is an automated message. Please do not reply to this email.</p>
          <p>© ${new Date().getFullYear()} HomeHero. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Plain text template for booking acceptance notification
const generateBookingAcceptedText = (bookingData, providerInfo) => {
  return `
BOOKING CONFIRMED! - HomeHero

Hello ${bookingData.customerName},

Great news! ${providerInfo.name} has accepted your booking request and is looking forward to helping you.

YOUR SERVICE PROVIDER:
----------------------
Provider: ${providerInfo.name}
Contact: ${providerInfo.phone || 'Will contact you shortly'}
Email: ${providerInfo.email}

BOOKING DETAILS:
---------------
Service Type: ${bookingData.serviceType}
Location: ${bookingData.location}
Preferred Time: ${bookingData.timeframe}
Budget: ${bookingData.budget}
${bookingData.description ? `Description: ${bookingData.description}` : ''}
${bookingData.specialRequests ? `Special Requests: ${bookingData.specialRequests}` : ''}

Next Steps:
1. Your provider will contact you within 24 hours to confirm details
2. Discuss any specific requirements or timing preferences
3. Be available at the scheduled time for the service

View your dashboard: ${getFrontendUrl()}/customer/dashboard

If you have any questions or need to make changes, please contact your provider directly.

This is an automated message. Please do not reply to this email.

© ${new Date().getFullYear()} HomeHero. All rights reserved.
  `;
};


// HTML email template
const generateVerificationEmailHTML = (name, verificationUrl) => {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
        .verification-url { background: #f4f4f4; padding: 15px; border-radius: 5px; word-break: break-all; margin: 20px 0; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Welcome to Home Heroes!</h1>
        <p>Verify your email address to get started</p>
      </div>
      <div class="content">
        <p>Hello <strong>${name}</strong>,</p>
        <p>Thank you for signing up for HomeHero! To complete your registration and start using your account, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center;">
          <a href="${verificationUrl}" class="button">Verify Email Address</a>
        </div>
        
        <p>Or copy and paste this link in your browser:</p>
        <div class="verification-url">
          ${verificationUrl}
        </div>
        
        <p><strong>This link will expire in 24 hours.</strong></p>
        
        <p>If you didn't create an account with HomeHero, you can safely ignore this email.</p>
        
        <div class="footer">
          <p>This is an automated message. Please do not reply to this email.</p>
          <p>© ${new Date().getFullYear()} HomeHero. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};


const sendProposalNotification = async (toEmail, customerName, providerName, serviceType, jobId) => {
  try {
    const emailTransporter = await getEmailTransporter();
    if (!emailTransporter) {
      console.log('📧 Email service not available, skipping notification');
      return false;
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@homeheroes.help',
      to: toEmail,
      subject: `New Proposal Received - ${serviceType}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #10B981, #059669); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { background: #10B981; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; }
                .footer { text-align: center; margin-top: 30px; color: #6B7280; font-size: 14px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 New Proposal Received!</h1>
                </div>
                <div class="content">
                    <h2>Hello ${customerName},</h2>
                    <p>Great news! <strong>${providerName}</strong> has submitted a proposal for your <strong>${serviceType}</strong> service request.</p>
                    
                    <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #10B981; margin: 20px 0;">
                        <h3 style="margin-top: 0;">Service Details:</h3>
                        <p><strong>Service Type:</strong> ${serviceType}</p>
                        <p><strong>Provider:</strong> ${providerName}</p>
                        <p><strong>Status:</strong> Waiting for your review</p>
                    </div>

                    <p>Review the proposal details and choose the best provider for your needs.</p>
                    
                    <a href="${process.env.FRONTEND_URL}/jobs/${jobId}" class="button">View Proposal</a>
                    
                    <p>You'll be able to:</p>
                    <ul>
                        <li>Review the provider's proposed budget and timeline</li>
                        <li>Check their profile and ratings</li>
                        <li>Message the provider directly</li>
                        <li>Accept the proposal when ready</li>
                    </ul>

                    <p><strong>Need help?</strong> Our support team is here to assist you.</p>
                </div>
                <div class="footer">
                    <p>Best regards,<br>The HomeHeroes Team</p>
                    <p><small>This is an automated message. Please do not reply to this email.</small></p>
                </div>
            </div>
        </body>
        </html>
      `
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Proposal notification email sent to:', toEmail);
    return true;
  } catch (error) {
    console.error('❌ Failed to send proposal notification email:', error);
    return false;
  }
};

const sendProposalAcceptedNotification = async (toEmail, providerName, customerName, serviceType, jobId) => {
  try {
    const emailTransporter = await getEmailTransporter();
    if (!emailTransporter) {
      console.log('📧 Email service not available, skipping notification');
      return false;
    }

    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@homeheroes.help',
      to: toEmail,
      subject: `🎉 Your Proposal Was Accepted! - ${serviceType}`,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: linear-gradient(135deg, #10B981, #059669); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
                .content { background: #f9fafb; padding: 30px; border-radius: 0 0 10px 10px; }
                .button { background: #10B981; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0; }
                .footer { text-align: center; margin-top: 30px; color: #6B7280; font-size: 14px; }
                .celebrate { font-size: 48px; text-align: center; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎉 Proposal Accepted!</h1>
                </div>
                <div class="content">
                    <div class="celebrate">🥳</div>
                    <h2>Congratulations ${providerName}!</h2>
                    <p>Great news! <strong>${customerName}</strong> has accepted your proposal for the <strong>${serviceType}</strong> service.</p>
                    
                    <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #10B981; margin: 20px 0;">
                        <h3 style="margin-top: 0;">Next Steps:</h3>
                        <p><strong>Contact the customer:</strong> Reach out to discuss details and schedule the service</p>
                        <p><strong>Review requirements:</strong> Make sure you understand all service requirements</p>
                        <p><strong>Plan your work:</strong> Prepare your tools and schedule</p>
                    </div>

                    <p><strong>Important:</strong> The payment is held securely in escrow and will be released after the customer confirms satisfactory completion of the work.</p>
                    
                    <a href="${process.env.FRONTEND_URL}/provider/job-board" class="button">View Job Details</a>
                    
                    <div style="background: #EFF6FF; padding: 15px; border-radius: 6px; margin: 20px 0;">
                        <h4 style="margin-top: 0; color: #1E40AF;">💡 Tips for Success:</h4>
                        <ul style="color: #374151;">
                            <li>Communicate clearly with the customer</li>
                            <li>Confirm the schedule and location</li>
                            <li>Deliver quality work on time</li>
                            <li>Update the job status when completed</li>
                        </ul>
                    </div>

                    <p>Ready to get started? Contact the customer now to arrange the service!</p>
                </div>
                <div class="footer">
                    <p>Best regards,<br>The HomeHeroes Team</p>
                    <p><small>This is an automated message. Please do not reply to this email.</small></p>
                </div>
            </div>
        </body>
        </html>
      `
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Proposal accepted notification email sent to:', toEmail);
    return true;
  } catch (error) {
    console.error('❌ Failed to send proposal accepted notification email:', error);
    return false;
  }
};



// Plain text email template
const generateVerificationEmailText = (name, verificationUrl) => {
  return `
Welcome to Home Heroes!

Hello ${name},

Thank you for signing up for HomeHero! To complete your registration and start using your account, please verify your email address by visiting the following link:

${verificationUrl}

This link will expire in 24 hours.

If you didn't create an account with HomeHero, you can safely ignore this email.

This is an automated message. Please do not reply to this email.

© ${new Date().getFullYear()} HomeHero. All rights reserved.
  `;
};



const generateBookingNotificationHTML = (bookingData, customerInfo) => {
  const frontendUrl = getFrontendUrl();
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
        .booking-details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981; }
        .button { display: inline-block; padding: 12px 30px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
        .detail-row { margin: 10px 0; padding: 8px 0; border-bottom: 1px solid #eee; }
        .detail-label { font-weight: bold; color: #555; }
        .urgent { background: #fef3cd; padding: 10px; border-radius: 5px; border-left: 4px solid #f59e0b; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>🎉 New Booking Request!</h1>
        <p>You have a new service request on HomeHero</p>
      </div>
      <div class="content">
        <p>Hello <strong>${bookingData.providerName}</strong>,</p>
        <p>Great news! You've received a new booking request from <strong>${customerInfo.name}</strong>.</p>
        
        <div class="booking-details">
          <h3>📋 Booking Details</h3>
          
          <div class="detail-row">
            <span class="detail-label">Service Type:</span>
            <span>${bookingData.serviceType}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Customer:</span>
            <span>${customerInfo.name}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Email:</span>
            <span>${customerInfo.email}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Phone:</span>
            <span>${customerInfo.phone || 'Not provided'}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Location:</span>
            <span>${bookingData.location}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Preferred Time:</span>
            <span>${bookingData.timeframe}</span>
          </div>
          
          <div class="detail-row">
            <span class="detail-label">Budget:</span>
            <span>${bookingData.budget}</span>
          </div>
          
          ${bookingData.description ? `
          <div class="detail-row">
            <span class="detail-label">Description:</span>
            <span>${bookingData.description}</span>
          </div>
          ` : ''}
          
          ${bookingData.specialRequests ? `
          <div class="detail-row">
            <span class="detail-label">Special Requests:</span>
            <span>${bookingData.specialRequests}</span>
          </div>
          ` : ''}
          
          ${bookingData.bookingType === 'immediate' ? `
          <div class="urgent">
            <strong>🚨 Immediate Booking:</strong> Customer needs this service as soon as possible!
          </div>
          ` : ''}
        </div>

        <p><strong>Next Steps:</strong></p>
        <ol>
          <li>Review the booking details above</li>
          <li>Contact the customer to confirm availability</li>
          <li>Update the booking status in your dashboard</li>
        </ol>
        
        <div style="text-align: center;">
          <a href="${frontendUrl}/provider/dashboard" class="button">View Booking in Dashboard</a>
        </div>
        
        <p>Please respond to this booking request within 24 hours.</p>
        
        <div class="footer">
          <p>This is an automated message. Please do not reply to this email.</p>
          <p>© ${new Date().getFullYear()} HomeHero. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
  `;
};

// Plain text template for booking notification
const generateBookingNotificationText = (bookingData, customerInfo) => {
  return `
NEW BOOKING REQUEST - HomeHero

Hello ${bookingData.providerName},

You have received a new booking request from ${customerInfo.name}.

BOOKING DETAILS:
---------------
Service Type: ${bookingData.serviceType}
Customer: ${customerInfo.name}
Email: ${customerInfo.email}
Phone: ${customerInfo.phone || 'Not provided'}
Location: ${bookingData.location}
Preferred Time: ${bookingData.timeframe}
Budget: ${bookingData.budget}
${bookingData.description ? `Description: ${bookingData.description}` : ''}
${bookingData.specialRequests ? `Special Requests: ${bookingData.specialRequests}` : ''}
${bookingData.bookingType === 'immediate' ? 'URGENT: Immediate booking requested!' : ''}

Next Steps:
1. Review the booking details
2. Contact the customer to confirm availability  
3. Update the booking status in your dashboard

Please respond to this booking request within 24 hours.

View your dashboard: ${getFrontendUrl()}/provider/dashboard

This is an automated message. Please do not reply to this email.

© ${new Date().getFullYear()} HomeHero. All rights reserved.
  `;
};
2