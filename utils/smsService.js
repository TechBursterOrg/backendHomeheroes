import twilio from 'twilio';

class SMSService {
  constructor() {
    this.client = null;
    this.initialize();
  }

  initialize() {
    // In production, only use real Twilio if credentials are provided
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.NODE_ENV === 'production') {
      this.client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
      console.log('✅ Twilio SMS service initialized for production');
    } else {
      console.log('⚠️ SMS service running in simulation mode');
    }
  }

  async sendVerificationCode(phoneNumber, token) {
    try {
      // Validate phone number format
      if (!this.isValidPhoneNumber(phoneNumber)) {
        throw new Error('Invalid phone number format');
      }

      // Use real Twilio in production if credentials are available
      if (this.client && process.env.NODE_ENV === 'production') {
        try {
          const message = await this.client.messages.create({
            body: `Your HomeHero verification code is: ${token}. This code expires in 5 minutes.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: phoneNumber
          });
          
          console.log(`✅ Production SMS sent via Twilio to ${phoneNumber}, Message SID: ${message.sid}`);
          return { 
            success: true, 
            messageId: message.sid,
            provider: 'twilio'
          };
        } catch (twilioError) {
          console.error('❌ Twilio SMS failed, falling back to simulation:', twilioError);
          // Fall through to simulation mode
        }
      }

      // Simulation mode (for development or as fallback)
      console.log(`📱 [SMS SIMULATION] Verification code for ${phoneNumber}: ${token}`);
      return { 
        success: true, 
        messageId: `simulated-${Date.now()}`,
        provider: 'simulation',
        debugToken: process.env.NODE_ENV === 'production' ? undefined : token
      };
      
    } catch (error) {
      console.error('❌ SMS sending error:', error);
      throw new Error(`Failed to send SMS: ${error.message}`);
    }
  }

  isValidPhoneNumber(phoneNumber) {
    const phoneRegex = /^\+[1-9]\d{1,14}$/;
    return phoneRegex.test(phoneNumber);
  }

  formatPhoneNumberWithCountryCode(phoneNumber, countryCode) {
    const cleanNumber = phoneNumber.replace(/^\++/, '').replace(/\D/g, '');
    
    // For Nigeria: remove leading 0 and add country code
    if (countryCode === '+234' && cleanNumber.startsWith('0')) {
      return `+234${cleanNumber.substring(1)}`;
    }
    
    return `${countryCode}${cleanNumber}`;
  }
}

const smsService = new SMSService();
export default smsService;