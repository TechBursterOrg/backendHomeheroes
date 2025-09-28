import twilio from 'twilio';

class SMSService {
  constructor() {
    this.client = null;
    this.initialize();
  }

  initialize() {
    // In production, require Twilio credentials
    if (process.env.NODE_ENV === 'production') {
      if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_PHONE_NUMBER) {
        this.client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
        console.log('✅ Twilio SMS service initialized for production');
      } else {
        console.error('❌ TWILIO CREDENTIALS MISSING IN PRODUCTION!');
        console.error('Required environment variables:');
        console.error('- TWILIO_ACCOUNT_SID');
        console.error('- TWILIO_AUTH_TOKEN'); 
        console.error('- TWILIO_PHONE_NUMBER');
        throw new Error('Twilio credentials required for production');
      }
    } else {
      // Development mode - use simulation
      console.log('⚠️ SMS service running in simulation mode (development)');
    }
  }

  async sendVerificationCode(phoneNumber, token) {
  try {
    console.log('🔧 Attempting to send SMS to:', phoneNumber);

    // Validate FROM number format
    const fromNumber = process.env.TWILIO_PHONE_NUMBER;
    if (!fromNumber || !fromNumber.startsWith('+')) {
      throw new Error(`Invalid Twilio phone number format: ${fromNumber}. Must start with +`);
    }

    console.log('📱 Using Twilio number:', fromNumber);

    // Enhanced validation for TO number
    if (!this.isValidPhoneNumber(phoneNumber)) {
      throw new Error('Invalid phone number format');
    }

    // In production, use Twilio
    if (this.client && process.env.NODE_ENV === 'production') {
      try {
        console.log('📱 Sending via Twilio:', { to: phoneNumber, from: fromNumber });
        
        const message = await this.client.messages.create({
          body: `Your HomeHero verification code is: ${token}. This code expires in 5 minutes.`,
          from: fromNumber,
          to: phoneNumber
        });
        
        console.log(`✅ Twilio SMS sent successfully`);
        console.log(`✅ Message SID: ${message.sid}`);
        
        return { 
          success: true, 
          messageId: message.sid,
          provider: 'twilio'
        };
      } catch (twilioError) {
        console.error('❌ Twilio error details:', {
          code: twilioError.code,
          message: twilioError.message,
          moreInfo: twilioError.moreInfo,
          fromNumber: fromNumber,
          toNumber: phoneNumber
        });
        
        throw new Error(`SMS delivery failed: ${twilioError.message}`);
      }
    }

    // Development mode only
    if (process.env.NODE_ENV !== 'production') {
      console.log(`📱 [SIMULATION] Verification code for ${phoneNumber}: ${token}`);
      return { 
        success: true, 
        messageId: `simulated-${Date.now()}`,
        provider: 'simulation',
        debugToken: token
      };
    }
    
    throw new Error('SMS service not configured');
    
  } catch (error) {
    console.error('❌ SMS sending error:', error);
    throw error;
  }
}


  isValidPhoneNumber(phoneNumber) {
    const phoneRegex = /^\+[1-9]\d{1,14}$/;
    return phoneRegex.test(phoneNumber);
  }

  formatPhoneNumberWithCountryCode(phoneNumber, countryCode) {
  const cleanNumber = phoneNumber.replace(/^\++/, '').replace(/\D/g, '');
  
  console.log('🔧 Formatting phone number:', {
    input: phoneNumber,
    cleaned: cleanNumber,
    countryCode: countryCode
  });

  // For Nigeria: special handling
  if (countryCode === '+234') {
    // Remove leading 0 if present
    let formatted = cleanNumber.startsWith('0') ? cleanNumber.substring(1) : cleanNumber;
    
    // Ensure it's exactly 10 digits after country code
    if (formatted.length !== 10) {
      throw new Error(`Nigerian phone number must be 10 digits after country code. Got: ${formatted.length}`);
    }
    
    // Return with country code
    const fullNumber = `+234${formatted}`;
    console.log('🔧 Formatted Nigerian number:', fullNumber);
    return fullNumber;
  }
  
  // For other countries
  const fullNumber = `${countryCode}${cleanNumber}`;
  console.log('🔧 Formatted number:', fullNumber);
  return fullNumber;
}

}

const smsService = new SMSService();
export default smsService;