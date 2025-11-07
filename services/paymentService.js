// services/paymentService.js
import StripeService from './stripeService.js';
import PaystackService from './paystackService.js';

export class PaymentService {
  static async createEscrowPayment(params) {
    const { amount, customerId, metadata = {}, customerCountry = 'NG', currency = 'NGN' } = params;
    
    console.log('🌍 Payment country detection:', { customerCountry, currency });
    
    // Use Paystack for Nigerian customers
    if (customerCountry === 'NG' || customerCountry === 'Nigeria') {
      console.log('🇳🇬 Using Paystack for Nigerian customer');
      return await PaystackService.initializeTransaction({
        amount,
        email: metadata.customerEmail,
        currency: 'NGN',
        metadata,
        callback_url: `${process.env.FRONTEND_URL}/payment-verify`
      });
    }
    
    // Use Stripe for UK and other countries
    if (customerCountry === 'GB' || customerCountry === 'UK' || customerCountry === 'United Kingdom') {
      console.log('🇬🇧 Using Stripe for UK customer');
      return await StripeService.createEscrowPaymentIntent({
        amount,
        currency: 'GBP',
        customerId,
        metadata
      });
    }
    
    // Default to Stripe for other countries
    if (!process.env.STRIPE_SECRET_KEY) {
      console.log('💳 Stripe not configured - using simulation mode');
      return this.simulateEscrowPayment(params);
    }
    
    return await StripeService.createEscrowPaymentIntent({
      amount,
      currency: 'USD',
      customerId,
      metadata
    });
  }

 static async capturePayment(paymentIntentId, paymentProcessor = 'stripe') {
  try {
    if (paymentProcessor === 'paystack') {
      // For Paystack, verify the transaction
      return await PaystackService.verifyTransaction(paymentIntentId);
    }
    
    // For Stripe
    if (!process.env.STRIPE_SECRET_KEY) {
      console.log('💳 Stripe not configured - using simulation mode');
      return this.simulatePaymentCapture(paymentIntentId);
    }
    
    return await StripeService.capturePayment(paymentIntentId);
  } catch (error) {
    console.error('Payment capture error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

  static async releasePaymentToProvider(provider, amount, currency = 'NGN') {
    const { country, paystackRecipientCode, stripeAccountId } = provider;
    
    // Use Paystack for Nigerian providers
    if ((country === 'NG' || country === 'Nigeria') && currency === 'NGN') {
      if (!paystackRecipientCode) {
        return {
          success: false,
          error: 'Provider does not have a Paystack recipient code setup'
        };
      }
      
      return await PaystackService.transferToProvider({
        amount,
        recipient_code: paystackRecipientCode,
        reason: 'Service completion payment',
        currency: 'NGN'
      });
    }
    
    // Use Stripe for UK and international providers
    if ((country === 'GB' || country === 'UK' || country === 'United Kingdom') && currency === 'GBP') {
      if (!stripeAccountId) {
        return {
          success: false,
          error: 'Provider does not have a Stripe account setup'
        };
      }
      
      return await StripeService.transferToProvider(stripeAccountId, amount, 'GBP');
    }
    
    // Default Stripe for other cases
    if (!process.env.STRIPE_SECRET_KEY) {
      console.log('💳 Stripe not configured - using simulation mode');
      return this.simulatePaymentCapture('stripe_simulation');
    }
    
    return await StripeService.transferToProvider(
      provider.stripeAccountId,
      amount,
      currency
    );
  }

  // Helper method to get provider type display name
  static getProviderTypeDisplayName(serviceType) {
    const providerTypeMap = {
      // Home Services
      houseCleaning: 'Cleaner',
      plumbing: 'Plumber',
      electrical: 'Electrician',
      gardenCare: 'Gardener',
      handyman: 'Handyman',
      painting: 'Painter',
      acRepair: 'AC Technician',
      generatorRepair: 'Generator Technician',
      carpentry: 'Carpenter',
      tiling: 'Tiler',
      masonry: 'Mason',
      welding: 'Welder',
      pestControl: 'Pest Control Specialist',
      
      // Automotive Services
      autoMechanic: 'Auto Mechanic',
      panelBeater: 'Panel Beater',
      autoElectric: 'Auto Electrician',
      vulcanizer: 'Vulcanizer',
      carWash: 'Car Wash Specialist',
      
      // Beauty & Personal Care
      barber: 'Barber',
      hairStylist: 'Hair Stylist',
      makeupArtist: 'Makeup Artist',
      nailTechnician: 'Nail Technician',
      massageTherapist: 'Massage Therapist',
      tailor: 'Tailor',
      
      // Home & Professional Services
      nanny: 'Nanny',
      cook: 'Cook',
      laundry: 'Laundry Specialist',
      gardener: 'Gardener',
      securityGuard: 'Security Guard',
      cctvInstaller: 'CCTV Installer',
      solarTechnician: 'Solar Technician',
      inverterTechnician: 'Inverter Technician',
      itSupport: 'IT Support Specialist',
      interiorDesigner: 'Interior Designer',
      tvRepair: 'TV Repair Technician'
    };

    return providerTypeMap[serviceType] || 'Service Provider';
  }

  // Simulation methods (unchanged)
  static simulateEscrowPayment({ amount, metadata }) {
    const simulatedPaymentId = `sim_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    return {
      success: true,
      paymentIntentId: simulatedPaymentId,
      clientSecret: `sim_${simulatedPaymentId}_secret`,
      amount: amount,
      simulated: true
    };
  }

  static simulatePaymentCapture(paymentIntentId) {
    return {
      success: true,
      paymentIntent: { id: paymentIntentId, status: 'succeeded' },
      amount: 100,
      status: 'succeeded',
      simulated: true
    };
  }

  static calculateCommission(amount, currency = 'NGN') {
    const commission = amount * 0.20;
    const providerAmount = amount * 0.80;
    
    return {
      commission: Math.round(commission * 100) / 100,
      providerAmount: Math.round(providerAmount * 100) / 100,
      total: amount,
      currency
    };
  }
}

export default PaymentService;