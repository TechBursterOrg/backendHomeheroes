import Stripe from 'stripe';

// Initialize Stripe with environment variable check
let stripeInstance = null;

const getStripeInstance = () => {
  if (!stripeInstance) {
    const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
    
    if (!stripeSecretKey) {
      throw new Error('STRIPE_SECRET_KEY is not defined in environment variables');
    }
    
    stripeInstance = new Stripe(stripeSecretKey, {
      apiVersion: '2025-09-30.clover',
    });
  }
  
  return stripeInstance;
};

export class StripeService {
  // Create a Payment Intent with escrow hold
  static async createEscrowPaymentIntent({
    amount,
    currency = 'usd',
    customerId,
    metadata = {}
  }) {
    try {
      const stripe = getStripeInstance();
      
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents
        currency,
        customer: customerId,
        capture_method: 'manual', // This holds the payment until manually captured
        metadata: {
          ...metadata,
          payment_type: 'escrow',
          status: 'held'
        }
      });

      return {
        success: true,
        paymentIntentId: paymentIntent.id,
        clientSecret: paymentIntent.client_secret,
        amount: paymentIntent.amount / 100
      };
    } catch (error) {
      console.error('Stripe payment intent creation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Capture payment (release to provider after service completion)
  static async capturePayment(paymentIntentId) {
    try {
      const stripe = getStripeInstance();
      const paymentIntent = await stripe.paymentIntents.capture(paymentIntentId);
      
      return {
        success: true,
        paymentIntent,
        amount: paymentIntent.amount / 100,
        status: paymentIntent.status
      };
    } catch (error) {
      console.error('Stripe payment capture error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Cancel/refund payment (if provider doesn't accept within 4 hours)
  static async cancelPayment(paymentIntentId) {
    try {
      const stripe = getStripeInstance();
      const refund = await stripe.refunds.create({
        payment_intent: paymentIntentId
      });

      return {
        success: true,
        refund,
        status: refund.status
      };
    } catch (error) {
      console.error('Stripe payment cancellation error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Calculate platform commission (20%)
  static calculateCommission(amount) {
    const commission = amount * 0.20;
    const providerAmount = amount * 0.80;
    
    return {
      commission: Math.round(commission * 100) / 100,
      providerAmount: Math.round(providerAmount * 100) / 100,
      total: amount
    };
  }

  // Create transfer to provider's bank account
  static async transferToProvider(providerStripeAccountId, amount, metadata = {}) {
    try {
      const stripe = getStripeInstance();
      const transfer = await stripe.transfers.create({
        amount: Math.round(amount * 100),
        currency: 'usd',
        destination: providerStripeAccountId,
        metadata
      });

      return {
        success: true,
        transfer,
        amount: transfer.amount / 100
      };
    } catch (error) {
      console.error('Stripe transfer error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Validate Stripe configuration
  static validateConfig() {
    const stripeSecretKey = process.env.STRIPE_SECRET_KEY;
    const stripePublishableKey = process.env.STRIPE_PUBLISHABLE_KEY;
    
    if (!stripeSecretKey || !stripePublishableKey) {
      console.warn('⚠️ Stripe keys not configured. Payment features will be disabled.');
      return false;
    }
    
    console.log('✅ Stripe configuration validated');
    return true;
  }
}

export default StripeService;