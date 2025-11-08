import axios from 'axios';

export class PaystackService {
  static getPaystackInstance() {
    const secretKey = process.env.NODE_ENV === 'production' 
      ? process.env.PAYSTACK_LIVE_SECRET_KEY
      : process.env.PAYSTACK_TEST_SECRET_KEY;
    
    if (!secretKey) {
      throw new Error('PAYSTACK_SECRET_KEY is not defined in environment variables');
    }
    
    return axios.create({
      baseURL: 'https://api.paystack.co',
      headers: {
        'Authorization': `Bearer ${secretKey}`,
        'Content-Type': 'application/json'
      }
    });
  }

  // Initialize transaction
  static async initializeTransaction({
    amount,
    email,
    currency = 'NGN',
    metadata = {},
    callback_url
  }) {
    try {
      const paystack = this.getPaystackInstance();
      
      const response = await paystack.post('/transaction/initialize', {
        amount: Math.round(amount * 100), // Convert to kobo
        email,
        currency,
        metadata,
        callback_url: callback_url || `${process.env.FRONTEND_URL}/payment-verify`
      });

      return {
        success: true,
        authorizationUrl: response.data.data.authorization_url,
        accessCode: response.data.data.access_code,
        reference: response.data.data.reference
      };
    } catch (error) {
      console.error('Paystack initialization error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Verify transaction
  static async verifyTransaction(reference) {
    try {
      const paystack = this.getPaystackInstance();
      
      const response = await paystack.get(`/transaction/verify/${reference}`);
      const data = response.data.data;

      return {
        success: true,
        transaction: {
          id: data.id,
          reference: data.reference,
          amount: data.amount / 100, // Convert from kobo
          currency: data.currency,
          status: data.status,
          paidAt: data.paid_at,
          customer: {
            email: data.customer.email,
            customer_code: data.customer.customer_code
          },
          metadata: data.metadata
        }
      };
    } catch (error) {
      console.error('Paystack verification error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Transfer to Nigerian provider (bank transfer)
  static async transferToProvider({
    amount,
    recipient_code,
    reason,
    currency = 'NGN'
  }) {
    try {
      const paystack = this.getPaystackInstance();
      
      const response = await paystack.post('/transfer', {
        source: 'balance',
        amount: Math.round(amount * 100), // Convert to kobo
        recipient: recipient_code,
        reason: reason || 'Service payment',
        currency
      });

      return {
        success: true,
        transfer: {
          id: response.data.data.id,
          amount: response.data.data.amount / 100,
          recipient: response.data.data.recipient,
          status: response.data.data.status,
          reference: response.data.data.reference
        }
      };
    } catch (error) {
      console.error('Paystack transfer error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Create transfer recipient (provider bank account)
  static async createTransferRecipient({
    type = 'nuban',
    name,
    account_number,
    bank_code,
    currency = 'NGN'
  }) {
    try {
      const paystack = this.getPaystackInstance();
      
      const response = await paystack.post('/transferrecipient', {
        type,
        name,
        account_number,
        bank_code,
        currency
      });

      return {
        success: true,
        recipient: {
          id: response.data.data.id,
          recipient_code: response.data.data.recipient_code,
          name: response.data.data.name,
          account_number: response.data.data.details.account_number,
          bank_name: response.data.data.details.bank_name
        }
      };
    } catch (error) {
      console.error('Paystack recipient creation error:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }
}
export default PaystackService;