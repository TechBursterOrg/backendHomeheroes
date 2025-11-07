import express from 'express';
import PaymentService from '../services/paymentService.js';
import Booking from '../models/Booking.js';
import User from '../models/User.js';
import Notification from '../models/Notification.js';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

const router = express.Router();

// Define authenticateToken middleware in this file
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    
    try {
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        console.error('User not found for ID:', decoded.id);
        return res.status(403).json({
          success: false,
          message: 'User not found'
        });
      }
      
      req.user = {
        id: user._id.toString(),
        userType: user.userType,
        email: user.email,
        name: user.name
      };
      
      next();
    } catch (error) {
      console.error('Error verifying user:', error);
      return res.status(500).json({
        success: false,
        message: 'Error verifying user'
      });
    }
  });
};

// Create escrow payment for booking
router.post('/create-escrow-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId, amount, paymentMethodId } = req.body;
    
    console.log('💰 Creating escrow payment for booking:', { bookingId, amount, userId: req.user.id });

    // Validate booking exists and is pending
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to pay for this booking'
      });
    }

    // Check if payment already exists
    if (booking.payment && booking.payment.paymentIntentId) {
      return res.status(400).json({
        success: false,
        message: 'Payment already exists for this booking'
      });
    }

    // Get customer with country information
    const customer = await User.findById(req.user.id);
    
    // Determine currency based on country
    let currency = 'NGN'; // Default to NGN for Nigeria
    let customerCountry = customer.country || 'NG';
    
    if (customerCountry === 'GB' || customerCountry === 'UK' || customerCountry === 'United Kingdom') {
      currency = 'GBP';
    } else if (customerCountry !== 'NG' && customerCountry !== 'Nigeria') {
      currency = 'USD'; // Default for other countries
    }

    console.log('🌍 Payment details:', { customerCountry, currency, customerEmail: customer.email });

    // Create payment intent with country-based gateway selection
    const paymentResult = await PaymentService.createEscrowPayment({
      amount: parseFloat(amount),
      customerId: customer._id.toString(),
      customerCountry: customerCountry,
      currency: currency,
      metadata: {
        bookingId: bookingId.toString(),
        customerId: req.user.id,
        providerId: booking.providerId.toString(),
        serviceType: booking.serviceType,
        customerEmail: customer.email,
        customerCountry: customerCountry
      }
    });

    if (!paymentResult.success) {
      return res.status(400).json({
        success: false,
        message: 'Payment creation failed',
        error: paymentResult.error
      });
    }

    // Update booking with payment info
    booking.payment = {
      paymentIntentId: paymentResult.paymentIntentId || paymentResult.reference,
      amount: paymentResult.amount,
      status: 'held',
      heldAt: new Date(),
      simulated: paymentResult.simulated || false,
      currency: currency,
      processor: customerCountry === 'NG' ? 'paystack' : 'stripe'
    };
    
    // Set auto-refund time (4 hours from now)
    booking.autoRefundAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
    
    await booking.save();

    console.log('✅ Escrow payment created successfully:', {
      paymentIntentId: booking.payment.paymentIntentId,
      processor: booking.payment.processor,
      currency: booking.payment.currency
    });

    res.json({
      success: true,
      message: 'Payment held in escrow successfully',
      data: {
        clientSecret: paymentResult.clientSecret,
        authorizationUrl: paymentResult.authorizationUrl, // For Paystack
        paymentIntentId: paymentResult.paymentIntentId || paymentResult.reference,
        amount: paymentResult.amount,
        currency: currency,
        processor: booking.payment.processor,
        simulated: paymentResult.simulated || false,
        autoRefundAt: booking.autoRefundAt
      }
    });

  } catch (error) {
    console.error('Create escrow payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create escrow payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Confirm payment and update booking status
router.post('/confirm-payment', authenticateToken, async (req, res) => {
  try {
    const { paymentIntentId, bookingId } = req.body;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify payment is held
    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // In a real implementation, you'd confirm the payment with Stripe
    // For now, we'll simulate successful payment confirmation
    
    booking.payment.status = 'confirmed';
    booking.payment.confirmedAt = new Date();
    booking.status = 'confirmed'; // Booking is now confirmed
    
    await booking.save();

    console.log('✅ Payment confirmed for booking:', bookingId);

    // Send notification to provider
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'payment_received',
      title: 'Payment Received',
      message: `Payment of $${booking.payment.amount} has been held for your ${booking.serviceType} booking`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Payment confirmed and booking is now active',
      data: { booking }
    });

  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm payment'
    });
  }
});

// Release payment to provider after service completion
router.post('/release-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.body;

    const booking = await Booking.findById(bookingId).populate('providerId');
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify user is authorized (provider or admin)
    if (booking.providerId._id.toString() !== req.user.id && req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to release this payment'
      });
    }

    // Verify booking is completed
    if (booking.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Booking must be completed before releasing payment'
      });
    }

    // Verify payment is confirmed
    if (booking.payment.status !== 'confirmed') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in confirmed status'
      });
    }

    const provider = await User.findById(booking.providerId);
    
    // Calculate commission and provider amount
    const { commission, providerAmount } = PaymentService.calculateCommission(booking.payment.amount);

    // In production, you would:
    // 1. Capture the held payment
    // 2. Transfer to provider's Stripe account (minus commission)
    
    const releaseResult = await PaymentService.capturePayment(booking.payment.paymentIntentId);
    
    if (!releaseResult.success) {
      return res.status(400).json({
        success: false,
        message: 'Failed to release payment',
        error: releaseResult.error
      });
    }

    booking.payment.status = 'released';
    booking.payment.releasedAt = new Date();
    booking.payment.commission = commission;
    booking.payment.providerAmount = providerAmount;
    
    await booking.save();

    // Update provider earnings
    provider.totalEarnings = (provider.totalEarnings || 0) + providerAmount;
    await provider.save();

    console.log('✅ Payment released to provider:', {
      bookingId,
      commission,
      providerAmount,
      provider: provider.name
    });

    res.json({
      success: true,
      message: 'Payment released to provider successfully',
      data: {
        commission,
        providerAmount,
        totalAmount: booking.payment.amount,
        releasedAt: booking.payment.releasedAt
      }
    });

  } catch (error) {
    console.error('Release payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to release payment'
    });
  }
});

// Auto-refund if provider doesn't accept within 4 hours
router.post('/auto-refund-expired', authenticateToken, async (req, res) => {
  try {
    // This would typically be called by a cron job or admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
    
    const expiredBookings = await Booking.find({
      status: 'pending',
      'payment.status': 'held',
      'payment.heldAt': { $lte: fourHoursAgo }
    });

    let refundedCount = 0;

    for (const booking of expiredBookings) {
      try {
        console.log(`🔄 Auto-refunding booking ${booking._id}`);
        
        // Refund the payment
        const refundResult = await PaymentService.cancelPayment(booking.payment.paymentIntentId);
        
        if (refundResult.success) {
          booking.payment.status = 'refunded';
          booking.payment.refundedAt = new Date();
          booking.status = 'cancelled';
          await booking.save();
          refundedCount++;
          
          console.log(`✅ Auto-refunded booking ${booking._id}`);
          
          // Notify customer
          await Notification.createNotification({
            userId: booking.customerId,
            type: 'payment_refunded',
            title: 'Payment Refunded',
            message: `Your payment has been refunded as the provider didn't accept the booking within 4 hours`,
            relatedId: booking._id,
            relatedType: 'booking',
            priority: 'medium'
          });
        }
      } catch (error) {
        console.error(`❌ Failed to refund booking ${booking._id}:`, error);
      }
    }

    res.json({
      success: true,
      message: `Auto-refund completed. ${refundedCount} bookings refunded.`,
      data: { refundedCount }
    });

  } catch (error) {
    console.error('Auto refund error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process auto refunds'
    });
  }
});

// Provider bank account setup
router.post('/setup-bank-account', authenticateToken, async (req, res) => {
  try {
    const { 
      accountHolderName, 
      accountNumber, 
      bankCode, 
      bankName, 
      country,
      routingNumber, // For international/US banks
      accountType = 'nuban'
    } = req.body;

    console.log('🏦 Setting up bank account for user:', req.user.id);
    console.log('🏦 Bank details:', {
      country,
      bankName,
      accountHolderName,
      accountNumber: `${accountNumber.slice(0, 2)}...${accountNumber.slice(-2)}`,
      bankCode: bankCode ? `${bankCode.slice(0, 2)}...${bankCode.slice(-2)}` : 'Not provided'
    });

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.userType !== 'provider' && user.userType !== 'both') {
      return res.status(400).json({
        success: false,
        message: 'Only providers can setup bank accounts'
      });
    }

    // Validate required fields based on country
    if (!accountHolderName || !accountNumber || !bankName || !country) {
      return res.status(400).json({
        success: false,
        message: 'Account holder name, account number, bank name, and country are required'
      });
    }

    if (country === 'NG' && !bankCode) {
      return res.status(400).json({
        success: false,
        message: 'Bank code is required for Nigerian bank accounts'
      });
    }

    if (country === 'US' && !routingNumber) {
      return res.status(400).json({
        success: false,
        message: 'Routing number is required for US bank accounts'
      });
    }

    let setupResult;
    let bankAccountData = {};

    // Handle Nigerian providers with Paystack
    if (country === 'NG') {
      console.log('🇳🇬 Setting up Nigerian bank account with Paystack');
      
      try {
        setupResult = await PaymentService.setupProviderBankAccount({
          country: 'NG',
          bankDetails: {
            accountHolderName,
            accountNumber,
            bankCode,
            bankName,
            accountType
          }
        });

        if (!setupResult.success) {
          console.error('❌ Paystack setup failed:', setupResult.error);
          return res.status(400).json({
            success: false,
            message: `Failed to setup bank account with Paystack: ${setupResult.error}`,
            error: setupResult.error
          });
        }

        console.log('✅ Paystack recipient created:', setupResult.recipient.recipient_code);
        
        // Store Paystack recipient code
        user.paystackRecipientCode = setupResult.recipient.recipient_code;
        
        bankAccountData = {
          accountHolderName,
          accountNumber: `***${accountNumber.slice(-4)}`, // Store only last 4 digits
          fullAccountNumber: accountNumber, // Encrypt this in production
          bankCode,
          bankName,
          country,
          isVerified: true,
          processor: 'paystack',
          recipientCode: setupResult.recipient.recipient_code,
          bankName: setupResult.recipient.bank_name
        };

      } catch (paystackError) {
        console.error('❌ Paystack integration error:', paystackError);
        return res.status(500).json({
          success: false,
          message: 'Failed to integrate with Paystack payment system',
          error: process.env.NODE_ENV === 'development' ? paystackError.message : 'Payment system error'
        });
      }
    } 
    // Handle international providers with Stripe
    else {
      console.log('🌍 Setting up international bank account with Stripe');
      
      try {
        // For Stripe, you might need to create a connected account or attach bank account
        // This is a simplified version - adjust based on your Stripe Connect implementation
        
        if (!routingNumber && (country === 'US' || country === 'CA')) {
          return res.status(400).json({
            success: false,
            message: `Routing number is required for ${country} bank accounts`
          });
        }

        // Store basic bank account info
        // In production, you'd use Stripe Connect to create external accounts
        bankAccountData = {
          accountHolderName,
          accountNumber: `***${accountNumber.slice(-4)}`,
          fullAccountNumber: accountNumber, // Encrypt this in production
          bankName,
          country,
          routingNumber: routingNumber ? `***${routingNumber.slice(-4)}` : undefined,
          isVerified: false, // Would be verified via Stripe in production
          processor: 'stripe'
        };

        // If user doesn't have Stripe account, create one
        if (!user.stripeAccountId) {
          const stripeAccount = await StripeService.createConnectedAccount({
            email: user.email,
            country: country,
            businessType: 'individual'
          });

          if (stripeAccount.success) {
            user.stripeAccountId = stripeAccount.accountId;
            console.log('✅ Stripe connected account created:', stripeAccount.accountId);
          }
        }

        setupResult = { success: true, message: 'Bank account details stored' };

      } catch (stripeError) {
        console.error('❌ Stripe integration error:', stripeError);
        return res.status(500).json({
          success: false,
          message: 'Failed to setup bank account with Stripe',
          error: process.env.NODE_ENV === 'development' ? stripeError.message : 'Payment system error'
        });
      }
    }

    // Update user with bank account information
    user.bankAccount = bankAccountData;
    user.country = country; // Update user's country if not set
    
    await user.save();

    console.log('✅ Bank account setup completed for user:', user.name);

    // Prepare response data (never send full account numbers)
    const responseData = {
      success: true,
      message: country === 'NG' 
        ? 'Bank account setup successfully with Paystack. You can now receive NGN payments.' 
        : 'Bank account details saved successfully. Account verification may be required.',
      data: {
        bankAccount: {
          accountHolderName: user.bankAccount.accountHolderName,
          accountNumber: user.bankAccount.accountNumber,
          bankName: user.bankAccount.bankName,
          country: user.bankAccount.country,
          isVerified: user.bankAccount.isVerified,
          processor: user.bankAccount.processor,
          ...(country === 'NG' && {
            recipientCode: user.bankAccount.recipientCode
          })
        },
        ...(setupResult.recipient && {
          paystackRecipient: {
            id: setupResult.recipient.id,
            recipientCode: setupResult.recipient.recipient_code,
            bankName: setupResult.recipient.bank_name
          }
        })
      }
    };

    res.json(responseData);

  } catch (error) {
    console.error('❌ Bank account setup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to setup bank account',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

router.get('/banks/nigeria', authenticateToken, async (req, res) => {
  try {
    // This would typically call Paystack's bank list endpoint
    const paystack = PaystackService.getPaystackInstance();
    const response = await paystack.get('/bank?country=nigeria');
    
    const banks = response.data.data.map(bank => ({
      id: bank.id,
      code: bank.code,
      name: bank.name
    }));

    res.json({
      success: true,
      data: { banks }
    });
  } catch (error) {
    console.error('Get Nigerian banks error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bank list',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


// Get payment status for a booking
router.get('/booking/:bookingId/status', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify user has access to this booking
    if (booking.customerId.toString() !== req.user.id && booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this booking payment'
      });
    }

    res.json({
      success: true,
      data: {
        payment: booking.payment,
        autoRefundAt: booking.autoRefundAt,
        timeUntilRefund: booking.autoRefundAt ? booking.autoRefundAt - new Date() : null
      }
    });

  } catch (error) {
    console.error('Get payment status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment status'
    });
  }
});

router.post('/webhooks/paystack', async (req, res) => {
  try {
    const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
      .update(JSON.stringify(req.body))
      .digest('hex');
    
    // Verify webhook signature
    if (hash !== req.headers['x-paystack-signature']) {
      console.log('❌ Invalid Paystack webhook signature');
      return res.status(401).send('Invalid signature');
    }

    const event = req.body;
    console.log(`✅ Paystack webhook received: ${event.event}`);

    switch (event.event) {
      case 'charge.success':
        await handleSuccessfulCharge(event.data);
        break;
        
      case 'transfer.success':
        await handleSuccessfulTransfer(event.data);
        break;
        
      case 'transfer.failed':
        await handleFailedTransfer(event.data);
        break;
        
      default:
        console.log(`🤔 Unhandled Paystack event: ${event.event}`);
    }

    res.status(200).json({ received: true });
  } catch (error) {
    console.error('Paystack webhook error:', error);
    res.status(500).json({ error: 'Webhook handler failed' });
  }
});


async function handleSuccessfulCharge(chargeData) {
  try {
    const { reference, metadata } = chargeData;
    
    // Find booking by reference
    const booking = await Booking.findOne({ 
      'payment.paymentIntentId': reference 
    });
    
    if (booking) {
      booking.payment.status = 'confirmed';
      booking.payment.confirmedAt = new Date();
      booking.status = 'confirmed';
      
      await booking.save();
      
      console.log(`✅ Paystack payment confirmed for booking: ${booking._id}`);
      
      // Notify provider
      await Notification.createNotification({
        userId: booking.providerId,
        type: 'payment_received',
        title: 'Payment Received',
        message: `Payment of ₦${booking.payment.amount} has been confirmed for your ${booking.serviceType} booking`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'high'
      });
    }
  } catch (error) {
    console.error('Error handling successful charge:', error);
  }
}

// Handle successful transfer to provider
async function handleSuccessfulTransfer(transferData) {
  try {
    const { recipient, amount, reason } = transferData;
    
    // Update provider payment status
    // You might want to store transfer references in your database
    console.log(`✅ Transfer successful to provider: ${recipient.name}, Amount: ₦${amount / 100}`);
    
  } catch (error) {
    console.error('Error handling successful transfer:', error);
  }
}


export default router;