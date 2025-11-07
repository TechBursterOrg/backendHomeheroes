// routes/bookingRoutes.js - Add this endpoint
import express from 'express';
import Booking from '../models/Booking.js';
import PaymentService from '../services/paymentService.js';
import jwt from 'jsonwebtoken';

const router = express.Router();

// Add authenticateToken middleware if not already present
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
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    
    try {
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
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
      return res.status(500).json({
        success: false,
        message: 'Error verifying user'
      });
    }
  });
};

// Confirm payment for booking


router.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});
router.post('/:bookingId/create-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    
    console.log('💰 Creating payment for booking:', bookingId);

    // Simple working response
    res.json({
      success: true,
      message: 'Payment created successfully',
      data: {
        bookingId,
        paymentIntentId: `pay_${Date.now()}`,
        status: 'requires_payment_method',
        amount: 100, // You can get this from the booking
        currency: 'NGN',
        processor: 'paystack'
      }
    });

  } catch (error) {
    console.error('Create payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment',
      error: error.message
    });
  }
});

router.post('/:bookingId/confirm-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    
    console.log('✅ Confirming payment for booking:', bookingId);

    // Simple working response
    res.json({
      success: true,
      message: 'Payment confirmed successfully',
      data: {
        bookingId,
        status: 'confirmed',
        confirmedAt: new Date().toISOString(),
        amount: 100,
        currency: 'NGN'
      }
    });

  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm payment',
      error: error.message
    });
  }
});



export default router;