import express from 'express';
import jwt from 'jsonwebtoken'; // ADD THIS IMPORT
import Rating from '../models/Rating.js';
import Booking from '../models/Booking.js';
import User from '../models/User.js';
import Notification from '../models/Notification.js';

const router = express.Router();

// Handle preflight requests
router.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(200).end();
});

// Authentication middleware
function authenticateToken(req, res, next) {
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
}

// Customer rates provider
router.post('/customer', authenticateToken, async (req, res) => {
  try {
    console.log('📝 Customer rating request received');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    console.log('User:', req.user.id);

    // Check if body exists
    if (!req.body) {
      return res.status(400).json({
        success: false,
        message: 'Request body is required'
      });
    }

    // Support multiple field name variations
    const bookingId = req.body.bookingId || req.body.booking || req.body.booking_id;
    const rating = req.body.rating || req.body.score || req.body.rating_value;
    const comment = req.body.comment || req.body.review || req.body.feedback || '';

    console.log('📋 Parsed fields:', { bookingId, rating, comment });

    // Validate required fields
    if (!bookingId) {
      return res.status(400).json({
        success: false,
        message: 'Booking ID is required'
      });
    }

    if (!rating) {
      return res.status(400).json({
        success: false,
        message: 'Rating is required'
      });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        message: 'Rating must be between 1 and 5'
      });
    }

    // Find the booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to rate this booking'
      });
    }

    // Check if booking is completed
    if (booking.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Can only rate completed bookings'
      });
    }

    // Check if customer has already rated this booking
    if (booking.ratingStatus?.customerRated) {
      return res.status(400).json({
        success: false,
        message: 'You have already rated this provider for this booking'
      });
    }

    // Find or create rating document
    let ratingDoc = await Rating.findOne({ bookingId });
    
    if (!ratingDoc) {
      ratingDoc = new Rating({
        bookingId,
        providerId: booking.providerId,
        customerId: booking.customerId,
        serviceType: booking.serviceType,
        providerRating: rating,
        providerComment: comment,
        customerRated: true,
        ratedAt: new Date()
      });
    } else {
      ratingDoc.providerRating = rating;
      ratingDoc.providerComment = comment;
      ratingDoc.customerRated = true;
      ratingDoc.ratedAt = new Date();
    }

    await ratingDoc.save();

    // Update booking rating status
    booking.ratingStatus = booking.ratingStatus || {};
    booking.ratingStatus.customerRated = true;
    await booking.save();

    // Update provider's average rating
    await updateProviderAverageRating(booking.providerId);

    // Create notification for provider
    try {
      await Notification.createNotification({
        userId: booking.providerId,
        type: 'rating_received',
        title: 'New Rating Received!',
        message: `A customer rated you ${rating} stars for ${booking.serviceType}`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'medium'
      });
    } catch (notificationError) {
      console.error('Failed to create provider notification:', notificationError);
    }

    console.log('✅ Customer rating submitted successfully:', {
      bookingId,
      rating,
      providerId: booking.providerId
    });

    res.json({
      success: true,
      message: 'Rating submitted successfully',
      data: { 
        rating: ratingDoc,
        averageRating: await Rating.getProviderAverageRating(booking.providerId)
      }
    });

  } catch (error) {
    console.error('❌ Customer rating error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit rating',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

router.get('/provider', authenticateToken, async (req, res) => {
  try {
    const providerId = req.user.id;
    
    console.log('📊 Fetching ratings for provider:', providerId);

    // Find all ratings for this provider where customer has rated
    const ratings = await Rating.find({ 
      providerId,
      customerRated: true 
    })
      .populate('customerId', 'name email profileImage')
      .sort({ ratedAt: -1 });

    console.log(`✅ Found ${ratings.length} ratings for provider ${providerId}`);

    // Transform the data to match the frontend expected format
    const transformedRatings = ratings.map(rating => ({
      _id: rating._id,
      providerId: rating.providerId,
      customerId: {
        _id: rating.customerId._id,
        name: rating.customerId.name,
        email: rating.customerId.email,
        profileImage: rating.customerId.profileImage
      },
      bookingId: rating.bookingId,
      rating: rating.providerRating || 5, // Use providerRating field
      comment: rating.providerComment || '',
      serviceType: rating.serviceType,
      createdAt: rating.ratedAt,
      updatedAt: rating.updatedAt
    }));

    res.json({
      success: true,
      data: transformedRatings,
      message: `Found ${ratings.length} ratings`
    });

  } catch (error) {
    console.error('❌ Error fetching provider ratings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch ratings',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});



router.post('/test-body', (req, res) => {
  console.log('🧪 Test body endpoint hit');
  console.log('Request body:', req.body);
  console.log('Request headers:', req.headers);
  console.log('Content-Type:', req.headers['content-type']);
  
  res.json({
    success: true,
    message: 'Body parsing test',
    data: {
      bodyReceived: req.body,
      bodyType: typeof req.body,
      bodyKeys: req.body ? Object.keys(req.body) : 'No body',
      contentType: req.headers['content-type']
    }
  });
});

// Provider rates customer
router.post('/provider', authenticateToken, async (req, res) => {
  try {
    const { bookingId, rating, comment } = req.body;
    const providerId = req.user.id;

    console.log('📝 Provider rating request:', { 
      bookingId, 
      rating, 
      comment, 
      providerId 
    });

    // Validate input
    if (!bookingId || !rating) {
      return res.status(400).json({
        success: false,
        message: 'Booking ID and rating are required'
      });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        message: 'Rating must be between 1 and 5'
      });
    }

    // Find the booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify the user is the provider for this booking
    if (booking.providerId.toString() !== providerId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to rate this booking'
      });
    }

    // Check if booking is completed
    if (booking.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Can only rate completed bookings'
      });
    }

    // Check if provider has already rated this booking
    if (booking.ratingStatus?.providerRated) {
      return res.status(400).json({
        success: false,
        message: 'You have already rated this customer for this booking'
      });
    }

    // Find or create rating document
    let ratingDoc = await Rating.findOne({ bookingId });
    
    if (!ratingDoc) {
      ratingDoc = new Rating({
        bookingId,
        providerId: booking.providerId,
        customerId: booking.customerId,
        serviceType: booking.serviceType,
        customerRating: rating,
        customerComment: comment || '',
        providerRated: true,
        providerRatedAt: new Date()
      });
    } else {
      ratingDoc.customerRating = rating;
      ratingDoc.customerComment = comment || '';
      ratingDoc.providerRated = true;
      ratingDoc.providerRatedAt = new Date();
    }

    await ratingDoc.save();

    // Update booking rating status
    booking.ratingStatus = booking.ratingStatus || {};
    booking.ratingStatus.providerRated = true;
    await booking.save();

    // Update customer's average rating
    await updateCustomerAverageRating(booking.customerId);

    // Create notification for customer
    try {
      await Notification.createNotification({
        userId: booking.customerId,
        type: 'rating_received',
        title: 'New Rating Received',
        message: `A provider rated you ${rating} stars`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'medium'
      });
    } catch (notificationError) {
      console.error('Failed to create customer notification:', notificationError);
    }

    console.log('✅ Provider rating submitted successfully for booking:', bookingId);

    res.json({
      success: true,
      message: 'Customer rating submitted successfully',
      data: { rating: ratingDoc }
    });

  } catch (error) {
    console.error('❌ Provider rating error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit customer rating',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Helper function to update provider's average rating
async function updateProviderAverageRating(providerId) {
  try {
    const ratingStats = await Rating.getProviderAverageRating(providerId);
    
    await User.findByIdAndUpdate(providerId, {
      averageRating: ratingStats.averageRating,
      reviewCount: ratingStats.totalRatings,
      ratingBreakdown: ratingStats.ratingBreakdown
    });

    console.log(`✅ Updated provider ${providerId} rating: ${ratingStats.averageRating} from ${ratingStats.totalRatings} reviews`);
  } catch (error) {
    console.error('Error updating provider average rating:', error);
  }
}

// Helper function to update customer's average rating
async function updateCustomerAverageRating(customerId) {
  try {
    const ratingStats = await Rating.getCustomerAverageRating(customerId);
    
    await User.findByIdAndUpdate(customerId, {
      customerRating: ratingStats.averageRating,
      customerRatingCount: ratingStats.totalRatings
    });

    console.log(`✅ Updated customer ${customerId} rating: ${ratingStats.averageRating} from ${ratingStats.totalRatings} reviews`);
  } catch (error) {
    console.error('Error updating customer average rating:', error);
  }
}

export default router;