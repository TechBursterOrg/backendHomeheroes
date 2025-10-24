// routes/providers.routes.js
import express from 'express';
import User from '../models/User.js';
import Gallery from '../models/Gallery.js';
import Rating from '../models/Rating.js';
import Booking from '../models/Booking.js';

const router = express.Router();

// Get provider profile by ID
router.get('/:id', async (req, res) => {
  try {
    const providerId = req.params.id;
    
    console.log('👤 Fetching provider profile:', providerId);

    const provider = await User.findById(providerId)
      .select('name email services hourlyRate averageRating city state country profileImage isAvailableNow experience phoneNumber address reviewCount completedJobs isVerified isTopRated responseTime createdAt')
      .lean();

    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    // Calculate REAL completed jobs from bookings
    const completedJobsCount = await Booking.countDocuments({
      providerId: providerId,
      status: 'completed'
    });

    console.log('📊 Completed jobs count:', completedJobsCount);

    // Calculate REAL rating stats
    const ratingStats = await Rating.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          customerRated: true,
          providerRating: { $exists: true, $ne: null, $gte: 1, $lte: 5 }
        }
      },
      {
        $group: {
          _id: '$providerId',
          averageRating: { $avg: '$providerRating' },
          totalRatings: { $sum: 1 },
          ratingBreakdown: {
            $push: '$providerRating'
          }
        }
      }
    ]);

    console.log('⭐ Rating stats:', ratingStats);

    const stats = ratingStats.length > 0 ? ratingStats[0] : {
      averageRating: 0,
      totalRatings: 0
    };

    // Get gallery count
    const galleryCount = await Gallery.countDocuments({ userId: providerId });

    // Format the response with REAL data
    const providerProfile = {
      ...provider,
      completedJobs: completedJobsCount, // Use REAL count from bookings
      averageRating: Math.round(stats.averageRating * 10) / 10 || 0,
      reviewCount: stats.totalRatings || 0,
      isAvailableNow: provider.isAvailableNow || false,
      isVerified: provider.isVerified || false,
      isTopRated: provider.isTopRated || false,
      responseTime: provider.responseTime || 'within 1 hour',
      joinedDate: provider.createdAt ? new Date(provider.createdAt).toLocaleDateString() : 'Recently',
      galleryCount: galleryCount // Add gallery count
    };

    console.log('✅ Final provider profile:', {
      name: providerProfile.name,
      completedJobs: providerProfile.completedJobs,
      averageRating: providerProfile.averageRating,
      reviewCount: providerProfile.reviewCount,
      galleryCount: providerProfile.galleryCount
    });

    res.json({
      success: true,
      data: providerProfile
    });
  } catch (error) {
    console.error('❌ Get provider profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider profile'
    });
  }
});

router.get('/:id/gallery', async (req, res) => {
  try {
    const providerId = req.params.id;
    const { page = 1, limit = 50, category } = req.query;

    console.log('🖼️ Fetching gallery for provider:', providerId);

    let filter = { userId: providerId };
    
    if (category && category !== 'all') {
      filter.category = category;
    }

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { createdAt: -1 },
      populate: { path: 'userId', select: 'name profileImage' }
    };

    const result = await Gallery.paginate(filter, options);

    console.log('📸 Gallery images found:', result.docs.length);

    // Format images with proper URLs
    const imagesWithFullUrl = result.docs.map(image => {
      const imageObj = image.toObject();
      
      // Handle both local and external URLs
      let fullImageUrl = imageObj.imageUrl;
      if (imageObj.imageUrl && !imageObj.imageUrl.startsWith('http')) {
        fullImageUrl = `${req.protocol}://${req.get('host')}${imageObj.imageUrl}`;
      }
      
      return {
        ...imageObj,
        imageUrl: fullImageUrl,
        fullImageUrl: fullImageUrl
      };
    });

    res.json({
      success: true,
      data: {
        docs: imagesWithFullUrl,
        totalDocs: result.totalDocs,
        limit: result.limit,
        totalPages: result.totalPages,
        page: result.page,
        pagingCounter: result.pagingCounter,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage,
        prevPage: result.prevPage,
        nextPage: result.nextPage
      }
    });
  } catch (error) {
    console.error('❌ Get provider gallery error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider gallery'
    });
  }
});


router.get('/:id/reviews', async (req, res) => {
  try {
    const providerId = req.params.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50; // Increased limit to show all
    const skip = (page - 1) * limit;

    console.log('📝 Fetching reviews for provider:', providerId);

    // Get ALL ratings for this provider (both customer and provider ratings)
    const ratings = await Rating.find({
      providerId: providerId,
      $or: [
        { customerRated: true, providerRating: { $exists: true, $ne: null } },
        { providerRated: true, customerRating: { $exists: true, $ne: null } }
      ]
    })
    .populate('customerId', 'name profileImage')
    .populate('providerId', 'name profileImage')
    .populate('bookingId', 'serviceType requestedAt customerName providerName')
    .sort({ ratedAt: -1, createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();

    console.log('📊 Raw ratings found:', ratings.length);

    const totalReviews = await Rating.countDocuments({
      providerId: providerId,
      $or: [
        { customerRated: true, providerRating: { $exists: true, $ne: null } },
        { providerRated: true, customerRating: { $exists: true, $ne: null } }
      ]
    });

    // Format reviews properly
    const formattedReviews = ratings.map(rating => {
      // Determine if this is a customer rating the provider or provider rating the customer
      const isCustomerRating = rating.customerRated && rating.providerRating;
      
      return {
        _id: rating._id,
        customerId: {
          _id: rating.customerId?._id || 'unknown',
          name: rating.customerId?.name || 
                rating.bookingId?.customerName || 
                'Anonymous Customer',
          profileImage: rating.customerId?.profileImage || null
        },
        rating: isCustomerRating ? rating.providerRating : rating.customerRating,
        comment: isCustomerRating ? rating.providerComment : rating.customerComment,
        serviceType: rating.bookingId?.serviceType || 
                    rating.serviceType || 
                    'General Service',
        createdAt: rating.ratedAt || rating.createdAt,
        reviewType: isCustomerRating ? 'customer_to_provider' : 'provider_to_customer'
      };
    }).filter(review => review.rating && review.rating >= 1); // Only include valid ratings

    console.log('✅ Formatted reviews:', formattedReviews.length);

    res.json({
      success: true,
      data: {
        reviews: formattedReviews,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalReviews / limit),
          totalReviews: totalReviews,
          hasNextPage: page < Math.ceil(totalReviews / limit),
          hasPrevPage: page > 1
        }
      }
    });
  } catch (error) {
    console.error('❌ Get provider reviews error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider reviews'
    });
  }
});




export default router;