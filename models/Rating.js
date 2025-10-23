// models/Rating.js - ENHANCED VERSION
import mongoose from 'mongoose';

const ratingSchema = new mongoose.Schema({
  bookingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Booking',
    required: true
  },
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  providerRating: {
    type: Number,
    min: 1,
    max: 5,
    required: false,
    validate: {
      validator: Number.isInteger,
      message: 'Provider rating must be an integer'
    }
  },
  providerComment: {
    type: String,
    default: "",
    maxlength: 500
  },
  customerRating: {
    type: Number,
    min: 1,
    max: 5,
    required: false,
    validate: {
      validator: Number.isInteger,
      message: 'Customer rating must be an integer'
    }
  },
  customerComment: {
    type: String,
    default: "",
    maxlength: 500
  },
  customerRated: {
    type: Boolean,
    default: false
  },
  providerRated: {
    type: Boolean,
    default: false
  },
  serviceType: {
    type: String,
    required: true
  },
  ratedAt: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['pending', 'completed', 'cancelled'],
    default: 'pending'
  }
}, {
  timestamps: true
});

// Static method to get provider's average rating - FIXED VERSION
ratingSchema.statics.getProviderAverageRating = async function(providerId) {
  try {
    console.log('📊 Calculating average rating for provider:', providerId);
    
    const result = await this.aggregate([
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
    
    console.log('📈 Rating aggregation result:', result);
    
    if (result.length === 0) {
      console.log('📭 No ratings found for provider');
      return {
        averageRating: 0,
        totalRatings: 0,
        ratingBreakdown: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 }
      };
    }
    
    const ratingData = result[0];
    
    // Calculate rating breakdown
    const breakdown = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    if (ratingData.ratingBreakdown && Array.isArray(ratingData.ratingBreakdown)) {
      ratingData.ratingBreakdown.forEach(rating => {
        const roundedRating = Math.round(rating); // Use round instead of floor
        if (roundedRating >= 1 && roundedRating <= 5) {
          breakdown[roundedRating]++;
        }
      });
    }
    
    const finalResult = {
      averageRating: Math.round(ratingData.averageRating * 10) / 10,
      totalRatings: ratingData.totalRatings,
      ratingBreakdown: breakdown
    };
    
    console.log('✅ Final rating stats:', finalResult);
    return finalResult;
    
  } catch (error) {
    console.error('❌ Error calculating provider average rating:', error);
    return {
      averageRating: 0,
      totalRatings: 0,
      ratingBreakdown: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 }
    };
  }
};

// Instance method to check if rating is complete
ratingSchema.methods.isComplete = function() {
  return this.customerRated && this.providerRated;
};

// Static method to create or update customer rating
ratingSchema.statics.submitCustomerRating = async function(bookingId, customerId, rating, comment) {
  try {
    // Find the booking first
    const booking = await mongoose.model('Booking').findById(bookingId);
    if (!booking) {
      throw new Error('Booking not found');
    }

    // Verify the customer owns this booking
    if (booking.customerId.toString() !== customerId) {
      throw new Error('Not authorized to rate this booking');
    }

    // Find existing rating or create new one
    let ratingDoc = await this.findOne({ bookingId });
    
    if (!ratingDoc) {
      ratingDoc = new this({
        bookingId,
        providerId: booking.providerId,
        customerId,
        serviceType: booking.serviceType
      });
    }

    // Update customer rating
    ratingDoc.providerRating = rating;
    ratingDoc.providerComment = comment || '';
    ratingDoc.customerRated = true;
    ratingDoc.ratedAt = new Date();

    if (ratingDoc.customerRated && ratingDoc.providerRated) {
      ratingDoc.status = 'completed';
    }

    await ratingDoc.save();

    // Update provider's average rating
    await this.updateProviderRating(booking.providerId);

    return ratingDoc;
  } catch (error) {
    console.error('Submit customer rating error:', error);
    throw error;
  }
};

// Static method to update provider rating in User model
ratingSchema.statics.updateProviderRating = async function(providerId) {
  try {
    const ratingStats = await this.getProviderAverageRating(providerId);
    
    await mongoose.model('User').findByIdAndUpdate(providerId, {
      averageRating: ratingStats.averageRating,
      reviewCount: ratingStats.totalRatings
    });

    console.log(`✅ Updated provider ${providerId} rating: ${ratingStats.averageRating}`);
  } catch (error) {
    console.error('Error updating provider rating:', error);
  }
};

// Ensure one rating document per booking
ratingSchema.index({ bookingId: 1 }, { unique: true });

// Compound indexes for better query performance
ratingSchema.index({ providerId: 1, customerRated: 1 });
ratingSchema.index({ customerId: 1, providerRated: 1 });
ratingSchema.index({ providerId: 1, status: 1 });

export default mongoose.model('Rating', ratingSchema);