// models/Rating.js
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
    required: false
  },
  providerComment: {
    type: String,
    default: ""
  },
  customerRating: {
    type: Number,
    min: 1,
    max: 5,
    required: false
  },
  customerComment: {
    type: String,
    default: ""
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
  }
}, {
  timestamps: true
});



// Static method to get provider's average rating
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
        const roundedRating = Math.floor(rating);
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

ratingSchema.statics.getCustomerAverageRating = async function(customerId) {
  try {
    const result = await this.aggregate([
      {
        $match: {
          customerId: new mongoose.Types.ObjectId(customerId),
          providerRated: true,
          customerRating: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: '$customerId',
          averageRating: { $avg: '$customerRating' },
          totalRatings: { $sum: 1 }
        }
      }
    ]);
    
    if (result.length === 0) {
      return {
        averageRating: 0,
        totalRatings: 0
      };
    }
    
    return {
      averageRating: Math.round(result[0].averageRating * 10) / 10,
      totalRatings: result[0].totalRatings
    };
  } catch (error) {
    console.error('Error calculating customer average rating:', error);
    return {
      averageRating: 0,
      totalRatings: 0
    };
  }
};


// Ensure one rating document per booking
ratingSchema.index({ bookingId: 1 }, { unique: true });

// Compound indexes for better query performance
ratingSchema.index({ providerId: 1, customerRated: 1 });
ratingSchema.index({ customerId: 1, providerRated: 1 });

export default mongoose.model('Rating', ratingSchema);