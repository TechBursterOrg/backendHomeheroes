import mongoose from 'mongoose';

const ratingSchema = new mongoose.Schema({
  // Rating from customer to provider
  providerRating: {
    type: Number,
    min: 1,
    max: 5,
    required: function() {
      return this.customerRated;
    }
  },
  providerComment: {
    type: String,
    maxlength: 500,
    default: ''
  },
  
  // Rating from provider to customer
  customerRating: {
    type: Number,
    min: 1,
    max: 5,
    required: function() {
      return this.providerRated;
    }
  },
  customerComment: {
    type: String,
    maxlength: 500,
    default: ''
  },
  
  // Rating status flags
  customerRated: {
    type: Boolean,
    default: false
  },
  providerRated: {
    type: Boolean,
    default: false
  },
  
  // References
  bookingId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Booking',
    required: true,
    index: true
  },
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  // Service details for context
  serviceType: {
    type: String,
    required: true
  },
  
  // Timestamps
  customerRatedAt: {
    type: Date
  },
  providerRatedAt: {
    type: Date
  }
}, {
  timestamps: true
});

// Ensure one rating document per booking
ratingSchema.index({ bookingId: 1 }, { unique: true });

// Compound indexes for better query performance
ratingSchema.index({ providerId: 1, customerRated: 1 });
ratingSchema.index({ customerId: 1, providerRated: 1 });
ratingSchema.index({ providerId: 1, createdAt: -1 });
ratingSchema.index({ customerId: 1, createdAt: -1 });

// Virtual for average provider rating (if needed for quick access)
ratingSchema.virtual('averageProviderRating').get(function() {
  if (this.customerRated) {
    return this.providerRating;
  }
  return null;
});

// Method to check if both parties have rated
ratingSchema.methods.isFullyRated = function() {
  return this.customerRated && this.providerRated;
};

// Static method to get provider's average rating
ratingSchema.statics.getProviderAverageRating = async function(providerId) {
  const result = await this.aggregate([
    {
      $match: {
        providerId: new mongoose.Types.ObjectId(providerId),
        customerRated: true,
        providerRating: { $exists: true, $ne: null }
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
  
  if (result.length === 0) {
    return {
      averageRating: 0,
      totalRatings: 0,
      ratingBreakdown: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 }
    };
  }
  
  const ratingData = result[0];
  
  // Calculate rating breakdown
  const breakdown = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  ratingData.ratingBreakdown.forEach(rating => {
    if (rating >= 1 && rating <= 5) {
      breakdown[rating]++;
    }
  });
  
  return {
    averageRating: Math.round(ratingData.averageRating * 10) / 10,
    totalRatings: ratingData.totalRatings,
    ratingBreakdown: breakdown
  };
};

// Static method to get customer's average rating
ratingSchema.statics.getCustomerAverageRating = async function(customerId) {
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
};

export default mongoose.model('Rating', ratingSchema);