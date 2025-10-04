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
  // Customer rating of provider
  providerRating: {
    type: Number,
    min: 1,
    max: 5
  },
  providerComment: {
    type: String,
    maxlength: 500
  },
  // Provider rating of customer
  customerRating: {
    type: Number,
    min: 1,
    max: 5
  },
  // Customer rating status
  customerRated: {
    type: Boolean,
    default: false
  },
  // Provider rating status
  providerRated: {
    type: Boolean,
    default: false
  },
  ratedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Ensure one rating per booking
ratingSchema.index({ bookingId: 1 }, { unique: true });

// Compound indexes for better query performance
ratingSchema.index({ providerId: 1, customerRated: 1 });
ratingSchema.index({ customerId: 1, providerRated: 1 });

export default mongoose.model('Rating', ratingSchema);