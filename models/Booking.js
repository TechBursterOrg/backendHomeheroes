import mongoose from 'mongoose';
import mongoosePaginate from 'mongoose-paginate-v2';

const bookingSchema = new mongoose.Schema({
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  providerName: {
    type: String,
    required: true
  },
  providerEmail: {
    type: String,
    required: true
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  customerName: {
    type: String,
    required: true
  },
  customerEmail: {
    type: String,
    required: true
  },
  customerPhone: {
    type: String,
    default: ''
  },
  serviceType: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  location: {
    type: String,
    required: true
  },
  timeframe: {
    type: String,
    required: true
  },
  budget: {
    type: String,
    default: 'Not specified'
  },
  specialRequests: {
    type: String,
    default: ''
  },
  bookingType: {
    type: String,
    enum: ['immediate', 'long-term'],
    default: 'immediate'
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected', 'completed', 'cancelled'],
    default: 'pending'
  },
  requestedAt: {
    type: Date,
    default: Date.now
  },
  acceptedAt: {
    type: Date
  },
  completedAt: {
    type: Date
  },
  updatedAt: {
    type: Date,
    default: Date.now
  },

  ratingStatus: {
    customerRated: { type: Boolean, default: false },
    providerRated: { type: Boolean, default: false }
  },

  ratingPrompted: { 
    type: Boolean, 
    default: false 
  },
  completedAt: {
    type: Date
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'cancelled'], // Changed from 'accepted' to 'confirmed'
    default: 'pending'
  },
  ratingStatus: {
    customerRated: { type: Boolean, default: false },
    providerRated: { type: Boolean, default: false }
  },
  ratingPrompted: { type: Boolean, default: false }
}, {
  timestamps: true
});

bookingSchema.plugin(mongoosePaginate);

// Update the updatedAt field before saving
bookingSchema.index({ status: 1, completedAt: 1 });
bookingSchema.index({ customerId: 1, ratingStatus: 1 });
bookingSchema.index({ providerId: 1, ratingStatus: 1 });
bookingSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

export default mongoose.model('Booking', bookingSchema);