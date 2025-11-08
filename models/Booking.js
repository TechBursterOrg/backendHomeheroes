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

  price: {
    type: Number,
    required: true,
    default: 0,
    min: 0
  },
  amount: {
    type: Number,
    required: true,
    default: 0,
    min: 0
  },
  budget: {
    type: String,
    required: false
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
    enum: ['pending','awaiting_payment',  'confirmed', 'completed', 'cancelled'],
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
  
  // New fields added here
  providerArrived: {
    type: Boolean,
    default: false
  },
  providerArrivedAt: Date,
  showHeroHereButton: {
    type: Boolean,
    default: false
  },
  customerConfirmedHeroHere: {
    type: Boolean,
    default: false
  },
  customerConfirmedAt: Date,
  heroHereConfirmed: {
    type: Boolean,
    default: false
  },
  
  // Payment release fields
  autoRefundAt: Date,
  paymentReleased: {
    type: Boolean,
    default: false
  },
  paymentReleasedAt: Date,
  
  // Commission tracking
  commissionAmount: Number,
  providerAmount: Number,

  payment: {
    processor: {
      type: String,
      enum: ['stripe', 'paystack', 'simulation'], 
      default: null
    },
    paymentIntentId: String,
    amount: Number,
    currency: {
      type: String,
      default: 'NGN'
    },
    status: {
      type: String,
      enum: ['requires_payment_method', 'held', 'released', 'refunded', 'failed'],
      default: 'requires_payment_method'
    },
    heldAt: Date,
    releasedAt: Date,
    refundedAt: Date,
    autoRefundAt: Date,
    commission: Number,
    providerAmount: Number
  },
  serviceConfirmedByCustomer: {
    type: Boolean,
    default: false
  },
  serviceConfirmedAt: Date
}, {
  timestamps: true
});



bookingSchema.plugin(mongoosePaginate);

// Indexes for query optimization
bookingSchema.index({ status: 1, completedAt: 1 });
bookingSchema.index({ customerId: 1, ratingStatus: 1 });
bookingSchema.index({ providerId: 1, ratingStatus: 1 });
bookingSchema.index({ 'payment.status': 1 });
bookingSchema.index({ 'payment.autoRefundAt': 1 });

// Update the updatedAt field before saving
bookingSchema.pre('save', function(next) {
  // If price is not set, try to extract from budget
  if ((!this.price || this.price === 0) && this.budget) {
    const numericValue = this.budget.replace(/[^\d.]/g, '');
    this.price = parseFloat(numericValue) || 0;
  }
  
  // If amount is not set, use price
  if (!this.amount || this.amount === 0) {
    this.amount = this.price;
  }
  
  next();
});

export default mongoose.model('Booking', bookingSchema);