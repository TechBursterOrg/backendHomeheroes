// models/ServiceRequest.js
import mongoose from 'mongoose';
import mongoosePaginate from 'mongoose-paginate-v2';

const serviceRequestSchema = new mongoose.Schema({
  serviceType: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  location: {
    type: String,
    required: true,
    trim: true
  },
  coordinates: {
    lat: {
      type: Number,
      default: 0
    },
    lng: {
      type: Number,
      default: 0
    }
  },
  urgency: {
    type: String,
    enum: ['normal', 'urgent', 'high'],
    default: 'normal'
  },
  timeframe: {
    type: String,
    default: 'ASAP'
  },
  budget: {
    type: String,
    default: 'Not specified'
  },
  contactInfo: {
    name: String,
    phone: String,
    email: String
  },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  providerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  category: {
    type: String,
    default: 'general'
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'rejected', 'completed', 'cancelled'],
    default: 'pending'
  },
  acceptedAt: {
    type: Date
  },
  // New fields for better job matching
  skillsRequired: [{
    type: String,
    trim: true
  }],
  estimatedDuration: {
    type: String,
    default: 'Not specified'
  },
  preferredSchedule: {
    type: String,
    default: 'Flexible'
  },
  images: [{
    type: String
  }],
  isPublic: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

serviceRequestSchema.index({ location: 'text', serviceType: 'text', description: 'text' });
serviceRequestSchema.index({ status: 1, createdAt: -1 });
serviceRequestSchema.index({ customerId: 1, createdAt: -1 });
serviceRequestSchema.index({ providerId: 1, createdAt: -1 });

serviceRequestSchema.plugin(mongoosePaginate);

export default mongoose.model('ServiceRequest', serviceRequestSchema);