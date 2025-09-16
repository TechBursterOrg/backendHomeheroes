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
  }
}, {
  timestamps: true
});

serviceRequestSchema.plugin(mongoosePaginate);

export default mongoose.model('ServiceRequest', serviceRequestSchema);