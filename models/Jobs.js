import mongoose from 'mongoose';

const jobSchema = new mongoose.Schema({
  serviceType: { type: String, required: true },
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, required: true },
  startTime: { type: String, required: true },
  duration: { type: String, default: '1 hour' },
  location: { type: String, required: true },
  payment: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'in-progress', 'completed', 'cancelled'], 
    default: 'pending' 
  },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  category: { type: String, default: 'other' },
  createdAt: { type: Date, default: Date.now }
});

export default mongoose.model('Job', jobSchema);