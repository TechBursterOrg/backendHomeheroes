import mongoose from 'mongoose';
import mongoosePaginate from 'mongoose-paginate-v2';

const gallerySchema = new mongoose.Schema({
title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    maxlength: 500,
    default: ''
  },
  imageMissing: {
  type: Boolean,
  default: false
},
  category: {
    type: String,
    required: true,
    enum: ['cleaning', 'handyman', 'gardening', 'other'],
    default: 'other'
  },
  imageUrl: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fullImageUrl: {
    type: String,
    required: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  featured: {
    type: Boolean,
    default: false
  },
  views: {
    type: Number,
    default: 0,
    min: 0
  },
  likes: {
    type: Number,
    default: 0,
    min: 0
  }
}, {
  timestamps: true
});

// Indexes for better performance
gallerySchema.index({ userId: 1, createdAt: -1 });
gallerySchema.index({ category: 1, featured: -1 });
gallerySchema.index({ featured: -1, createdAt: -1 });
gallerySchema.index({ title: 'text', description: 'text' });

// Add pagination plugin
gallerySchema.plugin(mongoosePaginate);

// Pre-save middleware
gallerySchema.pre('save', function(next) {
  if (this.views < 0) this.views = 0;
  if (this.likes < 0) this.likes = 0;
  next();
});

const Gallery = mongoose.model('Gallery', gallerySchema);

export default Gallery;