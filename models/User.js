import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  // Existing fields
  name: {
    type: String,
    required: true,
    trim: true,
    minLength: 2,
    maxLength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minLength: 6
  },
  userType: {
    type: String,
    enum: ['customer', 'provider', 'both'],
    required: true
  },
  country: {
    type: String,
    enum: ['UK', 'USA', 'CANADA', 'NIGERIA'],
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    default: null
  },
  emailVerificationExpires: {
    type: Date,
    default: null
  },
  passwordResetToken: {
    type: String,
    default: null
  },
  passwordResetExpires: {
    type: Date,
    default: null
  },
  lastLogin: {
    type: Date,
    default: null
  },
  profilePicture: {
    type: String,
    default: null
  },
  phoneNumber: {
    type: String,
    default: null
  },
  services: [{
    type: String,
    enum: [
      'House Cleaning',
      'Plumbing Repair', 
      'Garden Maintenance',
      'Electrical Work',
      'Painting',
      'General Maintenance',
      'Barber Services',
      'Hair Styling',
      'Veterinary Services',
      'Tailoring',
      'Shoe Repair',
      'Engineering Services',
      'Mechanical Services',
      'Car Washing',
      'Carpentry',
      'Other'
    ]
  }],
  hourlyRate: {
    type: Number,
    default: null
  },
  profileImage: {
    type: String,
    default: ''
  },
  experience: {
    type: String,
    default: null
  },
  certifications: [{
    type: String
  }],
  
  // Dashboard-related fields
  availability: [{
    id: String,
    date: {
      type: String,
      required: true
    },
    startTime: {
      type: String,
      required: true
    },
    endTime: {
      type: String,
      required: true
    },
    serviceType: {
      type: String,
      required: true
    },
    notes: {
      type: String,
      default: ''
    },
    status: {
      type: String,
      enum: ['active', 'inactive', 'booked'],
      default: 'active'
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Stats for dashboard
  totalEarnings: {
    type: Number,
    default: 0
  },
  completedJobs: {
    type: Number,
    default: 0
  },
  averageRating: {
    type: Number,
    default: 0,
    min: 0,
    max: 5
  },
  activeClients: {
    type: Number,
    default: 0
  },
  
  // Temporary fields for demo data (remove when you have real job system)
  recentJobs: [{
    id: Number,
    title: String,
    client: String,
    location: String,
    date: String,
    time: String,
    payment: String,
    status: String,
    category: String
  }],
  
  upcomingTasks: [{
    id: Number,
    title: String,
    time: String,
    duration: String,
    client: String,
    priority: String,
    category: String
  }]
}, {
  timestamps: true
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ emailVerificationToken: 1 });
userSchema.index({ passwordResetToken: 1 });

const User = mongoose.model('User', userSchema);

export default User;