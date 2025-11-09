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
  phoneNumber: {
    type: String,
    trim: true,
    sparse: true
  },
  isPhoneVerified: {
    type: Boolean,
    default: false
  },
  totalEarnings: {
    type: Number,
    default: 0
  },
  completedJobs: {
    type: Number,
    default: 0
  },
  activeClients: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  userType: {
    type: String,
    enum: ['customer', 'provider', 'both'],
    required: true
  },

    businessHours: [{
    dayOfWeek: {
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
    isAvailable: {
      type: Boolean,
      default: true
    },
    serviceTypes: [{
      type: String
    }],
    notes: {
      type: String,
      default: ''
    }
  }],


  favorites: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],

  

  isAvailableNow: {
    type: Boolean,
    default: false
  },
  identityVerification: {
    nin: {
      type: String,
      trim: true,
      sparse: true
    },
    nepaBillUrl: {
      type: String,
      trim: true
    },
    isNinVerified: {
      type: Boolean,
      default: false
    },
    isNepaVerified: {
      type: Boolean,
      default: false
    },
    verificationStatus: {
      type: String,
      enum: ['unverified', 'pending', 'verified', 'rejected'],
      default: 'unverified'
    },
    verificationSubmittedAt: {
      type: Date
    },
    verificationReviewedAt: {
      type: Date
    },
    verificationNotes: {
      type: String
    }
  },

  // ==================== NEW SETTINGS STRUCTURE ====================
  
  // General preferences (for both customers and providers)
  preferences: {
    // Customer preferences (existing)
    emailNotifications: { type: Boolean, default: true },
    smsNotifications: { type: Boolean, default: false },
    bookingReminders: { type: Boolean, default: true },
    marketingEmails: { type: Boolean, default: false },
    providerMessages: { type: Boolean, default: true },
    searchRadius: { type: String, default: '10' },
    contactMethod: { type: String, default: 'message' },
    
    // New general preferences
    language: { type: String, default: 'en-US' },
    timeZone: { type: String, default: 'America/New_York' },
    currency: { type: String, default: 'USD' },
    theme: { type: String, default: 'light', enum: ['light', 'dark', 'auto'] }
  },

  // Notification settings (unified structure)
  notificationSettings: {
    // Customer notifications (existing - for backward compatibility)
    emailNotifications: { type: Boolean, default: true },
    smsNotifications: { type: Boolean, default: false },
    bookingReminders: { type: Boolean, default: true },
    marketingEmails: { type: Boolean, default: false },
    providerMessages: { type: Boolean, default: true },
    
    // New unified notification structure
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    newJobs: { type: Boolean, default: true },
    messages: { type: Boolean, default: true },
    payments: { type: Boolean, default: true },
    reminders: { type: Boolean, default: true },
    marketing: { type: Boolean, default: false }
  },

  // Security settings
  security: {
    twoFactorEnabled: { type: Boolean, default: false },
    lastPasswordChange: { type: Date },
    loginAlerts: { type: Boolean, default: true },
    sessionTimeout: { type: Number, default: 60 } // minutes
  },

  // Payment settings (mainly for providers)
  paymentSettings: {
    payoutSchedule: { type: String, default: 'weekly', enum: ['daily', 'weekly', 'bi-weekly', 'monthly'] },
    currency: { type: String, default: 'USD' },
    bankAccount: {
      accountNumber: String,
      routingNumber: String,
      accountType: { type: String, enum: ['checking', 'savings'] },
      lastFour: String,
      bankName: String,
      accountHolderName: String
    },
    taxInformation: {
      taxId: String,
      taxFormSubmitted: { type: Boolean, default: false }
    }
  },

  // Provider-specific settings
  providerSettings: {
    autoAcceptJobs: { type: Boolean, default: false },
    maxJobsPerDay: { type: Number, default: 5 },
    serviceRadius: { type: Number, default: 25 }, // miles/km
    workingHours: {
      start: { type: String, default: '09:00' },
      end: { type: String, default: '17:00' }
    },
    vacationMode: { type: Boolean, default: false }
  },

  // Customer-specific settings
  customerSettings: {
    preferredProviders: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }],
    autoBook: { type: Boolean, default: false },
    budgetPreferences: {
      min: { type: Number, default: 0 },
      max: { type: Number, default: 1000 }
    }
  },

  // ==================== EXISTING FIELDS ====================
  
  hasSubmittedVerification: {
    type: Boolean,
    default: false
  },
  responseTime: {
    type: String,
    default: 'within 1 hour'
  },
  reviewCount: {
    type: Number,
    default: 0
  },
  completedJobs: {
    type: Number,
    default: 0
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isTopRated: {
    type: Boolean,
    default: false
  },
  rating: {
    type: Number,
    default: 4.5,
    min: 0,
    max: 5
  },
  address: { type: String, trim: true },
  city: { type: String, trim: true },
  state: { type: String, trim: true },
  country: { type: String, trim: true },
  locationData: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number],
      default: [0, 0]
    },
    formattedAddress: String
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
  profileImage: {
    type: String,
    default: ''
  },
  profileImageFull: {
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
  activeClients: {
    type: Number,
    default: 0
  },
  
  // Temporary fields for demo data
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
  }],

  stripeCustomerId: {
    type: String,
    sparse: true
  },
  
  // For providers
  stripeAccountId: {
    type: String,
    sparse: true
  },
  
  bankAccount: {
    accountHolderName: String,
    accountNumber: String,
    routingNumber: String,
    bankName: String,
    isVerified: { type: Boolean, default: false }
  },
  
  // Payment preferences
  paymentPreferences: {
    payoutSchedule: {
      type: String,
      enum: ['daily', 'weekly', 'monthly', 'manual'],
      default: 'weekly'
    },
    autoPayout: { type: Boolean, default: true }
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
    'Hair Stylist',
    'Veterinary Services',
    'Tailoring',
    'Shoe Repair',
    'Engineering Services',
    'Mechanical Services',
    'Car Washing',
    'Carpentry',
    'Barber',
    'Cook/Chef',
    'Nanny',
    'Laundry Services',
    'Security Services',
    'CCTV Installer',
    'Solar Panel Technician',
    'Inverter Installation',
    'IT Support',
    'Interior Design',
    'TV Repair',
    'Welder',
    'Spa/Massage Therapist',

    // ✅ Newly-added (NOT duplicates)
    'AC Repair',
    'Generator Repair',
    'Tiling',
    'Masonry',
    'Pest Control',
    'Auto Mechanic',
    'Panel Beater',
    'Auto Electrician',
    'Vulcanizer',
    'Nail Technician',
    'Massage Therapist',
    'Gardener',

    'Other'
  ]
}],
  hourlyRate: {
    type: Number,
    default: null
  },
  Rate: {
    type: Number,
    default: null
  }
}, {
  timestamps: true
});

// Index for better query performance
userSchema.index({ email: 1 });
userSchema.index({ emailVerificationToken: 1 });
userSchema.index({ passwordResetToken: 1 });
userSchema.index({ city: 1, state: 1, country: 1 });
userSchema.index({ 'identityVerification.nin': 1 }, { 
  unique: true, 
  sparse: true 
});

// Add middleware to handle backward compatibility
userSchema.pre('save', function(next) {
  // Sync notification settings for backward compatibility
  if (this.isModified('notificationSettings')) {
    const ns = this.notificationSettings;
    
    // Sync old fields with new fields
    if (ns.email !== undefined) {
      ns.emailNotifications = ns.email;
    }
    if (ns.sms !== undefined) {
      ns.smsNotifications = ns.sms;
    }
    if (ns.reminders !== undefined) {
      ns.bookingReminders = ns.reminders;
    }
    if (ns.marketing !== undefined) {
      ns.marketingEmails = ns.marketing;
    }
    if (ns.messages !== undefined) {
      ns.providerMessages = ns.messages;
    }
  }
  
  next();
});

// Instance method to get unified settings
userSchema.methods.getSettings = function() {
  const isProvider = this.userType === 'provider' || this.userType === 'both';
  
  return {
    general: {
      language: this.preferences?.language || 'en-US',
      timeZone: this.preferences?.timeZone || 'America/New_York',
      currency: this.preferences?.currency || 'USD',
      theme: this.preferences?.theme || 'light'
    },
    notifications: {
      // Use new structure, fall back to old structure
      email: this.notificationSettings?.email ?? this.notificationSettings?.emailNotifications ?? true,
      push: this.notificationSettings?.push ?? true,
      sms: this.notificationSettings?.sms ?? this.notificationSettings?.smsNotifications ?? false,
      newJobs: this.notificationSettings?.newJobs ?? true,
      messages: this.notificationSettings?.messages ?? this.notificationSettings?.providerMessages ?? true,
      payments: this.notificationSettings?.payments ?? true,
      reminders: this.notificationSettings?.reminders ?? this.notificationSettings?.bookingReminders ?? true,
      marketing: this.notificationSettings?.marketing ?? this.notificationSettings?.marketingEmails ?? false
    },
    security: this.security || {
      twoFactorEnabled: false,
      lastPasswordChange: null,
      loginAlerts: true,
      sessionTimeout: 60
    },
    account: {
      name: this.name,
      email: this.email,
      phoneNumber: this.phoneNumber || '',
      address: this.address || '',
      city: this.city || '',
      state: this.state || '',
      country: this.country || '',
      profileImage: this.profileImage || this.profilePicture || ''
    },
    payment: this.paymentSettings || {
      payoutSchedule: 'weekly',
      currency: 'USD',
      bankAccount: null
    },
    // Role-specific settings
    ...(isProvider && { provider: this.providerSettings }),
    ...(!isProvider && { customer: this.customerSettings })
  };
};

// Static method to update settings safely
userSchema.statics.updateUserSettings = async function(userId, updates) {
  const user = await this.findById(userId);
  if (!user) throw new Error('User not found');

  const { general, notifications, security, account, payment, provider, customer } = updates;

  // Update general preferences
  if (general) {
    user.preferences = { ...user.preferences, ...general };
  }

  // Update notifications
  if (notifications) {
    user.notificationSettings = { ...user.notificationSettings, ...notifications };
  }

  // Update security
  if (security) {
    user.security = { ...user.security, ...security };
  }

  // Update account info
  if (account) {
    Object.keys(account).forEach(key => {
      if (user[key] !== undefined) {
        user[key] = account[key];
      }
    });
  }

  // Update payment settings
  if (payment) {
    user.paymentSettings = { ...user.paymentSettings, ...payment };
  }

  // Update role-specific settings
  if (provider && (user.userType === 'provider' || user.userType === 'both')) {
    user.providerSettings = { ...user.providerSettings, ...provider };
  }

  if (customer && (user.userType === 'customer' || user.userType === 'both')) {
    user.customerSettings = { ...user.customerSettings, ...customer };
  }

  await user.save();
  return user.getSettings();
};

const User = mongoose.model('User', userSchema);

export default User;