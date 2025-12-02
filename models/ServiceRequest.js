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
  budgetAmount: {
    type: Number,
    default: 0
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
    enum: ['pending', 'accepted', 'awaiting_hero', 'in_progress', 'completed', 'cancelled', 'payment_pending', 'applied'],
    default: 'pending'
  },
  acceptedAt: {
    type: Date
  },
  startedAt: {
    type: Date
  },
  completedAt: {
    type: Date
  },
  
  // Payment and Escrow Fields
  payment: {
    processor: {
      type: String,
      enum: ['paystack', 'stripe', null],
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
      enum: ['pending', 'requires_payment_method', 'held', 'released', 'refunded', 'failed'],
      default: 'pending'
    },
    heldAt: Date,
    releasedAt: Date,
    refundedAt: Date,
    authorizationUrl: String,
    clientSecret: String,
    retryCount: {
      type: Number,
      default: 0
    },
    lastRetryAt: Date,
    initiatedAt: Date
  },
  
  // Refund eligibility
  canRefund: {
    type: Boolean,
    default: true
  },
  refundRequested: {
    type: Boolean,
    default: false
  },
  refundReason: String,
  
  // Proposals system - FIXED with proper _id generation
  proposals: [{
    _id: {
      type: mongoose.Schema.Types.ObjectId,
      default: () => new mongoose.Types.ObjectId()
    },
    providerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    proposalText: {
      type: String,
      required: true,
      trim: true
    },
    proposedAmount: {
      type: Number,
      required: true
    },
    estimatedDuration: {
      type: String,
      required: true
    },
    proposedSchedule: String,
    status: {
      type: String,
      enum: ['pending', 'accepted', 'rejected'],
      default: 'pending'
    },
    submittedAt: {
      type: Date,
      default: Date.now
    },
    acceptedAt: Date,
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  acceptedProposalId: {
    type: mongoose.Schema.Types.ObjectId
  },

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
  },
  
  // Auto-refund timer
  autoRefundAt: Date,

  // Payment history for tracking
  paymentHistory: [{
    action: {
      type: String,
      enum: ['payment_initiated', 'payment_retry', 'payment_held', 'payment_released', 'payment_refunded']
    },
    processor: String,
    paymentIntentId: String,
    amount: Number,
    currency: String,
    status: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    isRetry: {
      type: Boolean,
      default: false
    },
    originalReference: String,
    retryCount: Number
  }]
}, {
  timestamps: true
});

// Virtual for getting the accepted proposal
serviceRequestSchema.virtual('acceptedProposal').get(function() {
  if (!this.acceptedProposalId || !this.proposals) return null;
  return this.proposals.id(this.acceptedProposalId);
});

// Method to add a proposal
serviceRequestSchema.methods.addProposal = function(proposalData) {
  const newProposal = {
    providerId: proposalData.providerId,
    proposalText: proposalData.proposalText || `I can help with your ${this.serviceType} service`,
    proposedAmount: proposalData.proposedAmount || this.budgetAmount || 0,
    estimatedDuration: proposalData.estimatedDuration || 'Not specified',
    proposedSchedule: proposalData.proposedSchedule,
    status: 'pending'
  };
  
  if (!this.proposals) {
    this.proposals = [];
  }
  
  this.proposals.push(newProposal);
  return this.save();
};

// Method to accept a proposal
serviceRequestSchema.methods.acceptProposal = function(proposalId) {
  if (!this.proposals || this.proposals.length === 0) {
    throw new Error('No proposals found');
  }

  const proposal = this.proposals.id(proposalId);
  if (!proposal) {
    throw new Error('Proposal not found');
  }

  if (proposal.status === 'accepted') {
    throw new Error('Proposal already accepted');
  }

  // Update the accepted proposal
  proposal.status = 'accepted';
  proposal.acceptedAt = new Date();

  // Update service request
  this.status = 'accepted';
  this.providerId = proposal.providerId;
  this.acceptedProposalId = proposalId;
  this.acceptedAt = new Date();

  // Disable refunds once a proposal is accepted
  this.canRefund = false;

  // Reject all other pending proposals
  this.proposals.forEach(p => {
    if (p._id.toString() !== proposalId && p.status === 'pending') {
      p.status = 'rejected';
    }
  });

  return this.save();
};

// Method to get proposals with provider details
serviceRequestSchema.methods.getProposalsWithProviders = async function() {
  await this.populate('proposals.providerId', 'name email profileImage phoneNumber services rating reviewCount completedJobs');
  return this.proposals;
};

// Method to check if user has already applied
serviceRequestSchema.methods.hasUserApplied = function(userId) {
  if (!this.proposals || this.proposals.length === 0) return false;
  return this.proposals.some(proposal => 
    proposal.providerId.toString() === userId && proposal.status === 'pending'
  );
};

// Static method to find by ID with populated data
serviceRequestSchema.statics.findByIdWithDetails = function(id) {
  return this.findById(id)
    .populate('customerId', 'name email phoneNumber profileImage rating reviewCount')
    .populate('providerId', 'name email phoneNumber profileImage services rating reviewCount completedJobs')
    .populate('proposals.providerId', 'name email profileImage phoneNumber services rating reviewCount completedJobs');
};

// Static method to find customer requests
serviceRequestSchema.statics.findByCustomerId = function(customerId, options = {}) {
  const { status, page = 1, limit = 20 } = options;
  
  let filter = { customerId };
  if (status && status !== 'all') {
    filter.status = status;
  }

  return this.paginate(filter, {
    page,
    limit,
    sort: { createdAt: -1 },
    populate: [
      { path: 'customerId', select: 'name email phoneNumber profileImage rating reviewCount' },
      { path: 'providerId', select: 'name email phoneNumber profileImage rating reviewCount' },
      { path: 'proposals.providerId', select: 'name email profileImage rating reviewCount' }
    ]
  });
};

// Static method to find available requests for providers
serviceRequestSchema.statics.findAvailableRequests = function(options = {}) {
  const { serviceType, category, location, page = 1, limit = 20 } = options;
  
  let filter = { 
    status: 'pending',
    isPublic: true
  };
  
  if (serviceType && serviceType !== 'all') {
    filter.serviceType = { $regex: serviceType, $options: 'i' };
  }
  
  if (category && category !== 'all') {
    filter.category = category;
  }

  if (location && location !== 'all') {
    filter.location = { $regex: location, $options: 'i' };
  }

  return this.paginate(filter, {
    page,
    limit,
    sort: { createdAt: -1 },
    populate: { 
      path: 'customerId', 
      select: 'name email phoneNumber profileImage rating reviewCount' 
    }
  });
};

// Static method to find jobs where user has applied
serviceRequestSchema.statics.findAppliedJobs = function(providerId, options = {}) {
  const { page = 1, limit = 20 } = options;
  
  const filter = {
    'proposals.providerId': providerId
  };

  return this.paginate(filter, {
    page,
    limit,
    sort: { createdAt: -1 },
    populate: [
      { path: 'customerId', select: 'name email phoneNumber profileImage rating reviewCount' },
      { path: 'proposals.providerId', select: 'name email profileImage' }
    ]
  });
};

// Static method to find accepted jobs for provider
serviceRequestSchema.statics.findAcceptedJobs = function(providerId, options = {}) {
  const { page = 1, limit = 20 } = options;
  
  const filter = {
    providerId: providerId,
    status: { $in: ['accepted', 'awaiting_hero', 'in_progress'] }
  };

  return this.paginate(filter, {
    page,
    limit,
    sort: { createdAt: -1 },
    populate: [
      { path: 'customerId', select: 'name email phoneNumber profileImage rating reviewCount' },
      { path: 'providerId', select: 'name email profileImage' }
    ]
  });
};

// Indexes for performance
serviceRequestSchema.index({ location: 'text', serviceType: 'text', description: 'text' });
serviceRequestSchema.index({ status: 1, createdAt: -1 });
serviceRequestSchema.index({ customerId: 1, createdAt: -1 });
serviceRequestSchema.index({ providerId: 1, createdAt: -1 });
serviceRequestSchema.index({ 'payment.status': 1 });
serviceRequestSchema.index({ 'proposals.providerId': 1 });
serviceRequestSchema.index({ acceptedProposalId: 1 });
serviceRequestSchema.index({ 'proposals.status': 1 });
serviceRequestSchema.index({ urgency: 1, createdAt: -1 });
serviceRequestSchema.index({ category: 1, status: 1 });

// Transform output
serviceRequestSchema.set('toJSON', {
  virtuals: true,
  transform: function(doc, ret) {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    return ret;
  }
});

serviceRequestSchema.set('toObject', {
  virtuals: true,
  transform: function(doc, ret) {
    ret.id = ret._id;
    delete ret._id;
    delete ret.__v;
    return ret;
  }
});

serviceRequestSchema.plugin(mongoosePaginate);

// Pre-save middleware to update status based on proposals
serviceRequestSchema.pre('save', function(next) {
  // If there are accepted proposals and status is still pending, update to accepted
  if (this.status === 'pending' && this.proposals && this.proposals.length > 0) {
    const hasAcceptedProposal = this.proposals.some(p => p.status === 'accepted');
    if (hasAcceptedProposal) {
      this.status = 'accepted';
    }
  }
  next();
});

export default mongoose.model('ServiceRequest', serviceRequestSchema);