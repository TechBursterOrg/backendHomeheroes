import ServiceRequest from '../models/ServiceRequest.js';
import User from '../models/User.js';
import Notification from '../models/Notification.js';

// Use named exports instead of default export
export const applyForJob = async (req, res) => {
  try {
    const jobId = req.params.id;
    const providerId = req.user.id;

    console.log('🔧 Applying for job:', jobId, 'by provider:', providerId);

    const job = await ServiceRequest.findById(jobId);
    
    if (!job) {
      console.log('❌ Job not found:', jobId);
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }
    
    if (job.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Job is no longer available'
      });
    }

    // Check if user has verified their identity
    const user = await User.findById(providerId);
    if (!user.identityVerification?.isNinVerified) {
      return res.status(403).json({
        success: false,
        message: 'Identity verification required before applying for jobs. Please verify your NIN first.'
      });
    }

    // Update job status and assign provider
    job.providerId = providerId;
    job.status = 'accepted';
    job.acceptedAt = new Date();
    
    await job.save();
    
    // Populate the updated job
    await job.populate('customerId', 'name email phoneNumber');
    await job.populate('providerId', 'name email phoneNumber profileImage');

    // Create notifications
    await Notification.createNotification({
      userId: job.customerId,
      type: 'job_applied',
      title: 'New Job Application',
      message: `A provider has applied for your ${job.serviceType} job`,
      relatedId: job._id,
      relatedType: 'job',
      roleContext: 'customer',
      priority: 'medium'
    });

    await Notification.createNotification({
      userId: providerId,
      type: 'job_applied',
      title: 'Application Sent',
      message: `You applied for the ${job.serviceType} job`,
      relatedId: job._id,
      relatedType: 'job',
      roleContext: 'provider',
      priority: 'medium'
    });

    console.log('✅ Successfully applied for job:', jobId);
    
    res.json({
      success: true,
      message: 'Successfully applied for the job',
      data: job
    });

  } catch (error) {
    console.error('❌ Apply for job error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to apply for job'
    });
  }
};

export const getJobs = async (req, res) => {
  try {
    const {
      status = 'pending',
      serviceType = '',
      location = '',
      minBudget = '',
      maxBudget = '',
      urgency = '',
      sortBy = 'createdAt',
      sortOrder = 'desc',
      page = 1,
      limit = 10
    } = req.query;

    console.log('📋 Jobs query filter:', { status });

    // Build filter object
    const filter = { status };
    
    // Only show public jobs or jobs without isPublic field (backward compatibility)
    filter.$or = [
      { isPublic: true },
      { isPublic: { $exists: false } }
    ];

    if (serviceType) {
      filter.serviceType = { $regex: serviceType, $options: 'i' };
    }
    
    if (location) {
      filter.location = { $regex: location, $options: 'i' };
    }
    
    if (urgency) {
      filter.urgency = urgency;
    }
    
    if (minBudget || maxBudget) {
      filter.budget = {};
      if (minBudget) filter.budget.$gte = parseInt(minBudget);
      if (maxBudget) filter.budget.$lte = parseInt(maxBudget);
    }

    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    console.log('🔍 Querying jobs with status:', status);
    
    const jobs = await ServiceRequest.find(filter)
      .populate('customerId', 'name email phoneNumber rating reviewCount')
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    const totalJobs = await ServiceRequest.countDocuments(filter);

    console.log('✅ Found jobs:', jobs.length, 'of', totalJobs);

    res.json({
      success: true,
      data: {
        jobs,
        totalPages: Math.ceil(totalJobs / parseInt(limit)),
        currentPage: parseInt(page),
        totalJobs
      }
    });

  } catch (error) {
    console.error('❌ Get jobs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch jobs'
    });
  }
};

export const getProviderJobs = async (req, res) => {
  try {
    const providerId = req.user.id;
    const { status, page = 1, limit = 10 } = req.query;

    const filter = { providerId };
    if (status && status !== 'all') {
      filter.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const jobs = await ServiceRequest.find(filter)
      .populate('customerId', 'name email phoneNumber')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalJobs = await ServiceRequest.countDocuments(filter);

    res.json({
      success: true,
      data: {
        jobs,
        totalPages: Math.ceil(totalJobs / parseInt(limit)),
        currentPage: parseInt(page),
        totalJobs
      }
    });

  } catch (error) {
    console.error('Get provider jobs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider jobs'
    });
  }
};