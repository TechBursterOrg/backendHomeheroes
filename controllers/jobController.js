// controllers/jobController.js or add to your existing controller
import ServiceRequest from '../models/ServiceRequest.js';
import User from '../models/User.js';
import Booking from '../models/Booking.js';

const JobController = {
  async applyForJob(req, res) {
    try {
      const { jobId } = req.params;
      const { message } = req.body;
      const providerId = req.user.id;

      console.log('🔧 Applying for job:', { jobId, providerId });

      // Find the job
      const job = await ServiceRequest.findById(jobId);
      
      if (!job) {
        return res.status(404).json({
          success: false,
          message: 'Job not found'
        });
      }

      // Check if job is still available
      if (job.status !== 'pending') {
        return res.status(400).json({
          success: false,
          message: 'This job is no longer available'
        });
      }

      // Check if provider has already applied
      if (job.applications && job.applications.includes(providerId)) {
        return res.status(400).json({
          success: false,
          message: 'You have already applied for this job'
        });
      }

      // Get provider details
      const provider = await User.findById(providerId);
      if (!provider) {
        return res.status(404).json({
          success: false,
          message: 'Provider not found'
        });
      }

      // Update job with provider application
      job.providerId = providerId;
      job.status = 'accepted';
      job.acceptedAt = new Date();
      
      // Add to applications array if it exists
      if (job.applications) {
        job.applications.push(providerId);
      }

      await job.save();

      // Create a booking record
      const booking = new Booking({
        providerId: providerId,
        providerName: provider.name,
        providerEmail: provider.email,
        customerId: job.customerId,
        customerName: job.contactInfo?.name || 'Customer',
        customerEmail: job.contactInfo?.email || '',
        customerPhone: job.contactInfo?.phone || '',
        serviceType: job.serviceType,
        description: job.description,
        location: job.location,
        timeframe: job.timeframe,
        budget: job.budget,
        specialRequests: message || 'I would like to help with this service request.',
        bookingType: 'job_application',
        status: 'accepted',
        requestedAt: job.createdAt,
        acceptedAt: new Date()
      });

      await booking.save();

      // Populate the updated job for response
      await job.populate('customerId', 'name email phoneNumber profileImage');
      await job.populate('providerId', 'name email phoneNumber profileImage');

      console.log('✅ Job application successful:', {
        jobId: job._id,
        providerId: providerId,
        customerId: job.customerId
      });

      res.json({
        success: true,
        message: 'Successfully applied for the job!',
        data: {
          job: job,
          booking: booking
        }
      });

    } catch (error) {
      console.error('❌ Job application error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to apply for job',
        error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
      });
    }
  },

  async getProviderJobs(req, res) {
    try {
      const providerId = req.user.id;
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const status = req.query.status;

      let filter = { providerId: providerId };
      
      if (status && status !== 'all') {
        filter.status = status;
      }

      const options = {
        page,
        limit,
        sort: { createdAt: -1 },
        populate: { 
          path: 'customerId', 
          select: 'name email phoneNumber profileImage rating reviewCount' 
        }
      };

      const result = await ServiceRequest.paginate(filter, options);

      res.json({
        success: true,
        data: {
          jobs: result.docs,
          totalDocs: result.totalDocs,
          limit: result.limit,
          totalPages: result.totalPages,
          page: result.page,
          pagingCounter: result.pagingCounter,
          hasPrevPage: result.hasPrevPage,
          hasNextPage: result.hasNextPage,
          prevPage: result.prevPage,
          nextPage: result.nextPage
        }
      });
    } catch (error) {
      console.error('Get provider jobs error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to fetch provider jobs'
      });
    }
  }
};

export default JobController;