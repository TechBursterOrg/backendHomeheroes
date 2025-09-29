// routes/jobs.js
import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import JobController from '../controllers/jobController.js';

const router = express.Router();

// Apply for a job
router.post('/:id/apply', authenticateToken, JobController.applyForJob);

// Get provider's jobs
router.get('/provider/my-jobs', authenticateToken, JobController.getProviderJobs);

export default router;