import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
// Use named imports instead of default import
import { applyForJob, getJobs, getProviderJobs } from '../controllers/jobController.js';

const router = express.Router();

// Apply for a job
router.post('/:id/apply', authenticateToken, applyForJob);

// Get all jobs (for provider job board)
router.get('/', authenticateToken, getJobs);

// Get provider's jobs
router.get('/provider/my-jobs', authenticateToken, getProviderJobs);

export default router;