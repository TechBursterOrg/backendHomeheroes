import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import VerificationController from '../controllers/verificationController.js';

const router = express.Router();

// NIN verification with Dojah
router.post('/verify-nin', authenticateToken, VerificationController.verifyNINWithDojah);

// NIN + Selfie verification with Dojah
router.post('/verify-nin-selfie', authenticateToken, VerificationController.verifyNINWithSelfie);

export default router;