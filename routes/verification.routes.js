import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import VerificationController from '../controllers/verificationController.js';

const router = express.Router();



// Send verification email
router.post('/send-verification', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    console.log('📧 Sending verification to:', email);

    // Generate verification token
    const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();
    
    const emailResult = await sendVerificationEmail(
      { email, name: 'User' },
      verificationToken
    );

    if (emailResult.success) {
      res.json({
        success: true,
        message: 'Verification email sent successfully',
        // Only return debug token in development
        ...(process.env.NODE_ENV === 'development' && { 
          data: { debugToken: verificationToken } 
        })
      });
    } else {
      res.status(500).json({
        success: false,
        message: 'Failed to send verification email',
        error: emailResult.error
      });
    }

  } catch (error) {
    console.error('Send verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send verification email'
    });
  }
});

// NIN verification with Dojah
router.post('/verify-nin', authenticateToken, VerificationController.verifyNINWithDojah);

// NIN + Selfie verification with Dojah
router.post('/verify-nin-selfie', authenticateToken, VerificationController.verifyNINWithSelfie);

export default router;