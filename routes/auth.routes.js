import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';
import path from 'path';
import User from '../models/User.js';
import VerificationToken from '../models/VerificationToken.js';
import smsService from '../utils/smsService.js';


const router = express.Router();

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
}

// Validation middleware
const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  body('userType')
    .optional()
    .isIn(['customer', 'provider'])
    .withMessage('User type must be either customer or provider')
];

const signupValidation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
  body('userType')
    .isIn(['customer', 'provider', 'both'])
    .withMessage('User type must be customer, provider, or both'),
  body('country')
    .isIn(['UK', 'USA', 'CANADA', 'NIGERIA'])
    .withMessage('Please select a valid country')
];

// Auth routes
router.post('/signup', signupValidation, async (req, res) => {
  try {
    console.log('🔧 Signup request received:', {
      email: req.body.email,
      userType: req.body.userType,
      timestamp: new Date().toISOString()
    });

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('❌ Validation errors:', errors.array());
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, email, password, userType, country } = req.body;

    // Check for existing user
    const existingUser = await User.findOne({ email: email.toLowerCase() }).catch(dbError => {
      console.error('❌ Database error checking existing user:', dbError);
      throw new Error('Database connection error');
    });

    if (existingUser) {
      console.log('⚠️ User already exists:', email);
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.'
      });
    }

    // Hash password
    let hashedPassword;
    try {
      const saltRounds = 10;
      hashedPassword = await bcrypt.hash(password, saltRounds);
    } catch (hashError) {
      console.error('❌ Password hashing error:', hashError);
      return res.status(500).json({
        success: false,
        message: 'Error processing password'
      });
    }

    const verificationToken = generateVerificationToken();

    const newUser = new User({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      userType,
      country,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });

    // Save user
    const savedUser = await newUser.save().catch(saveError => {
      console.error('❌ User save error:', saveError);
      if (saveError.code === 11000) {
        return res.status(409).json({
          success: false,
          message: 'An account with this email already exists.'
        });
      }
      throw new Error('Failed to create user account');
    });

    console.log('✅ User created successfully:', savedUser._id);

    // ✅ CORRECT PLACEMENT: Email sending code should be HERE
    try {
      console.log('📧 Attempting to send verification email...');
      console.log('🔧 Email config:', {
        from: process.env.EMAIL_USER,
        to: savedUser.email,
        frontendUrl: process.env.FRONTEND_URL,
        token: verificationToken
      });

      const emailResult = await sendVerificationEmail(savedUser, verificationToken);
      console.log('✅ Email sending result:', emailResult);

      if (emailResult.simulated) {
        console.log('⚠️ Email simulation mode - no actual email sent');
        console.log('🔗 Verification URL would be:', `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`);
      } else {
        console.log('📨 Actual email sent with ID:', emailResult.messageId);
      }
    } catch (emailError) {
      console.error('❌ Email sending failed:', emailError);
      // Don't fail the signup if email fails
    }

    res.status(201).json({
      success: true,
      message: 'Account created successfully! Please check your email to verify your account.',
      data: {
        user: {
          id: savedUser._id,
          name: savedUser.name,
          email: savedUser.email,
          userType: savedUser.userType,
          country: savedUser.country,
          isEmailVerified: savedUser.isEmailVerified,
          createdAt: savedUser.createdAt
        },
        requiresVerification: true
      }
    });

  } catch (error) {
    console.error('💥 SIGNUP CRITICAL ERROR:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});




router.post('/login', loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password, userType } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password. Please try again.'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated. Please contact support.'
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password. Please try again.'
      });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email address before logging in.',
        requiresVerification: true,
        email: user.email
      });
    }

    if (userType) {
      const requestedUserType = userType.toLowerCase();
      const userAccountType = user.userType.toLowerCase();

      if (userAccountType === 'customer' && requestedUserType === 'provider') {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Your account is registered as a customer only. Please login as a customer or upgrade your account to access provider features.',
          allowedUserType: 'customer',
          requestedUserType: requestedUserType
        });
      }

      if (userAccountType === 'provider' && requestedUserType === 'customer') {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Your account is registered as a service provider only. Please login as a provider or contact support to modify your account type.',
          allowedUserType: 'provider',
          requestedUserType: requestedUserType
        });
      }

      if (userAccountType === 'both') {
        if (requestedUserType !== 'customer' && requestedUserType !== 'provider') {
          return res.status(400).json({
            success: false,
            message: 'Invalid login type. Please specify either "customer" or "provider".',
            allowedUserTypes: ['customer', 'provider']
          });
        }
      }

      const validUserTypes = ['customer', 'provider'];
      if (!validUserTypes.includes(requestedUserType)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid user type specified.',
          allowedUserTypes: validUserTypes
        });
      }
    }

    user.lastLogin = new Date();
    await user.save();

    const tokenUserType = userType && user.userType === 'both' 
      ? userType.toLowerCase()
      : user.userType;

    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email, 
        userType: tokenUserType,
        actualUserType: user.userType, 
        isEmailVerified: user.isEmailVerified
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    let redirectTo = '/dashboard';
    if (userType) {
      redirectTo = userType.toLowerCase() === 'provider' 
        ? '/provider/dashboard' 
        : '/customer/dashboard';
    } else {
      redirectTo = user.userType === 'provider' || user.userType === 'both' 
        ? '/provider/dashboard' 
        : '/customer/dashboard';
    }

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          userType: tokenUserType, 
          actualUserType: user.userType, 
          country: user.country,
          profilePicture: user.profilePicture,
          isEmailVerified: user.isEmailVerified,
          lastLogin: user.lastLogin,
          services: user.services,
          hourlyRate: user.hourlyRate
        },
        token,
        redirectTo,
        canSwitchRoles: user.userType === 'both' 
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

router.post('/verify-email', async (req, res) => {
  
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Verification token is required'
      });
    }

    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationExpires = null;
    await user.save();

    const authToken = jwt.sign(
      { 
        id: user._id, 
        email: user.email, 
        userType: user.userType,
        isEmailVerified: user.isEmailVerified
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Email verified successfully!',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          userType: user.userType,
          country: user.country,
          isEmailVerified: user.isEmailVerified
        },
        token: authToken,
        redirectTo: user.userType === 'provider' || user.userType === 'both' 
          ? '/provider/dashboard' 
          : '/customer'
      }
    });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

router.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address is required'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified'
      });
    }

    const verificationToken = generateVerificationToken();
    user.emailVerificationToken = verificationToken;
    user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await user.save();

    try {
      await sendVerificationEmail(user, verificationToken);
      
      res.json({
        success: true,
        message: 'Verification email sent successfully! Please check your inbox.'
      });
    } catch (emailError) {
      console.error('Email sending failed:', emailError);
      res.status(500).json({
        success: false,
        message: 'Failed to send verification email. Please try again later.'
      });
    }

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

router.post('/send-verification', async (req, res) => {
  try {
    const { phoneNumber, country } = req.body;

    if (!phoneNumber || !country) {
      return res.status(400).json({
        success: false,
        message: 'Phone number and country are required'
      });
    }

    // Validate phone number format based on country
    const countryData = {
      NIGERIA: { pattern: /^[0-9]{11}$/, code: '+234', name: 'Nigeria' },
      UK: { pattern: /^[0-9]{10}$/, code: '+44', name: 'United Kingdom' },
      USA: { pattern: /^[0-9]{10}$/, code: '+1', name: 'United States' },
      CANADA: { pattern: /^[0-9]{10}$/, code: '+1', name: 'Canada' }
    };

    const countryInfo = countryData[country];
    if (!countryInfo) {
      return res.status(400).json({
        success: false,
        message: 'Invalid country selected'
      });
    }

    // Clean phone number (remove any non-digit characters)
    const cleanPhoneNumber = phoneNumber.replace(/\D/g, '');
    
    if (!countryInfo.pattern.test(cleanPhoneNumber)) {
      return res.status(400).json({
        success: false,
        message: `Invalid phone number format for ${countryInfo.name}. Expected ${countryInfo.pattern.toString().match(/\d+/)[0]} digits.`
      });
    }

    // Check if phone number is already registered and verified
    const existingUser = await User.findOne({ 
      phoneNumber: cleanPhoneNumber,
      country: country,
      isPhoneVerified: true
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'This phone number is already registered and verified'
      });
    }

    const token = Math.floor(100000 + Math.random() * 900000).toString();

    // Store verification token in database
    const verificationToken = await VerificationToken.findOneAndUpdate(
      { phoneNumber: cleanPhoneNumber, country },
      {
        token,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
        verified: false
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // Format phone number with country code
    const fullPhoneNumber = smsService.formatPhoneNumberWithCountryCode(cleanPhoneNumber, countryInfo.code);
    
    // Send SMS
    const smsResult = await smsService.sendVerificationCode(fullPhoneNumber, token);

    console.log(`📱 Verification token for ${fullPhoneNumber}: ${token}`);

    const response = {
      success: true,
      message: `Verification code sent to ${fullPhoneNumber}`,
      data: {
        provider: smsResult.provider
      }
    };

    // Include debug token in development
    if (process.env.NODE_ENV === 'development') {
      response.data.debugToken = token;
    }

    res.json(response);

  } catch (error) {
    console.error('❌ Send verification error:', error);
    
    let errorMessage = 'Failed to send verification code';
    if (error.message.includes('Invalid phone number')) {
      errorMessage = 'Invalid phone number format';
    } else if (error.message.includes('Twilio')) {
      errorMessage = 'SMS service temporarily unavailable. Please try again.';
    }

    res.status(500).json({
      success: false,
      message: errorMessage
    });
  }
});

router.post('/verify-phone', async (req, res) => {
  try {
    const { phoneNumber, country, token } = req.body;

    if (!phoneNumber || !country || !token) {
      return res.status(400).json({
        success: false,
        message: 'Phone number, country, and token are required'
      });
    }

    // Find the verification token
    const verification = await VerificationToken.findOne({
      phoneNumber,
      country,
      token,
      expiresAt: { $gt: new Date() }
    });

    if (!verification) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification code'
      });
    }

    // Mark as verified
    verification.verified = true;
    verification.verifiedAt = new Date();
    await verification.save();

    res.json({
      success: true,
      message: 'Phone number verified successfully'
    });

  } catch (error) {
    console.error('Verify phone error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify phone number'
    });
  }
});


const generateVerificationToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// SIMPLIFIED email sending function (define it locally)
const sendVerificationEmail = async (user, verificationToken) => {
  try {
    console.log('📧 [SIMPLIFIED] Would send email to:', user.email);
    console.log('📧 [SIMPLIFIED] Token:', verificationToken);
    
    // For now, just log it instead of actually sending
    // We'll fix email sending after we get signup working
    return { success: true, simulated: true };
  } catch (error) {
    console.error('Email error:', error);
    return { success: false, error: error.message };
  }
};




// router.post('/signup', async (req, res) => {
//   console.log('🔧 Signup request received:', {
//     email: req.body.email,
//     userType: req.body.userType,
//     timestamp: new Date().toISOString()
//   });

//   try {
//     const { name, email, password, userType, country, confirmPassword } = req.body;

//     const verification = await VerificationToken.findOne({
//       phoneNumber,
//       country,
//       verified: true
//     });

//     if (!verification) {
//       return res.status(400).json({
//         success: false,
//         message: 'Phone number must be verified before signup'
//       });
//     }

//     // Validate required fields
//     if (!name || !email || !password || !userType) {
//       return res.status(400).json({
//         success: false,
//         message: 'All fields are required: name, email, password, userType'
//       });
//     }

//     // Check password confirmation if provided
//     if (confirmPassword && password !== confirmPassword) {
//       return res.status(400).json({
//         success: false,
//         message: 'Passwords do not match'
//       });
//     }

//     // Validate email format
//     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//     if (!emailRegex.test(email)) {
//       return res.status(400).json({
//         success: false,
//         message: 'Please provide a valid email address'
//       });
//     }

//     // Check if user exists
//     const existingUser = await User.findOne({ email: email.toLowerCase() });
//     if (existingUser) {
//       return res.status(400).json({
//         success: false,
//         message: 'User already exists with this email. Please try logging in.'
//       });
//     }

//     // Hash password
//     const hashedPassword = await bcrypt.hash(password, 12);

//     // Generate verification token (using the locally defined function)
//     const emailVerificationToken = generateVerificationToken();
//     const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

//     // Create user
//     const user = new User({
//       name: name.trim(),
//       email: email.toLowerCase(),
//       password: hashedPassword,
//       userType,
//       country: country || 'NIGERIA',
//       emailVerificationToken,
//       emailVerificationExpires,
//       isEmailVerified: false
//     });

//     await user.save();
//     console.log('✅ User created successfully:', user._id);

//     // Try to send verification email (but don't fail if it doesn't work)
//     const emailResult = await sendVerificationEmail(user, emailVerificationToken);

//     if (emailResult.success) {
//       res.status(201).json({
//         success: true,
//         message: 'Account created successfully! Please check your email for verification.',
//         data: {
//           user: {
//             id: user._id,
//             name: user.name,
//             email: user.email,
//             userType: user.userType
//           },
//           requiresVerification: true
//         }
//       });
//     } else {
//       // User created but email failed

//           await VerificationToken.deleteOne({ phoneNumber, country });

//       res.status(201).json({
//         success: true,
//         message: 'Account created! You can log in now.',
//         data: {
//           user: {
//             id: user._id,
//             name: user.name,
//             email: user.email,
//             userType: user.userType
//           },
//           requiresVerification: false
//         }
//       });
//     }

//   } catch (error) {
//     console.error('💥 SIGNUP CRITICAL ERROR:', error);
//     console.error('Error stack:', error.stack);
    
//     res.status(500).json({
//       success: false,
//       message: 'Internal server error during signup',
//       error: process.env.NODE_ENV === 'production' 
//         ? 'Please try again later' 
//         : error.message
//     });
//   }
// });



// Add a test endpoint to verify the route is working
router.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Auth routes are working!',
    timestamp: new Date().toISOString()
  });
});



router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address is required'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });
    }

    const resetToken = generateVerificationToken();
    user.passwordResetToken = resetToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();

    // Email sending logic would go here (similar to your existing code)

    res.json({
      success: true,
      message: 'If an account with that email exists, a password reset link has been sent.'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Token and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long'
      });
    }

    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await user.save();

    res.json({
      success: true,
      message: 'Password reset successfully! You can now login with your new password.'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

// FIXED: Get profile endpoint
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // FIXED: Map both profilePicture and profileImage fields
    const userResponse = {
      ...user.toObject(),
      profileImage: user.profileImage || user.profilePicture || '',
      profilePicture: user.profilePicture || user.profileImage || ''
    };

    res.json({
      success: true,
      data: { user: userResponse }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user profile'
    });
  }
});

// FIXED: Update profile endpoint
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phoneNumber, address, services, hourlyRate, experience } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;
    if (address !== undefined) updateData.address = address;
    if (services) updateData.services = services;
    if (hourlyRate !== undefined) updateData.hourlyRate = hourlyRate;
    if (experience !== undefined) updateData.experience = experience;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: updatedUser }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// NEW: Profile image upload endpoint
router.post('/profile/image', authenticateToken, async (req, res) => {
  try {
    if (!req.files || !req.files.profileImage) {
      return res.status(400).json({
        success: false,
        message: 'No image file provided'
      });
    }

    const profileImage = req.files.profileImage;
    
    // Validate file type
    if (!profileImage.mimetype.startsWith('image/')) {
      return res.status(400).json({
        success: false,
        message: 'Please upload a valid image file'
      });
    }

    // Validate file size (5MB limit)
    if (profileImage.size > 5 * 1024 * 1024) {
      return res.status(400).json({
        success: false,
        message: 'Image size should be less than 5MB'
      });
    }

    // Generate unique filename
    const fileExtension = profileImage.name.split('.').pop();
    const fileName = `profile-${req.user.id}-${Date.now()}.${fileExtension}`;
    const uploadDir = path.join(process.cwd(), 'uploads', 'profiles');
    const uploadPath = path.join(uploadDir, fileName);

    // Create uploads directory if it doesn't exist
    const fs = await import('fs');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    // Move the file to the upload directory
    await profileImage.mv(uploadPath);

    // Update user profile with image path
    const imageUrl = `/uploads/profiles/${fileName}`;
    
    // FIXED: Update both profileImage and profilePicture fields for compatibility
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id, 
      { 
        profileImage: imageUrl,
        profilePicture: imageUrl // Keep both fields in sync
      }, 
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Profile image uploaded successfully',
      data: { 
        imageUrl,
        user: updatedUser
      }
    });
  } catch (error) {
    console.error('Profile image upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload profile image',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

router.post('/logout', (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

export default router;