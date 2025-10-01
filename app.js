import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fileUpload from 'express-fileupload';
import fs from 'fs'; // Added missing import
import galleryRoutes from './routes/gallery.routes.js';
import Gallery from './models/Gallery.js';
import multer from 'multer'; // Added for error handling
import { Message } from './models/Message.js';
import { Conversation } from './models/Conversation.js';
import ServiceRequest from './models/ServiceRequest.js';
import Booking from './models/Booking.js';
import nodemailer from 'nodemailer';
import messageRoutes from './routes/messages.routes.js';
import jobRoutes from './routes/jobs.js';
import bcrypt from 'bcryptjs';
import Notification from './models/Notification.js';


// Add to your imports in server.js

// Import models
import User from './models/User.js';
import Job from './models/Jobs.js';
import Review from './models/Review.js';

// Import routes
import authRoutes from './routes/auth.routes.js';
import { initializeEmailTransporter } from './utils/emailService.js';
import verificationRoutes from './routes/verification.routes.js';


// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load the appropriate .env file based on environment
const envFile = process.env.NODE_ENV === 'production' 
  ? 'env.production'  // Match your actual file name
  : '.env';

console.log(`Loading environment from: ${envFile}`);
console.log(`File exists: ${fs.existsSync(path.resolve(__dirname, envFile))}`);

dotenv.config({ path: path.resolve(__dirname, envFile) });

const app = express();
const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/homehero';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Initialize email transporter
console.log('🚀 Starting email service initialization...');
initializeEmailTransporter().then(success => {
  if (success) {
    console.log('✅ Email service initialized successfully');
  } else {
    console.log('⚠️ Email service running in simulation mode');
  }
});



// ==================== UPLOAD DIRECTORY SETUP ====================

// Check and create upload directories with proper permissions
const setupUploadDirectories = () => {
  const uploadDirs = [
    path.join(__dirname, 'uploads', 'gallery'),
    path.join(__dirname, 'uploads', 'profiles')
  ];
  
  uploadDirs.forEach(uploadDir => {
    try {
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { 
          recursive: true,
          mode: 0o755 // Read/write/execute for owner, read/execute for group and others
        });
      }
      
      // Test write permissions
      const testFile = path.join(uploadDir, 'test.txt');
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);
      
      console.log(`✅ Upload directory is writable: ${uploadDir}`);
    } catch (error) {
      console.error(`❌ Upload directory error for ${uploadDir}:`, error);
      console.error('Please check directory permissions for:', uploadDir);
    }
  });
};

// Initialize upload directories
setupUploadDirectories();

// Connect to MongoDB
const connectDB = async () => {
  try {
    console.log('🔗 Attempting MongoDB connection...');
    
    const mongooseOptions = {
      // Connection pool settings
      maxPoolSize: parseInt(process.env.DB_MAX_POOL_SIZE) || 10,
      minPoolSize: 5,
      serverSelectionTimeoutMS: parseInt(process.env.DB_SERVER_SELECTION_TIMEOUT) || 30000,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT) || 45000,
      // Buffer commands to prevent timeouts (updated for Mongoose 6+)
      bufferCommands: true,
      // Retry settings
      retryWrites: true,
      retryReads: true,
      // Authentication
      authSource: 'admin',
      // Remove deprecated options
      // bufferMaxEntries: 0, // DEPRECATED - remove this line
    };

    console.log('📋 MongoDB connection options:', mongooseOptions);

    const conn = await mongoose.connect(process.env.MONGODB_URI, mongooseOptions);
    
    console.log('✅ MongoDB connected successfully');
    console.log(`📊 Database: ${conn.connection.name}`);
    console.log(`🌐 Host: ${conn.connection.host}`);

    // Connection event handlers
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err.message);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('✅ MongoDB reconnected');
    });

    // Handle process termination
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('MongoDB connection closed through app termination');
      process.exit(0);
    });

  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    
    if (error.name === 'MongoServerError') {
      console.error('🔐 Authentication failed. Please check:');
      console.error('   - MongoDB username and password');
      console.error('   - IP whitelist in MongoDB Atlas');
      console.error('   - Database name in connection string');
    }
    
    // In production, try to reconnect
    if (process.env.NODE_ENV === 'production') {
      console.log('🔄 Will attempt to reconnect in 10 seconds...');
      setTimeout(connectDB, 10000);
    } else {
      process.exit(1);
    }
  }
};



function startCleanupTask() {
  console.log('🔄 Starting profile image cleanup task...');
  
  setInterval(async () => {
    try {
      const users = await User.find({ profileImage: { $exists: true, $ne: '' } });
      
      let cleanedCount = 0;
      for (const user of users) {
        if (user.profileImage && user.profileImage.startsWith('/uploads/')) {
          const filePath = path.join(__dirname, user.profileImage);
          
          if (!fs.existsSync(filePath)) {
            console.log(`Profile image missing for user ${user._id}: ${user.profileImage}`);
            // Set profile image to empty if file doesn't exist
            user.profileImage = '';
            await user.save();
            cleanedCount++;
          }
        }
      }
      
      if (cleanedCount > 0) {
        console.log(`🧹 Cleaned up ${cleanedCount} missing profile images`);
      }
    } catch (error) {
      console.error('Cleanup task error:', error);
    }
  }, 3600000); // Run every hour
  setInterval(async () => {
    try {
      const galleryImages = await Gallery.find({ imageUrl: { $exists: true, $ne: '' } });
      let cleanedCount = 0;
      
      for (const image of galleryImages) {
        if (image.imageUrl && image.imageUrl.startsWith('/uploads/')) {
          const filePath = path.join(__dirname, image.imageUrl);
          if (!fs.existsSync(filePath)) {
            console.log(`Gallery image missing: ${image._id}, ${image.imageUrl}`);
            // Keep the record but mark it as missing
            image.imageMissing = true;
            await image.save();
            cleanedCount++;
          }
        }
      }
      
      if (cleanedCount > 0) {
        console.log(`🖼️ Cleaned up ${cleanedCount} missing gallery images`);
      }
    } catch (error) {
      console.error('Gallery cleanup task error:', error);
    }
  }, 3600000); // Run every hour
}

// Then call connectDB to start everything
connectDB();
// CORS configuration - MUST come before routes
// 

const allowedOrigins = process.env.NODE_ENV === 'production' 
  ? [
      'https://homeheroes.help',
      'https://www.homeheroes.help',
      'https://backendhomeheroes.onrender.com'
    ]
  : [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:5173',
      'http://localhost:4173',
      'http://localhost:5174',
    ];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      console.log('CORS blocked origin:', origin);
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin','Cache-Control', 'Pragma']
}));

app.post('/api/debug/test-email-verification', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const verificationToken = '123456';
    const emailResult = await sendVerificationEmail(
      { email, name: 'Test User' },
      verificationToken
    );

    res.json({
      success: emailResult.success,
      message: emailResult.success ? 'Test email sent successfully' : 'Failed to send test email',
      debugToken: verificationToken,
      emailResult
    });
  } catch (error) {
    console.error('Test email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: error.message
    });
  }
});

app.options('*', cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      return callback(new Error('Not allowed by CORS'), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With', 
    'Accept', 
    'Origin',
    'Cache-Control',
    'Pragma'
  ]
}));

// Handle preflight requests
app.options('*', cors());

// Explicitly handle preflight requests for all routes
app.options('*', cors());


// Handle preflight requests
app.options('*', cors());
// Middleware
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined'));
} else {
  app.use(morgan('dev'));
}

app.use(fileUpload({
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  abortOnLimit: true,
  createParentPath: true // This creates the directory if it doesn't exist
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Serve static files for uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Authentication middleware
// In your auth middleware
// function authenticateToken(req, res, next) {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];

//   if (!token) {
//     return res.status(401).json({
//       success: false,
//       message: 'Access token required'
//     });
//   }

//   jwt.verify(token, JWT_SECRET, async (err, decoded) => {
//     if (err) {
//       return res.status(403).json({
//         success: false,
//         message: 'Invalid or expired token'
//       });
//     }
    
//     // Add user info to request
//     try {
//       const user = await User.findById(decoded.id).select('-password');
//       if (!user) {
//         return res.status(403).json({
//           success: false,
//           message: 'User not found'
//         });
//       }
      
//       req.user = {
//         id: user._id.toString(),
//         userType: user.userType,
//         email: user.email,
//         name: user.name
//       };
      
//       next();
//     } catch (error) {
//       return res.status(500).json({
//         success: false,
//         message: 'Error verifying user'
//       });
//     }
//   });
// }
// function authenticateToken(req, res, next) {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];

//   if (!token) {
//     return res.status(401).json({
//       success: false,
//       message: 'Access token required'
//     });
//   }

//   jwt.verify(token, JWT_SECRET, async (err, decoded) => {
//     if (err) {
//       console.error('JWT verification error:', err);
//       return res.status(403).json({
//         success: false,
//         message: 'Invalid or expired token'
//       });
//     }
    
//     // Add user info to request
//     try {
//       const user = await User.findById(decoded.id).select('-password');
//       if (!user) {
//         return res.status(403).json({
//           success: false,
//           message: 'User not found'
//         });
//       }
      
//       req.user = {
//         id: user._id.toString(),
//         userType: user.userType,
//         email: user.email,
//         name: user.name
//       };
      
//       next();
//     } catch (error) {
//       console.error('Error verifying user:', error);
//       return res.status(500).json({
//         success: false,
//         message: 'Error verifying user'
//       });
//     }
//   });
// }


// ==================== API ROUTES ====================

// Auth routes
app.use('/api/auth', authRoutes);
app.use('/api/verification', verificationRoutes);
app.use('/api/jobs', jobRoutes);


// Update the authenticateToken middleware to be more specific
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  // Set timeout for JWT verification
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('JWT verification timeout')), 10000);
  });

  const verifyPromise = new Promise((resolve, reject) => {
    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.error('JWT verification error:', err);
        return reject(new Error('Invalid or expired token'));
      }
      
      try {
        const user = await User.findById(decoded.id)
          .select('-password')
          .maxTimeMS(10000); // 10 second timeout
        
        if (!user) {
          return reject(new Error('User not found'));
        }
        
        req.user = {
          id: user._id.toString(),
          userType: user.userType,
          email: user.email,
          name: user.name
        };
        
        resolve();
      } catch (dbError) {
        console.error('Database error in auth middleware:', dbError);
        reject(new Error('Error verifying user'));
      }
    });
  });

  Promise.race([verifyPromise, timeoutPromise])
    .then(() => next())
    .catch(error => {
      console.error('Auth middleware error:', error.message);
      
      if (error.message.includes('timeout')) {
        return res.status(503).json({
          success: false,
          message: 'Service temporarily unavailable'
        });
      }
      
      if (error.message.includes('Invalid') || error.message.includes('expired')) {
        return res.status(403).json({
          success: false,
          message: error.message
        });
      }
      
      res.status(500).json({
        success: false,
        message: 'Authentication error'
      });
    });
}



const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

app.get('/api/debug/email-status',async (req, res) => {
  const { getTransporterStatus } = await import('./utils/emailService.js');
  const status = getTransporterStatus();
  
  res.json({
    success: true,
    data: {
      ...status,
      frontendUrl: process.env.FRONTEND_URL,
      nodeEnv: process.env.NODE_ENV,
      emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
      timestamp: new Date().toISOString()
    }
  });
});

app.post('/api/debug/send-test-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address is required'
      });
    }

    const { initializeEmailTransporter, getEmailTransporter } = await import('./utils/emailService.js');
    
    console.log('🧪 Testing email sending to:', email);
    
    // Ensure transporter is initialized
    await initializeEmailTransporter();
    const transporter = getEmailTransporter();
    
    if (!transporter) {
      return res.status(500).json({
        success: false,
        message: 'Email transporter not available'
      });
    }

    const testMailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'HomeHero Production Email Test',
      text: `This is a test email sent from HomeHero production server at ${new Date().toISOString()}`,
      html: `
        <h1>HomeHero Production Test</h1>
        <p>This email was sent from your production server.</p>
        <p><strong>Time:</strong> ${new Date().toISOString()}</p>
        <p><strong>Environment:</strong> ${process.env.NODE_ENV}</p>
      `
    };

    const result = await transporter.sendMail(testMailOptions);
    
    res.json({
      success: true,
      message: 'Test email sent successfully',
      messageId: result.messageId
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test email',
      error: error.message
    });
  }
});

app.post('/api/debug/test-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!emailTransporter) {
      return res.json({
        success: false,
        message: 'Email transporter not initialized',
        details: {
          emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
          emailPassword: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set',
          environment: process.env.NODE_ENV
        }
      });
    }

    const testMailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'HomeHero Test Email',
      text: 'This is a test email from HomeHero production server.',
      html: '<h1>HomeHero Test Email</h1><p>This is a test email from production.</p>'
    };

    const result = await emailTransporter.sendMail(testMailOptions);
    
    res.json({
      success: true,
      message: 'Test email sent successfully',
      messageId: result.messageId
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test email',
      error: error.message,
      details: error
    });
  }
});


app.get('/api/providers/:id', async (req, res) => {
  try {
    const provider = await User.findById(req.params.id)
      .select('name email services hourlyRate averageRating city state country profileImage isAvailableNow experience phoneNumber address reviewCount completedJobs isVerified isTopRated responseTime createdAt');
    
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    res.json({
      success: true,
      data: provider
    });
  } catch (error) {
    console.error('Provider fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider'
    });
  }
});


app.get('/api/providers/:id/gallery', async (req, res) => {
  try {
    const providerId = req.params.id;
    // Fetch gallery from your database
    const gallery = await Gallery.find({ providerId });
    res.json({ success: true, data: gallery });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get('/api/auth/preferences', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('preferences notificationSettings');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Default preferences if none exist
    const defaultPreferences = {
      emailNotifications: true,
      smsNotifications: false,
      bookingReminders: true,
      marketingEmails: false,
      providerMessages: true,
      searchRadius: '10',
      contactMethod: 'message'
    };

    const preferences = user.preferences || defaultPreferences;
    const notificationSettings = user.notificationSettings || defaultPreferences;

    res.json({
      success: true,
      data: {
        preferences: {
          ...defaultPreferences,
          ...preferences,
          ...notificationSettings
        }
      }
    });
  } catch (error) {
    console.error('Get preferences error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch preferences'
    });
  }
});


// Get provider reviews
app.get('/api/providers/:id/reviews', async (req, res) => {
  try {
    const providerId = req.params.id;
    // Fetch reviews from your database
    const reviews = await Review.find({ providerId }).populate('customer');
    res.json({ success: true, data: reviews });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});
app.post('/api/test-email-simple', async (req, res) => {
  const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  try {
    await transporter.verify();
    const result = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER, // Send to yourself
      subject: 'Test from Production',
      text: 'This is a test email from production'
    });
    
    res.json({ success: true, messageId: result.messageId });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/debug/email-full-test', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address is required'
      });
    }

    console.log('🧪 FULL EMAIL TEST STARTED for:', email);
    
    // Test 1: Check environment variables
    console.log('🔍 Checking environment variables...');
    const envCheck = {
      NODE_ENV: process.env.NODE_ENV,
      EMAIL_USER: process.env.EMAIL_USER ? 'Set' : 'Not set',
      EMAIL_PASSWORD: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set',
      FRONTEND_URL: process.env.FRONTEND_URL,
      EMAIL_USER_VALUE: process.env.EMAIL_USER ? process.env.EMAIL_USER.substring(0, 3) + '...' : 'Not set',
      EMAIL_PASSWORD_LENGTH: process.env.EMAIL_PASSWORD ? process.env.EMAIL_PASSWORD.length : 'Not set'
    };
    
    console.log('🔍 Environment check:', envCheck);

    // Test 2: Initialize transporter
    const { initializeEmailTransporter, getEmailTransporter } = await import('./utils/emailService.js');
    console.log('🔍 Initializing email transporter...');
    
    const initResult = await initializeEmailTransporter();
    console.log('🔍 Transporter initialization result:', initResult);
    
    const transporter = getEmailTransporter();
    console.log('🔍 Transporter available:', !!transporter);

    if (!transporter) {
      return res.json({
        success: false,
        message: 'Email transporter not available',
        debug: envCheck
      });
    }

    // Test 3: Send test email
    console.log('🔍 Sending test email...');
    const testMailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `HomeHero Production Test - ${Date.now()}`,
      text: `Test email sent at: ${new Date().toISOString()}\nEnvironment: ${process.env.NODE_ENV}\nFrom: ${process.env.EMAIL_USER}`,
      html: `
        <h1>HomeHero Production Email Test</h1>
        <p><strong>Time:</strong> ${new Date().toISOString()}</p>
        <p><strong>Environment:</strong> ${process.env.NODE_ENV}</p>
        <p><strong>From:</strong> ${process.env.EMAIL_USER}</p>
        <p><strong>To:</strong> ${email}</p>
        <p><strong>Frontend URL:</strong> ${process.env.FRONTEND_URL}</p>
      `
    };

    const result = await transporter.sendMail(testMailOptions);
    
    console.log('✅ Test email sent successfully:', result.messageId);

    res.json({
      success: true,
      message: 'Test email sent successfully',
      data: {
        messageId: result.messageId,
        response: result.response,
        environment: envCheck
      }
    });
    
  } catch (error) {
    console.error('❌ Full email test failed:', error);
    res.status(500).json({
      success: false,
      message: 'Email test failed',
      error: {
        name: error.name,
        message: error.message,
        code: error.code,
        stack: error.stack
      },
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        EMAIL_USER_SET: !!process.env.EMAIL_USER,
        FRONTEND_URL: process.env.FRONTEND_URL
      }
    });
  }
});

app.get('/api/debug/email-config-detailed', async (req, res) => {
  try {
    const { initializeEmailTransporter, getEmailTransporter } = await import('./utils/emailService.js');
    
    // Test transporter initialization
    const initResult = await initializeEmailTransporter();
    const transporter = getEmailTransporter();
    
    // Test credentials
    const testTransporter = nodemailer.createTransporter({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      },
      logger: true,
      debug: true
    });
    
    let verifyResult;
    try {
      verifyResult = await testTransporter.verify();
    } catch (verifyError) {
      verifyResult = { error: verifyError.message };
    }
    
    res.json({
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        FRONTEND_URL: process.env.FRONTEND_URL,
        DOMAIN: process.env.DOMAIN
      },
      email: {
        EMAIL_USER: process.env.EMAIL_USER ? 'Set' : 'Not set',
        EMAIL_PASSWORD: process.env.EMAIL_PASSWORD ? `Set (length: ${process.env.EMAIL_PASSWORD.length})` : 'Not set',
        userValue: process.env.EMAIL_USER ? process.env.EMAIL_USER.substring(0, 3) + '...' : 'Not set'
      },
      transporter: {
        initialized: !!transporter,
        initResult: initResult,
        verifyResult: verifyResult
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      error: error.message,
      stack: error.stack
    });
  }
});



app.get('/api/debug/email-config', (req, res) => {
  res.json({
    environment: process.env.NODE_ENV,
    emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
    emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
    frontendUrl: process.env.FRONTEND_URL,
    transporterReady: !!emailTransporter
  });
});

// Add this test endpoint to your server.js
app.post('/api/debug/send-test-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address is required'
      });
    }

    console.log('📧 Attempting to send test email to:', email);
    console.log('🔧 Email transporter status:', emailTransporter ? 'Ready' : 'Not ready');
    console.log('👤 Sending from:', process.env.EMAIL_USER);

    if (!emailTransporter) {
      return res.json({
        success: false,
        message: 'Email transporter not initialized',
        details: {
          emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
          environment: process.env.NODE_ENV
        }
      });
    }

    const testMailOptions = {
      from: {
        name: 'HomeHero Test',
        address: process.env.EMAIL_USER
      },
      to: email,
      subject: 'HomeHero Test Email - Production',
      text: `This is a test email from HomeHero production server sent at ${new Date().toISOString()}`,
      html: `
        <h1>HomeHero Test Email</h1>
        <p>This is a test email from production server.</p>
        <p><strong>Sent:</strong> ${new Date().toISOString()}</p>
        <p><strong>From:</strong> ${process.env.EMAIL_USER}</p>
        <p><strong>To:</strong> ${email}</p>
      `
    };

    const result = await emailTransporter.sendMail(testMailOptions);
    
    console.log('✅ Test email sent successfully:', result.messageId);
    
    res.json({
      success: true,
      message: 'Test email sent successfully',
      messageId: result.messageId,
      previewUrl: `https://mail.google.com/mail/u/0/#search/${encodeURIComponent('HomeHero Test Email - Production')}`
    });
  } catch (error) {
    console.error('❌ Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test email',
      error: error.message,
      response: error.response
    });
  }
});



const sendBookingNotification = async (bookingData, providerEmail) => {
  try {
    console.log('📧 Attempting to send booking notification to:', providerEmail);
    
    // Check if email service is available
    if (!emailTransporter) {
      console.log('❌ Email transporter not available');
      return { success: false, error: 'Email service not configured' };
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: providerEmail,
      subject: 'New Booking Request - HomeHero',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .booking-details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .button { display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>📅 New Booking Request</h1>
              <p>You have a new service request on HomeHero</p>
            </div>
            <div class="content">
              <p>Hello Provider,</p>
              <p>You've received a new booking request from <strong>${bookingData.contactInfo.name}</strong>.</p>
              
              <div class="booking-details">
                <h3>Booking Details:</h3>
                <p><strong>Service:</strong> ${bookingData.serviceType}</p>
                <p><strong>Location:</strong> ${bookingData.location}</p>
                <p><strong>Timeframe:</strong> ${bookingData.timeframe}</p>
                <p><strong>Budget:</strong> ${bookingData.budget}</p>
                <p><strong>Description:</strong> ${bookingData.description || 'No description provided'}</p>
                ${bookingData.specialRequests ? `<p><strong>Special Requests:</strong> ${bookingData.specialRequests}</p>` : ''}
              </div>

              <p>Please log in to your HomeHero account to accept or reject this booking request.</p>
              
              <a href="https://homeheroes.help/provider/dashboard" class="button">View Dashboard</a>
              
              <p>If you have any questions, please contact our support team.</p>
              
              <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>© 2024 HomeHero. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `
    };

    const result = await emailTransporter.sendMail(mailOptions);
    console.log('✅ Booking notification email sent to provider:', providerEmail);
    console.log('✅ Message ID:', result.messageId);
    
    return { success: true, messageId: result.messageId };
  } catch (emailError) {
    console.error('❌ Failed to send booking notification email:', emailError);
    return { 
      success: false, 
      error: emailError.message,
      code: emailError.code 
    };
  }
};

// Then in your booking endpoint, update the email sending part:
if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
  try {
    // Make sure providerId is defined before using it
    if (providerId) {
      const providerUser = await User.findById(providerId);
      if (providerUser && providerUser.email) {
        const emailResult = await sendBookingNotification({
          serviceType,
          description,
          location,
          timeframe,
          budget,
          contactInfo,
          specialRequests
        }, providerUser.email);
        
        if (!emailResult.success) {
          console.log('⚠️ Email notification failed but booking was created');
          console.log('⚠️ Email error:', emailResult.error);
        }
      }
    } else {
      console.log('⚠️ providerId not available for email notification');
    }
  } catch (emailError) {
    console.error('⚠️ Email notification failed (non-critical):', emailError);
  }
} else {
  console.log('📧 Email service not configured, skipping notification');
}


app.post('/api/debug/test-email', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email address is required'
      });
    }

    console.log('🧪 Testing email to:', email);

    if (!emailTransporter) {
      return res.json({
        success: false,
        message: 'Email transporter not available'
      });
    }

    const testMailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'HomeHero Email Test',
      text: `This is a test email from HomeHero production server at ${new Date().toISOString()}`,
      html: `
        <h1>HomeHero Email Test</h1>
        <p>This email was sent from your production server.</p>
        <p><strong>Time:</strong> ${new Date().toISOString()}</p>
        <p><strong>Environment:</strong> ${process.env.NODE_ENV}</p>
      `
    };

    const result = await emailTransporter.sendMail(testMailOptions);
    
    res.json({
      success: true,
      message: 'Test email sent successfully',
      messageId: result.messageId
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send test email',
      error: error.message
    });
  }
});

app.post('/api/email/reinitialize', async (req, res) => {
  try {
    const { initializeEmailTransporter } = await import('./utils/emailService.js');
    
    console.log('🔄 Manually reinitializing email service...');
    const result = await initializeEmailTransporter();
    
    res.json({
      success: true,
      message: result ? 'Email service initialized successfully' : 'Email service initialization failed',
      status: result ? 'ready' : 'failed'
    });
  } catch (error) {
    console.error('Reinitialization error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reinitialize email service',
      error: error.message
    });
  }
});

// Add to server.js
app.get('/api/debug/email-config', (req, res) => {
  res.json({
    success: true,
    data: {
      environment: process.env.NODE_ENV,
      emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
      emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
      emailPassword: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set',
      frontendUrl: process.env.FRONTEND_URL,
      transporterReady: !!emailTransporter
    }
  });
});

app.get('/api/debug/email-config', (req, res) => {
  res.json({
    success: true,
    data: {
      emailUser: process.env.EMAIL_USER,
      emailPassword: process.env.EMAIL_PASSWORD ? '***' + process.env.EMAIL_PASSWORD.slice(-4) : 'Not set',
      frontendUrl: process.env.FRONTEND_URL,
      nodeEnv: process.env.NODE_ENV,
      envFile: process.env.NODE_ENV === 'production' ? 'env.production' : '.env'
    }
  });
});

// Add this test endpoint to verify nodemailer works
app.post('/api/test-nodemailer-direct', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
      return res.json({
        success: false,
        message: 'Email credentials not configured',
        emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
        emailPassword: process.env.EMAIL_PASSWORD ? 'Set' : 'Not set'
      });
    }

    // Test nodemailer directly
    const testTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
      }
    });

    // Verify connection
    await testTransporter.verify();
    console.log('✅ Direct nodemailer test: Connection verified');

    // Try to send a test email
    const result = await testTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email || process.env.EMAIL_USER, // Send to yourself if no email provided
      subject: 'Direct Nodemailer Test',
      text: 'This is a direct nodemailer test email'
    });

    res.json({
      success: true,
      message: 'Direct nodemailer test successful',
      messageId: result.messageId
    });

  } catch (error) {
    console.error('Direct nodemailer test failed:', error);
    res.status(500).json({
      success: false,
      message: 'Direct nodemailer test failed',
      error: error.message
    });
  }
});

app.get('/api/debug/email-status', (req, res) => {
  // Import directly to avoid any import issues
  import('./utils/emailService.js').then((emailService) => {
    const status = emailService.getEmailServiceStatus();
    const transporter = emailService.getEmailTransporter();
    
    res.json({
      success: true,
      data: {
        emailServiceStatus: status,
        hasTransporter: !!transporter,
        emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
        emailUser: process.env.EMAIL_USER ? 'Set' : 'Not set',
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString()
      }
    });
  }).catch(error => {
    res.status(500).json({
      success: false,
      error: 'Failed to import email service: ' + error.message
    });
  });
});

app.get('/api/debug/email-setup', (req, res) => {
  const emailConfig = {
    environment: process.env.NODE_ENV,
    emailUser: process.env.EMAIL_USER,
    emailPassword: process.env.EMAIL_PASSWORD ? '***' + process.env.EMAIL_PASSWORD.slice(-4) : 'Not set',
    frontendUrl: process.env.FRONTEND_URL,
    nodeEnv: process.env.NODE_ENV,
    // Check if we're using the right .env file
    envFile: process.env.NODE_ENV === 'production' ? 'env.production' : '.env'
  };
  
  res.json({
    success: true,
    data: emailConfig
  });
});

app.get('/api/health/email', async (req, res) => {
  const { getEmailServiceStatus } = await import('./utils/emailService.js');
  const status = getEmailServiceStatus();
  
  res.json({
    success: true,
    data: {
      emailService: status,
      configured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
      timestamp: new Date().toISOString()
    }
  });
});



// Profile image upload endpoint - FIXED VERSION


app.post('/api/auth/profile/image', authenticateToken, async (req, res) => {
  try {
    if (!req.files || !req.files.profileImage) {
      return res.status(400).json({
        success: false,
        message: 'No image file provided'
      });
    }

    const profileImage = req.files.profileImage;
    
    // Generate unique filename
    const fileExtension = path.extname(profileImage.name);
    const fileName = `profile-${req.user.id}-${Date.now()}${fileExtension}`;
    const uploadDir = path.join(__dirname, 'uploads', 'profiles');
    const uploadPath = path.join(uploadDir, fileName);

    // Create uploads directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
    }

    // Move the file to the upload directory
    await profileImage.mv(uploadPath);

    // Update user profile with the new image
    const imageUrl = `/uploads/profiles/${fileName}`;
    await User.findByIdAndUpdate(req.user.id, { 
      profileImage: imageUrl
    });

    res.json({
      success: true,
      message: 'Profile image uploaded successfully',
      data: { 
        imageUrl
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


// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
    const userCount = await User.countDocuments();
    const verifiedUserCount = await User.countDocuments({ isEmailVerified: true });
    const providerCount = await User.countDocuments({ userType: { $in: ['provider', 'both'] } });
    const customerCount = await User.countDocuments({ userType: { $in: ['customer', 'both'] } });
    
    const healthData = { 
      status: 'OK', 
      message: 'HomeHero API is running',
      environment: process.env.NODE_ENV || 'development',
      version: '2.0.0',
      uptime: Math.floor(process.uptime()),
      database: {
        status: dbStatus,
        name: mongoose.connection.name,
        host: mongoose.connection.host || 'localhost'
      },
      email: {
        configured: !!process.env.EMAIL_USER && !!process.env.EMAIL_PASSWORD,
        service: 'gmail'
      },
      statistics: {
        totalUsers: userCount,
        verifiedUsers: verifiedUserCount,
        providers: providerCount,
        customers: customerCount
      },
      timestamp: new Date().toISOString()
    };

    if (dbStatus !== 'Connected') {
      return res.status(503).json({
        ...healthData,
        status: 'DEGRADED',
        message: 'Database connection issues'
      });
    }

    res.json(healthData);
  } catch (error) {
    console.error('Health check error:', error);
    res.status(503).json({
      status: 'ERROR',
      message: 'Health check failed',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      timestamp: new Date().toISOString()
    });
  }
});

// Upload health check endpoint
app.get('/api/health/upload', async (req, res) => {
  try {
    const uploadDirs = [
      { name: 'gallery', path: path.join(__dirname, 'uploads', 'gallery') },
      { name: 'profiles', path: path.join(__dirname, 'uploads', 'profiles') }
    ];
    
    const results = {};
    
    for (const dir of uploadDirs) {
      try {
        // Check if directory exists and create if not
        if (!fs.existsSync(dir.path)) {
          fs.mkdirSync(dir.path, { recursive: true });
        }
        
        // Test write permissions
        const testFile = path.join(dir.path, 'test.txt');
        fs.writeFileSync(testFile, 'test');
        fs.unlinkSync(testFile);
        
        results[dir.name] = {
          exists: true,
          writable: true,
          path: dir.path
        };
      } catch (error) {
        results[dir.name] = {
          exists: fs.existsSync(dir.path),
          writable: false,
          path: dir.path,
          error: error.message
        };
      }
    }
    
    const allWritable = Object.values(results).every(result => result.writable);
    
    res.status(allWritable ? 200 : 500).json({
      success: allWritable,
      message: allWritable ? 'All upload directories are writable' : 'Some upload directories have issues',
      directories: results
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Upload directory health check failed',
      error: error.message
    });
  }
});

// Messages routes
app.use('/api/messages', messageRoutes);


// Gallery 
// ==================== GALLERY UPLOAD ENDPOINT ====================

// Configure multer specifically for gallery uploads
const galleryStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'uploads', 'gallery');
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'gallery-' + uniqueSuffix + ext);
  }
});

const galleryUpload = multer({
  storage: galleryStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Gallery upload endpoint
app.use('/api/gallery', (req, res, next) => {
  // Temporarily disable fileUpload for gallery routes to avoid conflict with multer
  next();
});

// Gallery upload using express-fileupload
// Gallery upload endpoint
app.post('/api/gallery/upload', authenticateToken, async (req, res) => {
  try {
    console.log('=== GALLERY UPLOAD USING EXPRESS-FILEUPLOAD ===');
    
    if (!req.files || !req.files.image) {
      console.log('No image file in req.files:', req.files);
      return res.status(400).json({
        success: false,
        message: 'No image file provided. Please select an image.'
      });
    }

    const imageFile = req.files.image;
    const { title, description, category, tags, featured } = req.body;

    // Validate required fields
    if (!title || !title.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Title is required'
      });
    }

    // Validate file type and size
    if (!imageFile.mimetype.startsWith('image/')) {
      return res.status(400).json({
        success: false,
        message: 'Only image files are allowed (jpg, png, gif, etc.)'
      });
    }

    if (imageFile.size > 5 * 1024 * 1024) {
      return res.status(400).json({
        success: false,
        message: 'File size must be less than 5MB'
      });
    }

    // Create upload directory if it doesn't exist
    const uploadDir = path.join(__dirname, 'uploads', 'gallery');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    // Generate unique filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const fileExtension = path.extname(imageFile.name);
    const fileName = `gallery-${uniqueSuffix}${fileExtension}`;
    const filePath = path.join(uploadDir, fileName);

    // Move the file
    await imageFile.mv(filePath);

    // FIXED: Create proper image URLs without double slashes
    const relativeUrl = `/uploads/gallery/${fileName}`;
    
    // Use the same domain for both development and production
    // This ensures consistency and avoids CORS issues
    const protocol = req.protocol;
    const host = req.get('host');
    const fullImageUrl = `${protocol}://${host}${relativeUrl}`;

    // Create gallery entry
    const newImage = new Gallery({
      title: title.trim(),
      description: description ? description.trim() : '',
      category: category || 'other',
      imageUrl: relativeUrl, // Store relative URL
      fullImageUrl: fullImageUrl, // Store complete URL for easy access
      userId: req.user.id,
      tags: tags ? tags.split(',').map(tag => tag.trim()).filter(tag => tag) : [],
      featured: featured === 'true' || featured === true
    });

    // Save to database
    const savedImage = await newImage.save();
    await savedImage.populate('userId', 'name profileImage');

    console.log('Image uploaded successfully:', savedImage._id, 'URL:', fullImageUrl);

    res.status(201).json({
      success: true,
      message: 'Image uploaded successfully',
      data: savedImage
    });
    
  } catch (error) {
    console.error('Gallery upload error:', error);
    
    let errorMessage = 'Failed to upload image';
    let statusCode = 500;
    
    if (error.name === 'ValidationError') {
      errorMessage = 'Invalid data: ' + Object.values(error.errors).map(e => e.message).join(', ');
      statusCode = 400;
    }
    
    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
});


// Simple test endpoint
app.post('/api/test-upload', async (req, res) => {
  try {
    console.log('Test upload - Files:', req.files);
    console.log('Test upload - Body:', req.body);
    
    if (req.files && req.files.testFile) {
      const testFile = req.files.testFile;
      console.log('Test file received:', testFile.name, testFile.size);
      
      res.json({
        success: true,
        message: 'File received successfully',
        file: {
          name: testFile.name,
          size: testFile.size,
          type: testFile.mimetype
        }
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'No file received',
        files: req.files
      });
    }
  } catch (error) {
    console.error('Test upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: error.message
    });
  }
});

// Get verification status
app.get('/api/auth/verification-status', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('identityVerification hasSubmittedVerification');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        isNinVerified: user.identityVerification?.isNinVerified || false,
        isNepaVerified: user.identityVerification?.isNepaVerified || false,
        verificationStatus: user.identityVerification?.verificationStatus || 'unverified',
        hasSubmittedVerification: user.hasSubmittedVerification || false
      }
    });
  } catch (error) {
    console.error('Get verification status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch verification status'
    });
  }
});

// Submit identity verification
app.post('/api/auth/verify-identity', authenticateToken, async (req, res) => {
  try {
    const { nin } = req.body;
    const nepaBill = req.files?.nepaBill;

    // Server-side NIN validation
    if (!nin) {
      return res.status(400).json({
        success: false,
        message: 'NIN is required'
      });
    }

    // Clean and validate NIN
    const cleanNIN = nin.replace(/\D/g, '');
    
    if (cleanNIN.length !== 11) {
      return res.status(400).json({
        success: false,
        message: 'NIN must be exactly 11 digits'
      });
    }

    if (!/^\d+$/.test(cleanNIN)) {
      return res.status(400).json({
        success: false,
        message: 'NIN must contain only numbers'
      });
    }

    // Enhanced server-side validation
    const validationError = validateNINOnServer(cleanNIN);
    if (validationError) {
      return res.status(400).json({
        success: false,
        message: validationError
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if NIN is already used by another user
    const existingUser = await User.findOne({ 
      'identityVerification.nin': cleanNIN,
      _id: { $ne: req.user.id }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'This NIN is already registered with another account. Please contact support if this is an error.'
      });
    }

    // Check if user has recently attempted verification (rate limiting)
    const lastAttempt = user.identityVerification?.verificationSubmittedAt;
    if (lastAttempt && Date.now() - new Date(lastAttempt).getTime() < 24 * 60 * 60 * 1000) {
      return res.status(429).json({
        success: false,
        message: 'Verification attempt limit exceeded. Please try again in 24 hours.'
      });
    }

    // Handle file upload for NEPA bill
    let nepaBillUrl = '';
    if (nepaBill) {
      const uploadDir = path.join(__dirname, 'uploads', 'verification');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }

      const fileName = `nepa-bill-${req.user.id}-${Date.now()}${path.extname(nepaBill.name)}`;
      const filePath = path.join(uploadDir, fileName);
      
      await nepaBill.mv(filePath);
      nepaBillUrl = `/uploads/verification/${fileName}`;
    }

    // Update user verification data
    user.identityVerification = {
      nin: cleanNIN,
      nepaBillUrl: nepaBillUrl,
      isNinVerified: false, // Will be verified against external service
      isNepaVerified: false,
      verificationStatus: 'pending',
      verificationSubmittedAt: new Date(),
      verificationNotes: ''
    };

    user.hasSubmittedVerification = true;

    await user.save();

    // In production, integrate with real NIMC API here
    await verifyWithExternalService(cleanNIN, user._id);

    res.json({
      success: true,
      message: 'Identity verification submitted successfully. It will be reviewed by our team.',
      data: {
        isNinVerified: false,
        isNepaVerified: false,
        verificationStatus: 'pending',
        hasSubmittedVerification: true
      }
    });

  } catch (error) {
    console.error('Identity verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit identity verification'
    });
  }
});

// Server-side NIN validation function
function validateNINOnServer(nin) {
  const stateCodes = {
    '01': 'Lagos', '02': 'Ogun', '03': 'Oyo', '04': 'Ondo', '05': 'Osun',
    // ... include all state codes
  };

  const stateCode = nin.substring(0, 2);
  if (!stateCodes[stateCode]) {
    return 'Invalid state code in NIN';
  }

  // Check for obvious fake patterns
  if (/^(\d)\1+$/.test(nin)) {
    return 'Invalid NIN pattern detected';
  }

  // Check sequential numbers
  let sequential = true;
  for (let i = 1; i < nin.length; i++) {
    if (parseInt(nin[i]) !== parseInt(nin[i-1]) + 1) {
      sequential = false;
      break;
    }
  }
  if (sequential) return 'Invalid sequential NIN detected';

  return null;
}

// Mock external verification (replace with real API integration)
async function verifyWithExternalService(nin, userId) {
  try {
    // In production, integrate with:
    // 1. NIMC API
    // 2. Third-party verification services
    // 3. Government databases
    
    // Simulate API call
    console.log(`Verifying NIN ${nin} for user ${userId} with external service`);
    
    // This would be the real implementation:
    // const response = await fetch('https://api.nimc.gov.ng/verify', {
    //   method: 'POST',
    //   headers: { 'Authorization': `Bearer ${process.env.NIMC_API_KEY}` },
    //   body: JSON.stringify({ nin: nin })
    // });
    
    // For now, simulate success after delay
    setTimeout(async () => {
      try {
        // Update verification status based on external service response
        await User.findByIdAndUpdate(userId, {
          'identityVerification.isNinVerified': true,
          'identityVerification.verificationStatus': 'verified',
          'identityVerification.verificationReviewedAt': new Date()
        });
        
        console.log(`NIN ${nin} verified successfully for user ${userId}`);
      } catch (error) {
        console.error('Error updating verification status:', error);
      }
    }, 5000);
    
  } catch (error) {
    console.error('External verification service error:', error);
  }
}


// Admin endpoint to verify identities (optional - for admin panel)
app.patch('/api/admin/verify-identity/:userId', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const { approveNIN, approveNepa, notes } = req.body;
    const userId = req.params.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (!user.identityVerification) {
      return res.status(400).json({
        success: false,
        message: 'User has not submitted verification'
      });
    }

    // Update verification status
    user.identityVerification.isNinVerified = approveNIN || false;
    user.identityVerification.isNepaVerified = approveNepa || false;
    user.identityVerification.verificationStatus = 
      (approveNIN && approveNepa) ? 'verified' : 
      approveNIN ? 'verified' : 'rejected';
    user.identityVerification.verificationReviewedAt = new Date();
    user.identityVerification.verificationNotes = notes || '';

    await user.save();

    // Send notification to user about verification status
    // You can implement email notification here

    res.json({
      success: true,
      message: 'Verification status updated successfully',
      data: user.identityVerification
    });

  } catch (error) {
    console.error('Admin verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update verification status'
    });
  }
});
// Gallery GET endpoint (for retrieving images)
// Gallery GET endpoint (for retrieving images)
// Gallery GET endpoint (for retrieving images) - MODIFIED
app.get('/api/gallery', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const category = req.query.category;
    const search = req.query.search;

    // ADDED: Filter by current user
    let filter = { userId: req.user.id };
    
    if (category && category !== 'all') {
      filter.category = category;
    }
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: { path: 'userId', select: 'name profileImage' }
    };

    const result = await Gallery.paginate(filter, options);

    // FIXED: Use request host to construct URLs
    const protocol = req.secure ? 'https' : 'http';
    const host = req.get('host');
    
    const imagesWithFullUrl = result.docs.map(image => {
      const imageObj = image.toObject();
      if (imageObj.imageMissing) {
        return {
          ...imageObj,
          fullImageUrl: 'https://via.placeholder.com/600x400/e2e8f0/64748b?text=Image+Not+Available',
          imageMissing: true
        };
      }
      // If fullImageUrl is already stored, use it
      if (imageObj.fullImageUrl) {
        return imageObj;
      }
      
      // Otherwise, construct proper URL using the request host
      let fullImageUrl;
      if (imageObj.imageUrl) {
        // Ensure imageUrl starts with /
        const relativeUrl = imageObj.imageUrl.startsWith('/') 
          ? imageObj.imageUrl 
          : `/${imageObj.imageUrl}`;
          
        fullImageUrl = `${protocol}://${host}${relativeUrl}`;
      }
      
      return {
        ...imageObj,
        fullImageUrl
      };
    });

    res.json({
      success: true,
      data: {
        docs: imagesWithFullUrl,
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
    console.error('Get gallery error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch gallery images'
    });
  }
});


// Gallery like endpoint
app.post('/api/gallery/:id/like', authenticateToken, async (req, res) => {
  try {
    const image = await Gallery.findById(req.params.id);
    
    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }

    // ADDED: Check if user owns this image
    if (image.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'You can only like your own images'
      });
    }

    image.likes = (image.likes || 0) + 1;
    await image.save();

    res.json({
      success: true,
      message: 'Image liked successfully',
      data: { likes: image.likes }
    });
  } catch (error) {
    console.error('Like image error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to like image'
    });
  }
});

// Gallery view count endpoint
app.get('/api/gallery/:id', authenticateToken, async (req, res) => {
  try {
    const image = await Gallery.findById(req.params.id)
      .populate('userId', 'name profileImage');
    
    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }

    // ADDED: Check if user owns this image
    if (image.userId._id.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only view your own images.'
      });
    }

    // Increment view count
    image.views = (image.views || 0) + 1;
    await image.save();

    // FIXED: Consistent URL construction
    const imageObj = image.toObject();
    
    let fullImageUrl;
    if (imageObj.fullImageUrl) {
      fullImageUrl = imageObj.fullImageUrl;
    } else if (imageObj.imageUrl) {
      const relativeUrl = imageObj.imageUrl.startsWith('/') 
        ? imageObj.imageUrl 
        : `/${imageObj.imageUrl}`;
        
      if (process.env.NODE_ENV === 'production') {
        fullImageUrl = `https://homeheroes.help${relativeUrl}`;
      } else {
        fullImageUrl = `http://localhost:${PORT}${relativeUrl}`;
      }
    }

    const imageWithFullUrl = {
      ...imageObj,
      fullImageUrl
    };

    res.json({
      success: true,
      data: imageWithFullUrl
    });
  } catch (error) {
    console.error('Get image error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch image'
    });
  }
});

// Serve static files for uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, filePath) => {
    // Set proper caching headers for images
    if (filePath.match(/\.(jpg|jpeg|png|gif|webp)$/)) {
      res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 day
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
  },
  fallthrough: true // Allow the request to continue to other middleware
}));

app.use('/uploads', (req, res, next) => {
  const filePath = path.join(__dirname, 'uploads', req.path);
  
  if (!fs.existsSync(filePath)) {
    console.log(`File not found: ${filePath}`);
    
    // Handle profile images - use local placeholder instead of external URL
    if (req.path.includes('/profiles/')) {
      // Return a simple placeholder image response
      const placeholderSvg = `<svg width="400" height="400" xmlns="http://www.w3.org/2000/svg">
        <rect width="100%" height="100%" fill="#e2e8f0"/>
        <text x="50%" y="50%" font-family="Arial" font-size="20" fill="#64748b" text-anchor="middle" dy=".3em">Profile Image</text>
      </svg>`;
      
      res.setHeader('Content-Type', 'image/svg+xml');
      return res.send(placeholderSvg);
    }
    
    // Handle gallery images
    if (req.path.includes('/gallery/')) {
      const placeholderSvg = `<svg width="600" height="400" xmlns="http://www.w3.org/2000/svg">
        <rect width="100%" height="100%" fill="#e2e8f0"/>
        <text x="50%" y="50%" font-family="Arial" font-size="20" fill="#64748b" text-anchor="middle" dy=".3em">Gallery Image</text>
      </svg>`;
      
      res.setHeader('Content-Type', 'image/svg+xml');
      return res.send(placeholderSvg);
    }
    
    // Return SVG placeholder for other images
    const placeholderSvg = `<svg width="400" height="400" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#e2e8f0"/>
      <text x="50%" y="50%" font-family="Arial" font-size="20" fill="#64748b" text-anchor="middle" dy=".3em">Image Not Found</text>
    </svg>`;
    
    res.setHeader('Content-Type', 'image/svg+xml');
    return res.send(placeholderSvg);
  }
  next();
});

// app.use('/uploads', (req, res, next) => {
//   const filePath = path.join(__dirname, 'uploads', req.path);
  
//   if (!fs.existsSync(filePath)) {
//     console.log(`File not found: ${filePath}`);
    
//     // Handle profile images
//     if (req.path.includes('/profiles/')) {
//       const filename = path.basename(req.path);
//       const userId = filename.split('-')[1];
      
//       if (userId && mongoose.Types.ObjectId.isValid(userId)) {
//         return User.findById(userId)
//           .then(user => {
//             if (user && user.profileImageFull) {
//               return res.redirect(user.profileImageFull);
//             }
//             return res.redirect('https://via.placeholder.com/400x400/e2e8f0/64748b?text=Profile+Image');
//           })
//           .catch(() => {
//             return res.redirect('https://via.placeholder.com/400x400/e2e8f0/64748b?text=Profile+Image');
//           });
//       }
//     }
    
//     // NEW: Handle gallery images
//     if (req.path.includes('/gallery/')) {
//       const filename = path.basename(req.path);
//       // Try to find the gallery image by filename
//       return Gallery.findOne({ imageUrl: `/uploads/gallery/${filename}` })
//         .then(image => {
//           if (image && image.fullImageUrl) {
//             return res.redirect(image.fullImageUrl);
//           }
//           return res.redirect('https://via.placeholder.com/600x400/e2e8f0/64748b?text=Gallery+Image');
//         })
//         .catch(() => {
//           return res.redirect('https://via.placeholder.com/600x400/e2e8f0/64748b?text=Gallery+Image');
//         });
//     }
    
//     // Return placeholder for other images
//     return res.redirect('https://via.placeholder.com/400x400/e2e8f0/64748b?text=Image+Not+Found');
//   }
//   next();
// });


app.post('/api/gallery/fix-urls', authenticateToken, async (req, res) => {
  try {
    const images = await Gallery.find({});
    
    let updatedCount = 0;
    
    for (const image of images) {
      let needsUpdate = false;
      let fullImageUrl;
      
      // Ensure imageUrl starts with /
      if (image.imageUrl && !image.imageUrl.startsWith('/')) {
        image.imageUrl = `/${image.imageUrl}`;
        needsUpdate = true;
      }
      
      // Generate fullImageUrl if missing
      if (!image.fullImageUrl && image.imageUrl) {
        if (process.env.NODE_ENV === 'production') {
          fullImageUrl = `https://homeheroes.help${image.imageUrl}`;
        } else {
          fullImageUrl = `http://localhost:${PORT}${image.imageUrl}`;
        }
        image.fullImageUrl = fullImageUrl;
        needsUpdate = true;
      }
      
      if (needsUpdate) {
        await image.save();
        updatedCount++;
      }
    }
    
    res.json({
      success: true,
      message: `Fixed URLs for ${updatedCount} images`,
      totalImages: images.length,
      updatedCount
    });
  } catch (error) {
    console.error('Fix URLs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fix URLs',
      error: error.message
    });
  }
});


// Debug endpoint to check image URLs
app.get('/api/debug/images', async (req, res) => {
  try {
    const images = await Gallery.find().limit(5);
    const debugInfo = images.map(image => ({
      _id: image._id,
      storedImageUrl: image.imageUrl,
      constructedUrl: process.env.NODE_ENV === 'production' 
        ? `https://homeheroes.help${image.imageUrl}`
        : `http://localhost:${PORT}${image.imageUrl}`,
      fileExists: fs.existsSync(path.join(__dirname, image.imageUrl))
    }));
    
    res.json({
      success: true,
      data: debugInfo,
      environment: process.env.NODE_ENV,
      domain: process.env.DOMAIN
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Test endpoint to check upload directory
app.get('/api/test-upload', (req, res) => {
  const uploadDir = path.join(__dirname, 'uploads', 'gallery');
  const testFile = path.join(uploadDir, 'test.txt');
  
  try {
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    // Test write permissions
    fs.writeFileSync(testFile, 'test');
    fs.unlinkSync(testFile);
    
    res.json({
      success: true,
      message: 'Upload directory is writable',
      path: uploadDir
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Upload directory error',
      error: error.message,
      path: uploadDir
    });
  }
});

// Gallery delete endpoint
app.delete('/api/gallery/:id', authenticateToken, async (req, res) => {
  try {
    const imageId = req.params.id;
    
    // Find the image first to get the file path
    const image = await Gallery.findById(imageId);
    
    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }
    
    // Check if the user owns this image or is an admin
    if (image.userId.toString() !== req.user.id && req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'You can only delete your own images'
      });
    }
    
    // Delete the physical file from the server
    if (image.imageUrl) {
      const filePath = path.join(__dirname, image.imageUrl);
      
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`Deleted file: ${filePath}`);
      }
    }
    
    // Delete the database record
    await Gallery.findByIdAndDelete(imageId);
    
    res.json({
      success: true,
      message: 'Image deleted successfully'
    });
    
  } catch (error) {
    console.error('Delete image error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete image',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});
// Dashboard endpoint
app.get('/api/user/dashboard', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Fetch user data
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Fetch availability slots
    const availabilitySlots = user.availability || [];
    
    // Fetch recent jobs
    const recentJobs = await Job.find({ providerId: userId })
      .sort({ date: -1 })
      .limit(3)
      .populate('clientId', 'name');
    
    // Fetch upcoming tasks
    const upcomingTasks = await Job.find({ 
      providerId: userId, 
      status: { $in: ['confirmed', 'upcoming'] },
      date: { $gte: new Date() }
    })
    .sort({ date: 1 })
    .limit(2)
    .populate('clientId', 'name');
    
    // NEW: Fetch recent bookings for the provider
    const bookings = await Booking.find({ providerId: userId })
      .sort({ requestedAt: -1 })
      .limit(5)
      .populate('customerId', 'name email phoneNumber');
    
    // Calculate stats
    const completedJobs = await Job.countDocuments({ 
      providerId: userId, 
      status: 'completed' 
    });
    
    const totalEarnings = await Job.aggregate([
      { $match: { providerId: new mongoose.Types.ObjectId(userId), status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
    const averageRating = await Review.aggregate([
      { $match: { providerId: new mongoose.Types.ObjectId(userId) } },
      { $group: { _id: null, average: { $avg: '$rating' } } }
    ]);
    
    const activeClients = await Job.distinct('clientId', { 
      providerId: userId, 
      status: 'completed',
      date: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
    });
    
    res.json({
      user: {
        name: user.name,
        email: user.email,
        id: user._id,
        country: user.country,
        profileImage: user.profilePicture || ''
      },
      availabilitySlots,
      recentJobs: recentJobs.map(job => ({
        id: job._id,
        title: job.serviceType,
        client: job.clientId?.name || 'Unknown Client',
        location: job.location,
        date: job.date.toISOString().split('T')[0],
        time: job.startTime,
        payment: job.payment,
        status: job.status,
        category: job.category || 'other'
      })),
      upcomingTasks: upcomingTasks.map(task => ({
        id: task._id,
        title: task.serviceType,
        time: task.startTime,
        duration: task.duration,
        client: task.clientId?.name || 'Unknown Client',
        priority: task.priority || 'medium',
        category: task.category || 'other'
      })),
      // NEW: Include bookings in the response
      bookings: bookings.map(booking => ({
        _id: booking._id,
        providerId: booking.providerId,
        providerName: booking.providerName,
        providerEmail: booking.providerEmail,
        customerId: booking.customerId?._id,
        customerName: booking.customerId?.name || booking.customerName,
        customerEmail: booking.customerId?.email || booking.customerEmail,
        customerPhone: booking.customerId?.phoneNumber || booking.customerPhone,
        serviceType: booking.serviceType,
        description: booking.description,
        location: booking.location,
        timeframe: booking.timeframe,
        budget: booking.budget,
        specialRequests: booking.specialRequests,
        bookingType: booking.bookingType,
        status: booking.status,
        requestedAt: booking.requestedAt,
        acceptedAt: booking.acceptedAt,
        completedAt: booking.completedAt,
        updatedAt: booking.updatedAt
      })),
      stats: {
        totalEarnings: totalEarnings.length > 0 ? totalEarnings[0].total : 0,
        jobsCompleted: completedJobs,
        averageRating: averageRating.length > 0 ? Math.round(averageRating[0].average * 10) / 10 : 0,
        activeClients: activeClients.length
      }
    });
  } catch (error) {
    console.error('Dashboard API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard data',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// ==================== MESSAGING ENDPOINTS ====================

// Get or create conversation between two users
app.post('/api/messages/conversation', authenticateToken, async (req, res) => {
  try {
    const { participantId } = req.body;
    
    if (!participantId) {
      return res.status(400).json({
        success: false,
        message: 'Participant ID is required'
      });
    }

    // Check if conversation already exists between these two users
    let conversation = await Conversation.findOne({
      participants: { $all: [req.user.id, participantId], $size: 2 }
    }).populate('participants', 'name email profileImage');

    // If not, create a new conversation
    if (!conversation) {
      conversation = new Conversation({
        participants: [req.user.id, participantId]
      });
      await conversation.save();
      await conversation.populate('participants', 'name email profileImage');
    }

    res.json({
      success: true,
      data: { conversation }
    });
  } catch (error) {
    console.error('Get conversation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get or create conversation'
    });
  }
});

// Send message
app.post('/api/messages/send', authenticateToken, async (req, res) => {
  try {
    const { conversationId, content, messageType = 'text' } = req.body;

    if (!conversationId || !content) {
      return res.status(400).json({
        success: false,
        message: 'Conversation ID and content are required'
      });
    }

    // Verify user is part of conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(req.user.id)) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized for this conversation'
      });
    }

    const message = new Message({
      conversationId,
      senderId: req.user.id,
      content,
      messageType
    });

    await message.save();
    
    // Update conversation last message and timestamp
    conversation.lastMessage = message._id;
    conversation.updatedAt = new Date();
    await conversation.save();

    // Populate sender info
    await message.populate('senderId', 'name profileImage');

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      data: { message }
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send message'
    });
  }
});

// Get messages for conversation
app.get('/api/messages/conversation/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;

    // Verify user is part of conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(req.user.id)) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized for this conversation'
      });
    }

    const messages = await Message.find({ conversationId })
      .populate('senderId', 'name profileImage')
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    // Mark messages as read if they're from other participants
    await Message.updateMany(
      {
        conversationId,
        senderId: { $ne: req.user.id },
        status: { $ne: 'read' }
      },
      { status: 'read' }
    );

    res.json({
      success: true,
      data: {
        messages: messages.reverse(), // Return in chronological order
        pagination: {
          currentPage: page,
          limit,
          totalPages: Math.ceil(await Message.countDocuments({ conversationId }) / limit)
        }
      }
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch messages'
    });
  }
});

// Get user conversations
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
  try {
    const conversations = await Conversation.find({
      participants: req.user.id
    })
    .populate('participants', 'name email profileImage')
    .populate('lastMessage')
    .sort({ updatedAt: -1 });

    res.json({
      success: true,
      data: { conversations }
    });
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch conversations'
    });
  }
});

// Get unread message count
app.get('/api/messages/unread-count', authenticateToken, async (req, res) => {
  try {
    // Get all conversations for the user
    const conversations = await Conversation.find({
      participants: req.user.id
    });
    
    const conversationIds = conversations.map(c => c._id);
    
    // Count unread messages (messages not from current user with status 'sent')
    const unreadCount = await Message.countDocuments({
      conversationId: { $in: conversationIds },
      senderId: { $ne: req.user.id },
      status: 'sent'
    });

    res.json({
      success: true,
      data: { unreadCount }
    });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch unread count'
    });
  }
});

// Add to your server.js in the API routes section
app.get('/api/user/schedule', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Fetch appointments for this user (provider)
    const appointments = await Job.find({ 
      providerId: userId,
      date: { $gte: new Date() } // Only future appointments
    })
    .sort({ date: 1, startTime: 1 })
    .populate('clientId', 'name phoneNumber address');
    
    // Format the response
    const formattedAppointments = appointments.map(appointment => ({
      id: appointment._id,
      title: appointment.serviceType,
      client: appointment.clientId?.name || 'Unknown Client',
      phone: appointment.clientId?.phoneNumber || 'No phone provided',
      location: appointment.location || appointment.clientId?.address || 'Location not specified',
      date: appointment.date.toISOString().split('T')[0],
      time: appointment.startTime,
      endTime: calculateEndTime(appointment.startTime, appointment.duration),
      duration: appointment.duration,
      payment: appointment.payment,
      status: appointment.status,
      notes: appointment.notes || '',
      category: appointment.category || 'other',
      priority: appointment.priority || 'medium'
    }));
    
    res.json({
      success: true,
      data: formattedAppointments
    });
  } catch (error) {
    console.error('Schedule API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch schedule data',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Helper function to calculate end time
function calculateEndTime(startTime, duration) {
  if (!startTime || !duration) return '';
  
  try {
    const [time, modifier] = startTime.split(' ');
    let [hours, minutes] = time.split(':').map(Number);
    
    if (modifier === 'PM' && hours !== 12) hours += 12;
    if (modifier === 'AM' && hours === 12) hours = 0;
    
    // Parse duration (e.g., "2 hours", "1.5 hours")
    const durationMatch = duration.match(/(\d+(\.\d+)?)\s*hours?/i);
    if (!durationMatch) return '';
    
    const durationHours = parseFloat(durationMatch[1]);
    const totalMinutes = hours * 60 + minutes + durationHours * 60;
    
    let endHours = Math.floor(totalMinutes / 60) % 24;
    const endMinutes = totalMinutes % 60;
    
    const endModifier = endHours >= 12 ? 'PM' : 'AM';
    if (endHours > 12) endHours -= 12;
    if (endHours === 0) endHours = 12;
    
    return `${endHours}:${endMinutes.toString().padStart(2, '0')} ${endModifier}`;
  } catch (error) {
    console.error('Error calculating end time:', error);
    return '';
  }
}


// Users endpoint
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const userType = req.query.userType;
    const country = req.query.country;
    const search = req.query.search;

    let filter = {};
    if (userType && userType !== 'all') {
      filter.userType = userType;
    }
    if (country && country !== 'all') {
      filter.country = country;
    }
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(filter, '-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalUsers = await User.countDocuments(filter);
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      success: true,
      data: {
        users,
        pagination: {
          currentPage: page,
          totalPages,
          totalUsers,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});
// Add to your server.js file

// Earnings endpoint
app.get('/api/earnings', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { period = 'month' } = req.query;
    
    // Get user to check currency preference
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Calculate date ranges based on period
    const now = new Date();
    let startDate, endDate;
    
    switch (period) {
      case 'week':
        startDate = new Date(now.setDate(now.getDate() - 7));
        endDate = new Date();
        break;
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        break;
      case 'quarter':
        const quarter = Math.floor(now.getMonth() / 3);
        startDate = new Date(now.getFullYear(), quarter * 3, 1);
        endDate = new Date(now.getFullYear(), (quarter + 1) * 3, 0);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        endDate = new Date(now.getFullYear(), 11, 31);
        break;
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    }

    // Calculate earnings data
    const completedJobs = await Job.countDocuments({ 
      providerId: userId, 
      status: 'completed',
      date: { $gte: startDate, $lte: endDate }
    });
    
    const totalEarningsResult = await Job.aggregate([
      { 
        $match: { 
          providerId: new mongoose.Types.ObjectId(userId), 
          status: 'completed',
          date: { $gte: startDate, $lte: endDate }
        } 
      },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
    const thisPeriodEarnings = totalEarningsResult.length > 0 ? totalEarningsResult[0].total : 0;
    
    // Calculate previous period for growth comparison
    let previousStartDate, previousEndDate;
    switch (period) {
      case 'week':
        previousStartDate = new Date(startDate);
        previousStartDate.setDate(previousStartDate.getDate() - 7);
        previousEndDate = new Date(startDate);
        break;
      case 'month':
        previousStartDate = new Date(startDate.getFullYear(), startDate.getMonth() - 1, 1);
        previousEndDate = new Date(startDate.getFullYear(), startDate.getMonth(), 0);
        break;
      case 'quarter':
        const prevQuarter = Math.floor((startDate.getMonth() - 3) / 3);
        previousStartDate = new Date(startDate.getFullYear(), prevQuarter * 3, 1);
        previousEndDate = new Date(startDate.getFullYear(), (prevQuarter + 1) * 3, 0);
        break;
      case 'year':
        previousStartDate = new Date(startDate.getFullYear() - 1, 0, 1);
        previousEndDate = new Date(startDate.getFullYear() - 1, 11, 31);
        break;
    }
    
    const previousEarningsResult = await Job.aggregate([
      { 
        $match: { 
          providerId: new mongoose.Types.ObjectId(userId), 
          status: 'completed',
          date: { $gte: previousStartDate, $lte: previousEndDate }
        } 
      },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
    const previousPeriodEarnings = previousEarningsResult.length > 0 ? previousEarningsResult[0].total : 0;
    const growth = previousPeriodEarnings > 0 
      ? ((thisPeriodEarnings - previousPeriodEarnings) / previousPeriodEarnings) * 100 
      : 0;
    
    const pendingEarningsResult = await Job.aggregate([
      { 
        $match: { 
          providerId: new mongoose.Types.ObjectId(userId), 
          status: 'pending' 
        } 
      },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
    const avgPerJobResult = await Job.aggregate([
      { 
        $match: { 
          providerId: new mongoose.Types.ObjectId(userId), 
          status: 'completed',
          date: { $gte: startDate, $lte: endDate }
        } 
      },
      { $group: { _id: null, average: { $avg: '$payment' } } }
    ]);
    
    // Get recent transactions
    const recentTransactions = await Job.find({ 
      providerId: userId,
      date: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
    })
    .sort({ date: -1 })
    .limit(10)
    .populate('clientId', 'name');
    
    // Get monthly data for the chart
    const monthlyData = await Job.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(userId),
          status: 'completed',
          date: { $gte: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000) } // Last 6 months
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$date' },
            month: { $month: '$date' }
          },
          total: { $sum: '$payment' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.year': 1, '_id.month': 1 } },
      { $limit: 7 }
    ]);
    
    // Format monthly data
    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const formattedMonthlyData = monthlyData.map((data, index, array) => {
      const month = monthNames[data._id.month - 1];
      const prevData = index > 0 ? array[index - 1].total : 0;
      const growth = prevData > 0 ? ((data.total - prevData) / prevData) * 100 : 0;
      
      return {
        month,
        amount: data.total,
        growth: Math.round(growth * 10) / 10
      };
    });
    
    // Format transactions
    const formattedTransactions = recentTransactions.map(transaction => ({
      id: transaction._id,
      client: transaction.clientId?.name || 'Unknown Client',
      service: transaction.serviceType,
      amount: transaction.payment,
      date: transaction.date.toISOString().split('T')[0],
      status: transaction.status,
      method: transaction.paymentMethod || 'Bank Transfer',
      category: transaction.category || 'other'
    }));
    
    // Prepare response
    const earningsData = {
      total: thisPeriodEarnings,
      thisWeek: period === 'week' ? thisPeriodEarnings : await calculatePeriodEarnings(userId, 'week'),
      thisMonth: period === 'month' ? thisPeriodEarnings : await calculatePeriodEarnings(userId, 'month'),
      thisQuarter: period === 'quarter' ? thisPeriodEarnings : await calculatePeriodEarnings(userId, 'quarter'),
      thisYear: period === 'year' ? thisPeriodEarnings : await calculatePeriodEarnings(userId, 'year'),
      lastMonth: previousPeriodEarnings,
      pending: pendingEarningsResult.length > 0 ? pendingEarningsResult[0].total : 0,
      growth: Math.round(growth * 10) / 10,
      avgPerJob: avgPerJobResult.length > 0 ? Math.round(avgPerJobResult[0].average) : 0,
      currency: user.currency || 'NGN'
    };
    
    res.json({
      success: true,
      data: {
        earnings: earningsData,
        transactions: formattedTransactions,
        monthlyData: formattedMonthlyData
      }
    });
  } catch (error) {
    console.error('Earnings API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch earnings data',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Helper function to calculate earnings for a specific period
async function calculatePeriodEarnings(userId, period) {
  const now = new Date();
  let startDate, endDate;
  
  switch (period) {
    case 'week':
      startDate = new Date(now.setDate(now.getDate() - 7));
      endDate = new Date();
      break;
    case 'month':
      startDate = new Date(now.getFullYear(), now.getMonth(), 1);
      endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      break;
    case 'quarter':
      const quarter = Math.floor(now.getMonth() / 3);
      startDate = new Date(now.getFullYear(), quarter * 3, 1);
      endDate = new Date(now.getFullYear(), (quarter + 1) * 3, 0);
      break;
    case 'year':
      startDate = new Date(now.getFullYear(), 0, 1);
      endDate = new Date(now.getFullYear(), 11, 31);
      break;
  }
  
  const result = await Job.aggregate([
    { 
      $match: { 
        providerId: new mongoose.Types.ObjectId(userId), 
        status: 'completed',
        date: { $gte: startDate, $lte: endDate }
      } 
    },
    { $group: { _id: null, total: { $sum: '$payment' } } }
  ]);
  
  return result.length > 0 ? result[0].total : 0;
}

// Export earnings data endpoint
app.get('/api/earnings/export', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { period = 'month' } = req.query;
    
    // Calculate date range based on period
    const now = new Date();
    let startDate, endDate;
    
    switch (period) {
      case 'week':
        startDate = new Date(now.setDate(now.getDate() - 7));
        endDate = new Date();
        break;
      case 'month':
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        break;
      case 'quarter':
        const quarter = Math.floor(now.getMonth() / 3);
        startDate = new Date(now.getFullYear(), quarter * 3, 1);
        endDate = new Date(now.getFullYear(), (quarter + 1) * 3, 0);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        endDate = new Date(now.getFullYear(), 11, 31);
        break;
    }
    
    // Get transactions for export
    const transactions = await Job.find({ 
      providerId: userId,
      date: { $gte: startDate, $lte: endDate }
    })
    .sort({ date: -1 })
    .populate('clientId', 'name');
    
    // Create CSV content
    const headers = ['Date', 'Client', 'Service', 'Amount (₦)', 'Status', 'Payment Method', 'Category'];
    const csvContent = [
      headers.join(','),
      ...transactions.map(transaction => [
        transaction.date.toISOString().split('T')[0],
        `"${transaction.clientId?.name || 'Unknown Client'}"`,
        `"${transaction.serviceType}"`,
        transaction.payment,
        transaction.status,
        transaction.paymentMethod || 'Bank Transfer',
        transaction.category || 'other'
      ].join(','))
    ].join('\n');
    
    // Set response headers for file download
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=earnings-${period}-${new Date().toISOString().split('T')[0]}.csv`);
    
    res.send(csvContent);
  } catch (error) {
    console.error('Export earnings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to export earnings data'
    });
  }
});
app.get('/api/debug/all-users', async (req, res) => {
  try {
    const users = await User.find({}).select('name email userType services city state country isActive isEmailVerified');
    console.log('📊 Total users in database:', users.length);
    
    res.json({
      success: true,
      total: users.length,
      users: users.map(user => ({
        id: user._id,
        name: user.name,
        email: user.email,
        userType: user.userType,
        services: user.services,
        location: `${user.city || 'No city'}, ${user.state || 'No state'}, ${user.country || 'No country'}`,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified
      }))
    });
  } catch (error) {
    console.error('Debug all users error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
// Enhanced providers endpoint with better location handling
// In your server.js file, update the /api/providers endpoint:
app.post('/api/debug/create-test-providers', async (req, res) => {
  try {
    // Delete existing test users first
    await User.deleteMany({ email: { $in: ['alex@example.com', 'sarah@test.com', 'mike@test.com', 'fatima@test.com'] } });
    
    const bcrypt = await import('bcryptjs');
    const hashedPassword = await bcrypt.hash('Password123', 10);
    
    const testProviders = [
      {
        name: 'Alex Johnson',
        email: 'alex@example.com',
        password: hashedPassword,
        userType: 'provider',
        country: 'Nigeria',
        state: 'Lagos',
        city: 'Lagos',
        address: 'Lagos, Lagos, Nigeria',
        isEmailVerified: true,
        emailVerificationToken: null,
        emailVerificationExpires: null,
        services: ['House Cleaning', 'Garden Maintenance'],
        hourlyRate: 2500,
        experience: '3 years',
        profileImage: '',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.8,
        reviewCount: 127,
        completedJobs: 234,
        isVerified: true,
        isTopRated: true,
        responseTime: 'within 30 minutes'
      },
      {
        name: 'Sarah Williams',
        email: 'sarah@test.com',
        password: hashedPassword,
        userType: 'provider',
        country: 'Nigeria',
        state: 'Lagos',
        city: 'Ikeja',
        address: 'Ikeja, Lagos, Nigeria',
        isEmailVerified: true,
        services: ['Plumbing', 'Electrical Work'],
        hourlyRate: 3500,
        experience: '5 years',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.6,
        reviewCount: 89,
        completedJobs: 156
      },
      {
        name: 'Mike Adebayo',
        email: 'mike@test.com',
        password: hashedPassword,
        userType: 'both', // This user is both customer and provider
        country: 'Nigeria',
        state: 'Abuja',
        city: 'Abuja',
        address: 'Abuja, Federal Capital Territory, Nigeria',
        isEmailVerified: true,
        services: ['Painting', 'Interior Design'],
        hourlyRate: 3000,
        experience: '4 years',
        isActive: true,
        isAvailableNow: false,
        averageRating: 4.7,
        reviewCount: 156
      },
      {
        name: 'Fatima Ibrahim',
        email: 'fatima@test.com',
        password: hashedPassword,
        userType: 'provider',
        country: 'Nigeria',
        state: 'Lagos',
        city: 'Ikeja',
        address: 'Ikeja, Lagos, Nigeria',
        isEmailVerified: true,
        services: ['Laundry', 'House Cleaning', 'Cooking'],
        hourlyRate: 2000,
        experience: '2 years',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.9,
        reviewCount: 203
      }
    ];
    
    const createdProviders = [];
    for (const providerData of testProviders) {
      const provider = new User(providerData);
      const saved = await provider.save();
      createdProviders.push(saved);
      console.log(`✅ Created test provider: ${saved.name} (${saved.email}) in ${saved.city}, ${saved.state}`);
    }
    
    res.json({
      success: true,
      message: `Created ${createdProviders.length} test providers`,
      providers: createdProviders.map(p => ({
        id: p._id,
        name: p.name,
        email: p.email,
        userType: p.userType,
        services: p.services,
        location: `${p.city}, ${p.state}, ${p.country}`,
        isAvailableNow: p.isAvailableNow
      }))
    });
  } catch (error) {
    console.error('Create test providers error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create test providers',
      error: error.message
    });
  }
});

app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const settings = user.getSettings();

    res.json({
      success: true,
      data: settings
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch settings'
    });
  }
});

app.put('/api/settings', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;

    const updatedUser = await User.updateUserSettings(req.user.id, updates);

    res.json({
      success: true,
      message: 'Settings updated successfully',
      data: updatedUser
    });
  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update settings',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.put('/api/settings/:section', authenticateToken, async (req, res) => {
  try {
    const { section } = req.params;
    const data = req.body;

    const updates = { [section]: data };
    const updatedUser = await User.updateUserSettings(req.user.id, updates);

    res.json({
      success: true,
      message: `${section.charAt(0).toUpperCase() + section.slice(1)} settings updated successfully`,
      data: updatedUser[section]
    });
  } catch (error) {
    console.error(`Update ${req.params.section} settings error:`, error);
    res.status(500).json({
      success: false,
      message: `Failed to update ${req.params.section} settings`
    });
  }
});



app.put('/api/settings/general', authenticateToken, async (req, res) => {
  try {
    const { language, timeZone, currency } = req.body;

    const updateData = {};
    if (language) updateData.language = language;
    if (timeZone) updateData.timeZone = timeZone;
    if (currency) updateData.currency = currency;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    ).select('language timeZone currency');

    res.json({
      success: true,
      message: 'General settings updated successfully',
      data: updatedUser
    });
  } catch (error) {
    console.error('Update general settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update general settings'
    });
  }
});

app.put('/api/settings/notifications', authenticateToken, async (req, res) => {
  try {
    const { email, push, sms, newJobs, messages, payments } = req.body;

    const notificationSettings = {
      email: email ?? true,
      push: push ?? true,
      sms: sms ?? false,
      newJobs: newJobs ?? true,
      messages: messages ?? true,
      payments: payments ?? true
    };

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { notificationSettings },
      { new: true }
    ).select('notificationSettings');

    res.json({
      success: true,
      message: 'Notification settings updated successfully',
      data: updatedUser.notificationSettings
    });
  } catch (error) {
    console.error('Update notification settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update notification settings'
    });
  }
});

app.put('/api/settings/security', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword, enableTwoFactor } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const updateData = {};
    let message = 'Security settings updated successfully';

    // Handle password change
    if (currentPassword && newPassword) {
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isCurrentPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'Current password is incorrect'
        });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      updateData.password = hashedNewPassword;
      updateData.lastPasswordChange = new Date();
      message = 'Password updated successfully';
    }

    // Handle two-factor authentication
    if (enableTwoFactor !== undefined) {
      updateData.twoFactorEnabled = enableTwoFactor;
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true }
    ).select('twoFactorEnabled lastPasswordChange');

    res.json({
      success: true,
      message,
      data: updatedUser
    });
  } catch (error) {
    console.error('Update security settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update security settings'
    });
  }
});


app.put('/api/settings/account', authenticateToken, async (req, res) => {
  try {
    const { name, phoneNumber, address, city, state, country } = req.body;

    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phoneNumber !== undefined) updateData.phoneNumber = phoneNumber;
    if (address !== undefined) updateData.address = address;
    if (city !== undefined) updateData.city = city;
    if (state !== undefined) updateData.state = state;
    if (country !== undefined) updateData.country = country;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true, runValidators: true }
    ).select('name email phoneNumber address city state country profileImage');

    res.json({
      success: true,
      message: 'Account information updated successfully',
      data: updatedUser
    });
  } catch (error) {
    console.error('Update account settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update account information'
    });
  }
});


app.put('/api/settings/payment', authenticateToken, async (req, res) => {
  try {
    const { payoutSchedule, currency, bankAccount } = req.body;

    const updateData = {};
    if (payoutSchedule) updateData.payoutSchedule = payoutSchedule;
    if (currency) updateData.currency = currency;
    
    // In a real app, you'd want to encrypt bank account info
    if (bankAccount) {
      updateData.bankAccount = {
        ...bankAccount,
        lastFour: bankAccount.accountNumber ? bankAccount.accountNumber.slice(-4) : ''
      };
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true }
    ).select('payoutSchedule currency bankAccount');

    res.json({
      success: true,
      message: 'Payment settings updated successfully',
      data: updatedUser
    });
  } catch (error) {
    console.error('Update payment settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update payment settings'
    });
  }
});

// Delete account
app.delete('/api/settings/account', authenticateToken, async (req, res) => {
  try {
    const { confirmation } = req.body;

    if (confirmation !== 'DELETE MY ACCOUNT') {
      return res.status(400).json({
        success: false,
        message: 'Please type "DELETE MY ACCOUNT" to confirm account deletion'
      });
    }

    const user = await User.findByIdAndDelete(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Clean up related data (bookings, service requests, etc.)
    await Booking.deleteMany({ 
      $or: [
        { customerId: req.user.id },
        { providerId: req.user.id }
      ]
    });

    await ServiceRequest.deleteMany({
      $or: [
        { customerId: req.user.id },
        { providerId: req.user.id }
      ]
    });

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete account'
    });
  }
});



app.get('/api/providers', async (req, res) => {
  try {
    const { 
      service, 
      location, 
      availableNow, 
      page = 1,
      limit = 50
    } = req.query;
    
    console.log('📥 Provider query params:', { service, location, availableNow });

    console.log('📥 Provider query params:', { 
      service: service || 'none', 
      location: location || 'none', 
      availableNow: availableNow || 'false' 
    });
    
    let currentUserId = null;
    try {
      const authHeader = req.headers['authorization'];
      if (authHeader) {
        const token = authHeader.split(' ')[1];
        if (token) {
          const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production');
          currentUserId = decoded.id;
          console.log('👤 Current user ID:', currentUserId);
        }
      }
    } catch (tokenError) {
      console.log('🔐 No valid auth token or token error, not excluding any users');
    }

    // Build main query - FIXED SERVICE FILTER
    const mainQuery = {
      userType: { $in: ['provider', 'both'] },
      isActive: true
    };

    // Exclude current user if authenticated
    if (currentUserId) {
  mainQuery._id = { $ne: new mongoose.Types.ObjectId(currentUserId) };
}

    // FIXED: Service filter - use regex instead of empty object
    if (service && service.trim() !== '' && service !== 'all') {
      mainQuery.services = { 
        $in: [new RegExp(service, 'i')] 
      };
      console.log('🔍 Added service filter:', service);
    } else {
      console.log('🔧 No service filter applied');
    }

    // Build location filters if provided - FIXED: Use partial matches
    const locationFilters = [];
    if (location && location.trim() !== '' && location !== 'all') {
      const locationLower = location.toLowerCase().trim();
      const mainLocationTerm = locationLower.split(',')[0].trim();
      
      console.log('🔍 Location filter:', locationLower);
      console.log('🔍 Main location term:', mainLocationTerm);
      
      // FIXED: Use partial matches instead of exact matches
      locationFilters.push({
        $or: [
          { city: { $regex: mainLocationTerm, $options: 'i' } },
          { state: { $regex: mainLocationTerm, $options: 'i' } },
          { country: { $regex: mainLocationTerm, $options: 'i' } },
          { address: { $regex: mainLocationTerm, $options: 'i' } }
        ]
      });
    } else {
      console.log('🌍 No location filter applied');
    }

    // Build availability filters if provided
    const availabilityFilters = [];
    if (availableNow === 'true') {
      availabilityFilters.push({
        $or: [
          { isAvailableNow: true },
          { isAvailableNow: { $exists: false } },
          { isAvailableNow: null }
        ]
      });
      console.log('🔍 Added availability filter: now');
    } else {
      console.log('⏰ No availability filter applied');
    }

    // Combine all filters
    const allFilters = [...locationFilters, ...availabilityFilters];

    if (allFilters.length > 0) {
      if (allFilters.length === 1) {
        // If only one filter type, add it directly to mainQuery
        Object.assign(mainQuery, allFilters[0]);
      } else {
        // If multiple filter types, combine with $and
        mainQuery.$and = allFilters;
      }
    }

    console.log('📋 Final MongoDB query:', JSON.stringify(mainQuery, null, 2));

    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Get providers with the query
    const providers = await User.find(mainQuery)
      .select('name email services hourlyRate averageRating city state country profileImage isAvailableNow experience phoneNumber address reviewCount completedJobs isVerified isTopRated responseTime rating _id')
      .skip(skip)
      .limit(parseInt(limit));

    const totalProviders = await User.countDocuments(mainQuery);

    console.log('✅ Providers found with query:', providers.length);
    console.log('📊 Providers details:', providers.map(p => ({
      name: p.name,
      email: p.email,
      services: p.services && p.services.length > 0 ? p.services : ['No services'],
      city: p.city || 'No city',
      state: p.state || 'No state', 
      country: p.country || 'No country',
      address: p.address || 'No address',
      isAvailableNow: p.isAvailableNow
    })));

    // Calculate match scores and sort providers
    const scoredProviders = providers.map((provider) => {
      let score = 50; // Base score for all providers
      
      // Service match scoring
      if (service && service.trim() !== '') {
        const serviceLower = service.toLowerCase();
        const providerServices = Array.isArray(provider.services) ? provider.services : [];
        
        if (providerServices.length === 0) {
          score += 5;
        } else {
          if (providerServices.some(s => s.toLowerCase() === serviceLower)) {
            score += 100;
          }
          else if (providerServices.some(s => s.toLowerCase().includes(serviceLower))) {
            score += 50;
          }
          else {
            score += 10;
          }
        }
      } else if (Array.isArray(provider.services) && provider.services.length > 0) {
        score += 15;
      }
      
      // Location match scoring
      if (location && location.trim() !== '') {
        const locationLower = location.toLowerCase().trim();
        const mainLocationTerm = locationLower.split(',')[0].trim();
        
        const providerAddress = (provider.address || '').toLowerCase();
        const providerCity = (provider.city || '').toLowerCase();
        const providerState = (provider.state || '').toLowerCase();
        const providerCountry = (provider.country || '').toLowerCase();
        
        // Check for exact matches
        if (providerCity === mainLocationTerm) score += 100;
        else if (providerState === mainLocationTerm) score += 90;
        else if (providerCountry === mainLocationTerm) score += 80;
        // Check for partial matches
        else if (providerCity.includes(mainLocationTerm)) score += 70;
        else if (providerState.includes(mainLocationTerm)) score += 60;
        else if (providerCountry.includes(mainLocationTerm)) score += 50;
        else if (providerAddress.includes(mainLocationTerm)) score += 40;
      }
      
      // Availability scoring
      if (availableNow === 'true') {
        if (provider.isAvailableNow === true) {
          score += 60;
        } else if (provider.isAvailableNow === undefined || provider.isAvailableNow === null) {
          score += 20;
        }
      }
      
      // Rating scoring
      const rating = provider.averageRating || provider.rating || 4.0;
      score += rating * 10;
      
      // Verified providers get bonus
      if (provider.isVerified) {
        score += 25;
      }
      
      // Top-rated providers get bonus
      if (provider.isTopRated) {
        score += 35;
      }
      
      // More reviews indicate more experience
      const reviewCount = provider.reviewCount || 0;
      score += Math.min(reviewCount / 10, 20);
      
      return {
        ...provider.toObject(),
        _matchScore: score
      };
    });
    
    // Sort by match score (highest first), then by rating, then by review count
    scoredProviders.sort((a, b) => {
      if (b._matchScore !== a._matchScore) {
        return b._matchScore - a._matchScore;
      }
      
      const ratingA = a.averageRating || a.rating || 4.0;
      const ratingB = b.averageRating || b.rating || 4.0;
      if (ratingB !== ratingA) {
        return ratingB - ratingA;
      }
      
      const reviewsA = a.reviewCount || 0;
      const reviewsB = b.reviewCount || 0;
      return reviewsB - reviewsA;
    });
    
    // Transform providers to ensure consistent format
    const transformedProviders = scoredProviders.map((provider) => {
      // Ensure services is always an array
      let services = [];
      if (Array.isArray(provider.services)) {
        services = provider.services;
      } else if (typeof provider.services === 'string') {
        services = [provider.services];
      }
      
      // Create a formatted location string for display
      const locationParts = [
        provider.city,
        provider.state,
        provider.country
      ].filter(part => part && part.trim() !== '');
      
      const locationText = locationParts.join(', ') || 'Location not specified';
      
      return {
        ...provider,
        _matchScore: undefined, // Remove from final output
        services: services,
        location: locationText,
        averageRating: provider.averageRating || provider.rating || 4.0,
        reviewCount: provider.reviewCount || 0,
        completedJobs: provider.completedJobs || 0,
        isVerified: provider.isVerified !== undefined ? provider.isVerified : false,
        isTopRated: provider.isTopRated !== undefined ? provider.isTopRated : false,
        isAvailableNow: provider.isAvailableNow !== undefined ? provider.isAvailableNow : true,
        responseTime: provider.responseTime || 'within 1 hour',
        hourlyRate: provider.hourlyRate || 0
      };
    });
    
    console.log('📍 Search location was:', location);
    console.log('🔧 Search service was:', service);
    console.log('⏰ Available now filter:', availableNow);
    console.log('🏆 All providers count:', transformedProviders.length);
    
    res.json({
      success: true,
      data: {
        providers: transformedProviders,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalProviders / parseInt(limit)),
          totalProviders,
          hasNextPage: parseInt(page) < Math.ceil(totalProviders / parseInt(limit)),
          hasPrevPage: parseInt(page) > 1,
          limit: parseInt(limit)
        }
      }
    });
    
  } catch (error) {
    console.error('❌ Error fetching providers:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch providers',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


app.get('/api/debug/providers-error', async (req, res) => {
  try {
    // Test the exact same logic but with proper error handling
    const { service, location, availableNow } = req.query;
    
    console.log('Testing providers query with:', { service, location, availableNow });
    
    // Initialize query properly
    let query = {
      userType: { $in: ['provider', 'both'] },
      isActive: true
    };
    
    // Test service filter
    if (service && service.trim() !== '' && service !== 'all') {
      query.services = { 
        $in: [new RegExp(service, 'i')] 
      };
      console.log('Service filter applied:', query.services);
    }
    
    // Test location filter  
    if (location && location.trim() !== '' && location !== 'all') {
      const locationLower = location.toLowerCase().trim();
      query.$or = [
        { city: { $regex: locationLower, $options: 'i' } },
        { state: { $regex: locationLower, $options: 'i' } },
        { country: { $regex: locationLower, $options: 'i' } },
        { address: { $regex: locationLower, $options: 'i' } }
      ];
      console.log('Location filter applied:', query.$or);
    }
    
    // Test availability filter
    if (availableNow === 'true') {
      query.$or = query.$or || [];
      query.$or.push({
        $or: [
          { isAvailableNow: true },
          { isAvailableNow: { $exists: false } },
          { isAvailableNow: null }
        ]
      });
      console.log('Availability filter applied');
    }
    
    console.log('Final query:', JSON.stringify(query, null, 2));
    
    const results = await User.find(query).limit(5);
    
    res.json({
      success: true,
      query: query,
      results: results.map(r => ({
        name: r.name,
        services: r.services,
        location: `${r.city}, ${r.state}, ${r.country}`,
        isAvailableNow: r.isAvailableNow
      }))
    });
    
  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      stack: error.stack 
    });
  }
});


app.post('/api/debug/cleanup-bad-providers', async (req, res) => {
  try {
    // Delete providers with incomplete or incorrect location data
    const result = await User.deleteMany({
      $or: [
        { name: { $in: ['Peter vjj', 'Suf', 'ogundiran tosin', 'Jamie Fabrinnzo', 'Rebecca popoola', 'rebecca popoola'] } },
        { city: { $in: ['No city', '', null] } },
        { state: { $in: ['No state', '', null] } },
        { country: { $in: ['No country', '', null] } }
      ]
    });
    
    res.json({
      success: true,
      message: `Deleted ${result.deletedCount} providers with bad location data`
    });
  } catch (error) {
    console.error('Cleanup bad providers error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cleanup bad providers',
      error: error.message
    });
  }
});


app.post('/api/debug/setup-test-data', async (req, res) => {
  try {
    console.log('🧹 Cleaning up existing test data...');
    
    // Delete all existing test users
    await User.deleteMany({
      $or: [
        { email: { $in: ['alex@example.com', 'sarah@test.com', 'mike@test.com', 'fatima@test.com'] } },
        { name: { $in: ['Alex Johnson', 'Sarah Williams', 'Mike Adebayo', 'Fatima Ibrahim'] } }
      ]
    });
    
    console.log('✅ Existing test data cleaned up');
    
    const bcrypt = await import('bcryptjs');
    const hashedPassword = await bcrypt.hash('Password123', 10);
    
    // Create test providers with proper location data
    const testProviders = [
      {
        name: 'Alex Johnson',
        email: 'alex@example.com',
        password: hashedPassword,
        userType: 'provider',
        country: 'Nigeria',
        state: 'Lagos',
        city: 'Lagos',
        address: 'Victoria Island, Lagos, Nigeria',
        isEmailVerified: true,
        services: ['House Cleaning', 'Garden Maintenance'],
        hourlyRate: 2500,
        experience: '3 years',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.8,
        reviewCount: 127,
        completedJobs: 234
      },
      {
        name: 'Sarah Williams',
        email: 'sarah@test.com',
        password: hashedPassword,
        userType: 'provider',
        country: 'Nigeria',
        state: 'Lagos',
        city: 'Ikeja',
        address: 'Ikeja, Lagos, Nigeria',
        isEmailVerified: true,
        services: ['Plumbing', 'Electrical Work'],
        hourlyRate: 3500,
        experience: '5 years',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.6,
        reviewCount: 89,
        completedJobs: 156
      },
      {
        name: 'Mike Adebayo',
        email: 'mike@test.com',
        password: hashedPassword,
        userType: 'both',
        country: 'Nigeria',
        state: 'Abuja',
        city: 'Abuja',
        address: 'Garki, Abuja, Nigeria',
        isEmailVerified: true,
        services: ['Painting', 'Interior Design'],
        hourlyRate: 3000,
        experience: '4 years',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.7,
        reviewCount: 156,
        completedJobs: 89
      },
      {
        name: 'Fatima Ibrahim',
        email: 'fatima@test.com',
        password: hashedPassword,
        userType: 'provider',
        country: 'Nigeria',
        state: 'Abuja',
        city: 'Abuja',
        address: 'Wuse, Abuja, Nigeria',
        isEmailVerified: true,
        services: ['Laundry', 'House Cleaning', 'Cooking'],
        hourlyRate: 2000,
        experience: '2 years',
        isActive: true,
        isAvailableNow: true,
        averageRating: 4.9,
        reviewCount: 203,
        completedJobs: 145
      }
    ];
    
    const createdProviders = [];
    for (const providerData of testProviders) {
      const provider = new User(providerData);
      const saved = await provider.save();
      createdProviders.push(saved);
      console.log(`✅ Created provider: ${saved.name} in ${saved.city}, ${saved.state}`);
    }
    
    // Also clean up the problematic providers that don't have proper locations
    await User.deleteMany({
      name: { 
        $in: [
          'Peter vjj', 
          'Suf', 
          'ogundiran tosin', 
          'Jamie Fabrinnzo', 
          'Rebecca popoola',
          'rebecca popoola'
        ] 
      }
    });
    
    console.log('🧹 Cleaned up providers with incomplete location data');
    
    res.json({
      success: true,
      message: `Created ${createdProviders.length} test providers with proper location data`,
      providers: createdProviders.map(p => ({
        id: p._id,
        name: p.name,
        email: p.email,
        location: `${p.city}, ${p.state}, ${p.country}`,
        services: p.services,
        isAvailableNow: p.isAvailableNow
      }))
    });
    
  } catch (error) {
    console.error('Setup test data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to setup test data',
      error: error.message
    });
  }
});


app.post('/api/debug/fix-availability', async (req, res) => {
  try {
    // Update all providers to have isAvailableNow set to true
    const result = await User.updateMany(
      { 
        userType: { $in: ['provider', 'both'] },
        isActive: true 
      },
      { 
        $set: { 
          isAvailableNow: true,
          responseTime: 'within 1 hour',
          reviewCount: 0,
          completedJobs: 0,
          isVerified: false,
          isTopRated: false,
          rating: 4.0
        }
      }
    );
    
    res.json({
      success: true,
      message: `Updated ${result.modifiedCount} providers with default availability settings`
    });
  } catch (error) {
    console.error('Fix availability error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update provider availability',
      error: error.message
    });
  }
});

// Simple test endpoint to fix availability from browser
app.get('/api/debug/fix-availability-now', async (req, res) => {
  try {
    // Update all providers to have isAvailableNow set to true
    const result = await User.updateMany(
      { 
        userType: { $in: ['provider', 'both'] },
        isActive: true 
      },
      { 
        $set: { 
          isAvailableNow: true,
          responseTime: 'within 1 hour',
          reviewCount: 0,
          completedJobs: 0,
          isVerified: false,
          isTopRated: false,
          rating: 4.0
        }
      }
    );
    
    res.json({
      success: true,
      message: `Updated ${result.modifiedCount} providers with default availability settings`
    });
  } catch (error) {
    console.error('Fix availability error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update provider availability',
      error: error.message
    });
  }
});


app.get('/api/debug/all-providers', async (req, res) => {
  try {
    const providers = await User.find({
      userType: { $in: ['provider', 'both'] },
      isActive: true
    }).select('name services city state country isAvailableNow');
    
    res.json({
      success: true,
      count: providers.length,
      providers: providers
    });
  } catch (error) {
    console.error('Debug providers error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/debug/fix-location-data', async (req, res) => {
  try {
    // Update providers with missing location data
    const updates = await User.updateMany(
      {
        userType: { $in: ['provider', 'both'] },
        $or: [
          { city: { $in: [null, '', 'No city'] } },
          { state: { $in: [null, '', 'No state'] } },
          { country: { $in: [null, '', 'No country'] } }
        ]
      },
      {
        $set: {
          city: 'Lagos',
          state: 'Lagos',
          country: 'Nigeria'
        }
      }
    );
    
    res.json({
      success: true,
      message: `Updated ${updates.modifiedCount} providers with location data`
    });
  } catch (error) {
    console.error('Fix location data error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});
app.get('/api/debug/all-providers-with-details', async (req, res) => {
  try {
    const allProviders = await User.find({
      userType: { $in: ['provider', 'both'] },
      isActive: true
    }).select('name email userType services city state country isAvailableNow isActive');
    
    let currentUserId = null;
    try {
      const authHeader = req.headers['authorization'];
      if (authHeader) {
        const token = authHeader.split(' ')[1];
        if (token) {
          const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production');
          currentUserId = decoded.id;
        }
      }
    } catch (tokenError) {
      console.log('No auth token for debug');
    }
    
    res.json({
      success: true,
      currentUserId,
      totalCount: allProviders.length,
      providers: allProviders.map(p => ({
        id: p._id,
        name: p.name,
        email: p.email,
        userType: p.userType,
        services: p.services,
        location: `${p.city || 'No city'}, ${p.state || 'No state'}, ${p.country || 'No country'}`,
        isAvailableNow: p.isAvailableNow,
        isActive: p.isActive,
        isCurrentUser: currentUserId ? p._id.toString() === currentUserId : false
      }))
    });
  } catch (error) {
    console.error('Debug all providers error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug endpoint to test the exact query
app.get('/api/debug/test-no-filters', async (req, res) => {
  try {
    const query = {
      userType: { $in: ['provider', 'both'] },
      isActive: true,
      _id: { $ne: new mongoose.Types.ObjectId('68af7817cf6c6c9eefd5476e') } // Your current user ID
    };
    
    console.log('Testing query with no filters:', JSON.stringify(query, null, 2));
    
    const results = await User.find(query);
    
    res.json({
      success: true,
      query: query,
      resultsCount: results.length,
      results: results.map(r => ({
        name: r.name,
        email: r.email,
        userType: r.userType,
        services: r.services,
        isAvailableNow: r.isAvailableNow,
        isActive: r.isActive
      }))
    });
  } catch (error) {
    console.error('Test no filters error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


app.get('/api/debug/current-user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    res.json({
      success: true,
      currentUser: {
        id: user._id,
        name: user.name,
        email: user.email,
        userType: user.userType
      },
      allProviders: await User.find({ 
        userType: { $in: ['provider', 'both'] },
        isActive: true 
      }).select('name email userType')
    });
  } catch (error) {
    console.error('Debug current user error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/debug/providers-detailed', async (req, res) => {
  try {
    console.log('🔍 Debug: Fetching all providers with detailed info');
    
    const providers = await User.find({ 
      userType: { $in: ['provider', 'both'] },
      isActive: true 
    }).select('name email userType services city state country isActive isAvailableNow');
    
    console.log('📊 MongoDB providers count:', providers.length);
    console.log('📋 Providers:', providers.map(p => ({
      name: p.name,
      email: p.email,
      userType: p.userType,
      services: p.services,
      servicesCount: p.services.length,
      location: `${p.city}, ${p.state}, ${p.country}`,
      isActive: p.isActive,
      isAvailableNow: p.isAvailableNow
    })));
    
    res.json({
      success: true,
      count: providers.length,
      providers: providers
    });
  } catch (error) {
    console.error('❌ Detailed debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


app.post('/api/debug/update-provider-fields', async (req, res) => {
  try {
    // Update all providers to have the required fields
    const result = await User.updateMany(
      { userType: { $in: ['provider', 'both'] } },
      { 
        $set: { 
          isAvailableNow: true,
          responseTime: 'within 1 hour',
          reviewCount: { $ifNull: ['$reviewCount', Math.floor(Math.random() * 100) + 10] },
          completedJobs: 0, // CHANGED: Set all completed jobs to 0
          isVerified: { $ifNull: ['$isVerified', Math.random() > 0.3] },
          isTopRated: { $ifNull: ['$isTopRated', Math.random() > 0.7] },
          rating: { $ifNull: ['$rating', { $ifNull: ['$averageRating', 4 + Math.random()] }] }
        }
      }
    );
    
    res.json({
      success: true,
      message: `Updated ${result.modifiedCount} providers with default fields`
    });
  } catch (error) {
    console.error('Update provider fields error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update provider fields',
      error: error.message
    });
  }
});

app.get('/api/debug/providers', async (req, res) => {
  try {
    console.log('🔍 Debug: Fetching all providers from MongoDB');
    
    const providers = await User.find({ 
      userType: { $in: ['provider', 'both'] },
      isActive: true 
    }).select('name email userType services city state country isActive');
    
    console.log('📊 MongoDB providers count:', providers.length);
    console.log('📋 Providers:', providers.map(p => ({
      name: p.name,
      email: p.email,
      userType: p.userType,
      services: p.services,
      location: `${p.city}, ${p.state}, ${p.country}`,
      isActive: p.isActive
    })));
    
    res.json({
      success: true,
      count: providers.length,
      providers: providers
    });
  } catch (error) {
    console.error('❌ Debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});




app.get('/api/services', async (req, res) => {
  try {
    const { q } = req.query;
    
    // Get unique services from providers
    const services = await User.aggregate([
      { 
        $match: { 
          userType: { $in: ['provider', 'both'] },
          services: { $exists: true, $ne: [] }
        } 
      },
      { $unwind: '$services' },
      { $group: { _id: '$services' } },
      { $sort: { _id: 1 } }
    ]);

    const serviceNames = services.map(s => s._id);
    
    // Filter by search query if provided
    let filteredServices = serviceNames;
    if (q) {
      filteredServices = serviceNames.filter(service => 
        service.toLowerCase().includes(q.toLowerCase())
      );
    }

    res.json({
      success: true,
      data: { services: filteredServices }
    });
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch services',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/service-requests/search', async (req, res) => {
  try {
    const { location, radius, available } = req.query;
    
    let filter = { status: 'pending' };
    
    // Filter by location
    if (location) {
      filter.$or = [
        { location: { $regex: location, $options: 'i' } },
        { 'customerId.location': { $regex: location, $options: 'i' } }
      ];
    }
    
    // Filter by availability
    if (available === 'true') {
      filter.urgency = { $in: ['urgent', 'high'] };
    }
    
    const requests = await ServiceRequest.find(filter)
      .populate('customerId', 'name email phoneNumber location')
      .sort({ createdAt: -1 })
      .limit(20);

    res.json({
      success: true,
      data: { requests }
    });
  } catch (error) {
    console.error('Error searching service requests:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search service requests',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Providers/search endpoint
app.get('/api/service-requests', async (req, res) => {
  const { q, location, radius, available } = req.query;
  // Implement your provider search logic
  res.json({ data: [] }); // Return your providers data
});


// Booking endpoint
app.post('/api/bookings', authenticateToken, async (req, res) => {
  try {
    const {
      providerId,
      providerName,
      providerEmail,
      serviceType,
      description,
      location,
      timeframe,
      budget,
      contactInfo,
      specialRequests,
      bookingType
    } = req.body;

    // Validate required fields
    if (!providerId || !serviceType || !location || !contactInfo) {
      return res.status(400).json({
        success: false,
        message: 'Provider ID, service type, location, and contact info are required'
      });
    }

    // Create new booking
    const newBooking = new Booking({
      providerId,
      providerName: providerName || 'Unknown Provider',
      providerEmail: providerEmail || '',
      customerId: req.user.id,
      customerName: contactInfo.name || 'Unknown Customer',
      customerEmail: contactInfo.email || '',
      customerPhone: contactInfo.phone || '',
      serviceType,
      description: description || '',
      location,
      timeframe: timeframe || 'Flexible',
      budget: budget || 'Not specified',
      specialRequests: specialRequests || '',
      bookingType: bookingType || 'immediate',
      status: 'pending',
      requestedAt: new Date()
    });

    const savedBooking = await newBooking.save();

    // Populate customer and provider info
    await savedBooking.populate('customerId', 'name email phoneNumber');
    await savedBooking.populate('providerId', 'name email phoneNumber');

    // Send notification to provider (you can implement email/notification service here)
    console.log(`New booking created for provider: ${providerId}`);
    if (process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
      try {
        const providerUser = await User.findById(providerId);
        if (providerUser && providerUser.email) {
          await sendBookingNotification({
            serviceType,
            description,
            location,
            timeframe,
            budget,
            contactInfo,
            specialRequests
          }, providerUser.email);
        }
      } catch (emailError) {
        console.error('Failed to send booking notification email:', emailError);
        // Don't fail the booking if email fails
      }
    }

    await Notification.createNotification({
      userId: providerId,
      type: 'booking',
      title: 'New Booking Request',
      message: `You have a new booking request for ${serviceType}`,
      relatedId: savedBooking._id,
      relatedType: 'booking',
      priority: 'high'
    });


    res.status(201).json({
      success: true,
      message: 'Booking request sent successfully',
      data: savedBooking
    });
  } catch (error) {
    console.error('Create booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create booking',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get bookings for a provider
app.get('/api/bookings/provider', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;

    let filter = { providerId: req.user.id };
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { requestedAt: -1 },
      populate: { path: 'customerId', select: 'name email phoneNumber profileImage' }
    };

    const result = await Booking.paginate(filter, options);

    res.json({
      success: true,
      data: {
        bookings: result.docs,
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
    console.error('Get provider bookings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bookings'
    });
  }
});

app.post('/api/schedule', authenticateToken, async (req, res) => {
  try {
    const scheduleData = req.body;
    
    // Save to your database (adjust based on your schema)
    const newScheduleEntry = new Schedule(scheduleData);
    await newScheduleEntry.save();
    
    res.json({
      success: true,
      message: 'Booking added to schedule successfully',
      data: newScheduleEntry
    });
  } catch (error) {
    console.error('Add to schedule error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add booking to schedule'
    });
  }
});


// Get bookings for a customer
app.get('/api/bookings/customer', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;

    let filter = { customerId: req.user.id };
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { requestedAt: -1 },
      populate: { 
        path: 'providerId', 
        select: 'name email phoneNumber profileImage' 
      }
    };

    const result = await Booking.paginate(filter, options);

    res.json({
      success: true,
      data: {
        bookings: result.docs,
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
    console.error('Get customer bookings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bookings'
    });
  }
});


// Update booking status
// Update booking status and add to schedule when confirmed
app.patch('/api/bookings/:id/status', authenticateToken, async (req, res) => {
  try {
    let { status } = req.body;
    const bookingId = req.params.id;

    console.log('🔧 Updating booking status:', { 
      bookingId, 
      status, 
      userId: req.user.id 
    });

    // Enhanced status mapping with validation
    const statusMapping = {
      'pending': 'pending',
      'accepted': 'confirmed',
      'confirmed': 'confirmed',
      'completed': 'completed',
      'cancelled': 'cancelled',
      'rejected': 'cancelled'
    };

    const backendStatus = statusMapping[status?.toLowerCase()];
    
    if (!backendStatus) {
      return res.status(400).json({
        success: false,
        message: `Invalid status: ${status}. Must be one of: ${Object.keys(statusMapping).join(', ')}`
      });
    }

    // Find and update the booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check authorization
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this booking'
      });
    }

    const oldStatus = booking.status;
    booking.status = backendStatus;
    booking.updatedAt = new Date();

    // Set timestamps based on status changes
    if (backendStatus === 'confirmed' && oldStatus !== 'confirmed') {
      booking.acceptedAt = new Date();
    } else if (backendStatus === 'completed' && oldStatus !== 'completed') {
      booking.completedAt = new Date();
    }

    const updatedBooking = await booking.save();
    
    // Populate for response
    await updatedBooking.populate('customerId', 'name email phoneNumber');
    await updatedBooking.populate('providerId', 'name email phoneNumber');

    // Map response back to frontend
    const responseStatusMapping = {
      'pending': 'pending',
      'confirmed': 'accepted',
      'completed': 'completed',
      'cancelled': 'cancelled'
    };

    const frontendStatus = responseStatusMapping[updatedBooking.status] || updatedBooking.status;

    res.json({
      success: true,
      message: `Booking ${frontendStatus} successfully`,
      data: {
        ...updatedBooking.toObject(),
        status: frontendStatus
      }
    });

  } catch (error) {
    console.error('❌ Update booking status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update booking status',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.patch('/api/debug/test-booking-status/:id', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    const bookingId = req.params.id;

    console.log('🧪 Testing booking status:', { bookingId, status });

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    // Test different status values
    const testStatuses = ['pending', 'confirmed', 'accepted', 'completed', 'cancelled'];
    
    const results = [];
    for (const testStatus of testStatuses) {
      try {
        booking.status = testStatus;
        await booking.save();
        results.push({ status: testStatus, success: true });
        console.log(`✅ ${testStatus}: SUCCESS`);
      } catch (error) {
        results.push({ status: testStatus, success: false, error: error.message });
        console.log(`❌ ${testStatus}: FAILED - ${error.message}`);
      }
    }

    res.json({
      success: true,
      message: 'Status test completed',
      results
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});



async function addBookingToSchedule(booking) {
  try {
    const Schedule = mongoose.model('Schedule');
    
    // Calculate end time
    const calculateEndTime = (startTime, serviceType) => {
      const [time, modifier] = startTime.split(' ');
      let [hours, minutes] = time.split(':').map(Number);
      
      if (modifier === 'PM' && hours !== 12) hours += 12;
      if (modifier === 'AM' && hours === 12) hours = 0;
      
      let durationHours = 2; // default
      if (serviceType.includes('Cleaning')) durationHours = 3;
      if (serviceType.includes('Maintenance')) durationHours = 4;
      
      const totalMinutes = hours * 60 + minutes + durationHours * 60;
      let endHours = Math.floor(totalMinutes / 60) % 24;
      const endMinutes = totalMinutes % 60;
      
      const endModifier = endHours >= 12 ? 'PM' : 'AM';
      if (endHours > 12) endHours -= 12;
      if (endHours === 0) endHours = 12;
      
      return `${endHours}:${endMinutes.toString().padStart(2, '0')} ${endModifier}`;
    };

    // Parse timeframe to get date
    let scheduleDate = new Date();
    let scheduleTime = '10:00 AM';
    
    if (booking.timeframe.toLowerCase().includes('tomorrow')) {
      scheduleDate.setDate(scheduleDate.getDate() + 1);
    } else if (booking.timeframe.toLowerCase().includes('next week')) {
      scheduleDate.setDate(scheduleDate.getDate() + 7);
    }

    const scheduleData = {
      title: booking.serviceType,
      client: booking.customerName,
      phone: booking.customerPhone,
      location: booking.location,
      date: scheduleDate.toISOString().split('T')[0],
      time: scheduleTime,
      endTime: calculateEndTime(scheduleTime, booking.serviceType),
      duration: '2 hours',
      payment: booking.budget,
      status: 'confirmed',
      notes: booking.specialRequests || booking.description,
      category: booking.serviceType.toLowerCase().includes('clean') ? 'cleaning' : 'handyman',
      priority: 'medium',
      providerId: booking.providerId,
      customerId: booking.customerId,
      bookingId: booking._id
    };

    const newSchedule = new Schedule(scheduleData);
    await newSchedule.save();
    
    return newSchedule;
  } catch (error) {
    console.error('Error in addBookingToSchedule:', error);
    throw error;
  }
}

// Test endpoint - add to server.js
app.get('/api/test-booking-update', authenticateToken, async (req, res) => {
  try {
    // Create a test booking
    const testBooking = new Booking({
      providerId: req.user.id,
      providerName: 'Test Provider',
      providerEmail: 'test@example.com',
      customerId: new mongoose.Types.ObjectId(), // dummy ID
      customerName: 'Test Customer',
      customerEmail: 'customer@example.com',
      serviceType: 'Test Service',
      location: 'Test Location',
      timeframe: 'ASAP',
      budget: '₦10,000',
      status: 'pending'
    });

    await testBooking.save();

    res.json({
      success: true,
      message: 'Test booking created',
      bookingId: testBooking._id,
      testUrl: `PATCH /api/bookings/${testBooking._id}/status`
    });
  } catch (error) {
    console.error('Test booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: error.message
    });
  }
});


app.get('/api/debug/booking/:id', authenticateToken, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }
    
    res.json({
      success: true,
      data: {
        booking,
        isProvider: booking.providerId.toString() === req.user.id
      }
    });
  } catch (error) {
    console.error('Debug booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching booking',
      error: error.message
    });
  }
});

async function sendBookingConfirmationEmail(booking, customerEmail) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: customerEmail,
      subject: 'Booking Confirmed - HomeHero',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #10b981 0%, #059669 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .booking-details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .button { display: inline-block; padding: 12px 30px; background: #10b981; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>✅ Booking Confirmed!</h1>
              <p>Your service request has been accepted</p>
            </div>
            <div class="content">
              <p>Hello ${booking.customerName},</p>
              <p>Great news! <strong>${booking.providerName}</strong> has accepted your booking request.</p>
              
              <div class="booking-details">
                <h3>Booking Details:</h3>
                <p><strong>Service:</strong> ${booking.serviceType}</p>
                <p><strong>Provider:</strong> ${booking.providerName}</p>
                <p><strong>Location:</strong> ${booking.location}</p>
                <p><strong>Budget:</strong> ${booking.budget}</p>
                <p><strong>Status:</strong> <span style="color: #10b981; font-weight: bold;">Confirmed</span></p>
                ${booking.specialRequests ? `<p><strong>Special Requests:</strong> ${booking.specialRequests}</p>` : ''}
              </div>

              <p>The provider will contact you shortly to confirm the exact time and date.</p>
              
              <a href="https://homeheroes.help/dashboard" class="button">View Booking Details</a>
              
              <p>If you have any questions, please contact our support team.</p>
              
              <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>© 2024 HomeHero. All rights reserved.</p>
              </div>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log('Booking confirmation email sent to:', customerEmail);
  } catch (error) {
    console.error('Failed to send booking confirmation email:', error);
    throw error;
  }
}

// Get user notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const unreadOnly = req.query.unreadOnly === 'true';

    let filter = { userId: req.user.id };
    if (unreadOnly) {
      filter.isRead = false;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 }
    };

    const result = await Notification.paginate(filter, options);

    res.json({
      success: true,
      data: {
        notifications: result.docs,
        totalDocs: result.totalDocs,
        totalPages: result.totalPages,
        page: result.page,
        hasNextPage: result.hasNextPage,
        hasPrevPage: result.hasPrevPage
      }
    });
  } catch (error) {
    console.error('Get notifications error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notifications'
    });
  }
});

app.get('/api/notifications/unread-count', authenticateToken, async (req, res) => {
  try {
    const count = await Notification.countDocuments({
      userId: req.user.id,
      isRead: false
    });

    res.json({
      success: true,
      data: { count }
    });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch unread count'
    });
  }
});

// Mark notification as read
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const notification = await Notification.findOne({
      _id: req.params.id,
      userId: req.user.id
    });

    if (!notification) {
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }

    notification.isRead = true;
    await notification.save();

    res.json({
      success: true,
      message: 'Notification marked as read'
    });
  } catch (error) {
    console.error('Mark notification as read error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark notification as read'
    });
  }
});

app.patch('/api/notifications/mark-all-read', authenticateToken, async (req, res) => {
  try {
    await Notification.updateMany(
      { userId: req.user.id, isRead: false },
      { isRead: true }
    );

    res.json({
      success: true,
      message: 'All notifications marked as read'
    });
  } catch (error) {
    console.error('Mark all notifications as read error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark all notifications as read'
    });
  }
});


app.post('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { userId, type, title, message, relatedId, relatedType, priority } = req.body;

    const notification = await Notification.createNotification({
      userId,
      type,
      title,
      message,
      relatedId,
      relatedType,
      priority: priority || 'medium'
    });

    res.status(201).json({
      success: true,
      message: 'Notification created',
      data: { notification }
    });
  } catch (error) {
    console.error('Create notification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create notification'
    });
  }
});


app.get('/api/jobs', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const status = req.query.status || 'pending';
    const serviceType = req.query.serviceType;
    const location = req.query.location;
    const minBudget = req.query.minBudget;
    const maxBudget = req.query.maxBudget;
    const urgency = req.query.urgency;
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder || 'desc';

    // Build filter object - FIXED: Handle missing isPublic field
    let filter = { 
      status: status,
      $or: [
        { isPublic: true },
        { isPublic: { $exists: false } } // Include documents without isPublic field
      ]
    };
    
    // Only show pending jobs to providers (unless they're viewing their own accepted jobs)
    if (status === 'all') {
      filter.status = { $in: ['pending', 'accepted', 'completed'] };
    } else if (status === 'my-jobs') {
      filter = {
        providerId: req.user.id,
        status: { $in: ['accepted', 'completed'] }
      };
    }
    
    // Filter by service type
    if (serviceType && serviceType !== 'all') {
      filter.serviceType = { $regex: serviceType, $options: 'i' };
    }
    
    // Filter by location
    if (location && location !== 'all') {
      filter.location = { $regex: location, $options: 'i' };
    }
    
    // Filter by urgency
    if (urgency && urgency !== 'all') {
      filter.urgency = urgency;
    }

    const options = {
      page,
      limit,
      sort: { [sortBy]: sortOrder === 'desc' ? -1 : 1 },
      populate: { 
        path: 'customerId', 
        select: 'name email phoneNumber profileImage rating reviewCount' 
      }
    };

    console.log('📋 Jobs query filter:', JSON.stringify(filter, null, 2));
    console.log('🔍 Querying jobs with status:', status);

    const result = await ServiceRequest.paginate(filter, options);

    console.log('✅ Found jobs:', result.docs.length, 'of', result.totalDocs);

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
    console.error('Get jobs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch jobs',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});



// Get a single job details
app.get('/api/jobs/:id', authenticateToken, async (req, res) => {
  try {
    const job = await ServiceRequest.findById(req.params.id)
      .populate('customerId', 'name email phoneNumber profileImage rating reviewCount createdAt')
      .populate('providerId', 'name email phoneNumber profileImage rating reviewCount');

    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }

    res.json({
      success: true,
      data: job
    });
  } catch (error) {
    console.error('Get job error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch job details'
    });
  }
});

// Apply for a job (provider accepts a service request)


app.post('/api/jobs/:id/apply', authenticateToken, async (req, res) => {
  try {
    const job = await ServiceRequest.findById(req.params.id);
    
    if (!job) {
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
    const user = await User.findById(req.user.id);
    if (!user.identityVerification?.isNinVerified) {
      return res.status(403).json({
        success: false,
        message: 'Identity verification required before applying for jobs. Please verify your NIN first.'
      });
    }

    // Check if user has already applied for this job
    const existingApplication = await ServiceRequest.findOne({
      _id: job._id,
      'applications.providerId': req.user.id
    });

    if (existingApplication) {
      return res.status(400).json({
        success: false,
        message: 'You have already applied for this job'
      });
    }

    // Add application to job (or update job status based on your business logic)
    job.providerId = req.user.id;
    job.status = 'accepted';
    job.acceptedAt = new Date();
    
    await job.save();
    
    // Populate the updated job
    await job.populate('customerId', 'name email phoneNumber');
    await job.populate('providerId', 'name email phoneNumber profileImage');

    await Notification.createNotification({
      userId: job.customerId,
      type: 'job_applied',
      title: 'New Job Application',
      message: `A provider has applied for your ${job.serviceType} job`,
      relatedId: job._id,
      relatedType: 'job',
      priority: 'medium'
    });
    
    res.json({
      success: true,
      message: 'Successfully applied for the job',
      data: job
    });
  } catch (error) {
    console.error('Apply for job error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to apply for job'
    });
  }
});

app.patch('/api/jobs/:id/accept', authenticateToken, async (req, res) => {
  try {
    const job = await ServiceRequest.findById(req.params.id);
    
    // Update job status to accepted
    job.status = 'accepted';
    job.providerId = req.user.id; // or the provider who applied
    await job.save();

    // Create notification for the provider who applied
    await Notification.createNotification({
      userId: req.user.id, // or the provider ID
      type: 'job_accepted',
      title: 'Job Application Accepted!',
      message: `Your application for ${job.serviceType} has been accepted`,
      relatedId: job._id,
      relatedType: 'job',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Job accepted successfully',
      data: job
    });
  } catch (error) {
    console.error('Accept job error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to accept job'
    });
  }
});


// Update job status (complete, cancel, etc.)
app.patch('/api/jobs/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    
    if (!['accepted', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status'
      });
    }
    
    const job = await ServiceRequest.findById(req.params.id);
    
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }
    
    // Check if user has permission to update this job
    if (job.providerId.toString() !== req.user.id && job.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this job'
      });
    }
    
    job.status = status;
    
    if (status === 'completed') {
      job.completedAt = new Date();
    }
    
    await job.save();
    
    res.json({
      success: true,
      message: `Job status updated to ${status}`,
      data: job
    });
  } catch (error) {
    console.error('Update job status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update job status'
    });
  }
});

// Get stats for provider dashboard
app.get('/api/jobs/stats/dashboard', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const [
      totalJobs,
      pendingJobs,
      acceptedJobs,
      completedJobs,
      totalEarnings
    ] = await Promise.all([
      ServiceRequest.countDocuments({ providerId: userId }),
      ServiceRequest.countDocuments({ providerId: userId, status: 'pending' }),
      ServiceRequest.countDocuments({ providerId: userId, status: 'accepted' }),
      ServiceRequest.countDocuments({ providerId: userId, status: 'completed' }),
      ServiceRequest.aggregate([
        { $match: { providerId: new mongoose.Types.ObjectId(userId), status: 'completed' } },
        { $group: { _id: null, total: { $sum: { $toDouble: '$budget' } } } }
      ])
    ]);
    
    // Recent jobs
    const recentJobs = await ServiceRequest.find({ providerId: userId })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('customerId', 'name profileImage');
    
    res.json({
      success: true,
      data: {
        stats: {
          total: totalJobs,
          pending: pendingJobs,
          accepted: acceptedJobs,
          completed: completedJobs,
          earnings: totalEarnings.length > 0 ? totalEarnings[0].total : 0
        },
        recentJobs
      }
    });
  } catch (error) {
    console.error('Get job stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch job statistics'
    });
  }
});

app.get('/api/jobs/customer', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;

    let filter = { customerId: req.user.id };
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 }
    };

    // Using ServiceRequest model to fetch jobs (adjust if you have a different model)
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
    console.error('Get customer jobs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch customer jobs',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


app.post('/api/jobs', authenticateToken, async (req, res) => {
  try {
    const {
      title,
      description,
      budget,
      category,
      location,
      deadline,
      requirements
    } = req.body;

    // Validate required fields
    if (!title || !description || !category || !location) {
      return res.status(400).json({
        success: false,
        message: 'Title, description, category, and location are required'
      });
    }

    // Create new job post
    const newJob = new ServiceRequest({
      title,
      description,
      budget: budget || 0,
      category,
      location,
      deadline: deadline || null,
      requirements: requirements || [],
      customerId: req.user.id,
      status: 'active'
    });

    const savedJob = await newJob.save();
    
    // Populate customer info
    await savedJob.populate('customerId', 'name email');

    res.status(201).json({
      success: true,
      message: 'Job posted successfully',
      data: savedJob
    });
  } catch (error) {
    console.error('Create job error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create job post',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});






// Favorites endpoint
app.post('/api/favorites/:providerId', authenticateToken, async (req, res) => {
  try {
    const { providerId } = req.params;
    
    // Check if provider exists
    const provider = await User.findById(providerId);
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }
    
    // Check if already favorited
    const user = await User.findById(req.user.id);
    if (user.favorites.includes(providerId)) {
      return res.status(400).json({
        success: false,
        message: 'Provider already in favorites'
      });
    }
    
    // Add to favorites
    user.favorites.push(providerId);
    await user.save();
    
    res.json({
      success: true,
      message: 'Provider added to favorites',
      data: { favorites: user.favorites }
    });
  } catch (error) {
    console.error('Add favorite error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add to favorites'
    });
  }
});

app.delete('/api/favorites/:providerId', authenticateToken, async (req, res) => {
  try {
    const { providerId } = req.params;
    
    const user = await User.findById(req.user.id);
    user.favorites = user.favorites.filter(id => id.toString() !== providerId);
    await user.save();
    
    res.json({
      success: true,
      message: 'Provider removed from favorites',
      data: { favorites: user.favorites }
    });
  } catch (error) {
    console.error('Remove favorite error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove from favorites'
    });
  }
});

app.get('/api/favorites', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .populate('favorites', 'name email services hourlyRate averageRating city state country profileImage isAvailableNow experience phoneNumber address reviewCount completedJobs isVerified isTopRated responseTime rating');
    
    res.json({
      success: true,
      data: { favorites: user.favorites || [] }
    });
  } catch (error) {
    console.error('Get favorites error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch favorites'
    });
  }
});

app.get('/api/auth/favorites', authenticateToken, async (req, res) => {
  try {
    // For now, return empty array since favorites functionality isn't implemented yet
    // You can implement this later by adding a favorites field to the User model
    res.json({
      success: true,
      data: { favorites: [] }
    });
  } catch (error) {
    console.error('Get favorites error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch favorites',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});




//Messages end point

    app.post('/api/messages/conversation', authenticateToken, async (req, res) => {
  try {
    const { participantIds } = req.body;
    
    if (!participantIds || !Array.isArray(participantIds) || participantIds.length < 2) {
      return res.status(400).json({
        success: false,
        message: 'At least two participants are required'
      });
    }

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: participantIds, $size: participantIds.length }
    }).populate('participants', 'name email profileImage');

    if (!conversation) {
      conversation = new Conversation({
        participants: participantIds
      });
      await conversation.save();
      await conversation.populate('participants', 'name email profileImage');
    }

    res.json({
      success: true,
      data: { conversation }
    });
  } catch (error) {
    console.error('Get conversation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get or create conversation'
    });
  }
});

// Send message
app.post('/api/messages/send', authenticateToken, async (req, res) => {
  try {
    const { conversationId, content, messageType = 'text' } = req.body;

    if (!conversationId || !content) {
      return res.status(400).json({
        success: false,
        message: 'Conversation ID and content are required'
      });
    }

    // Verify user is part of conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(req.user.id)) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized for this conversation'
      });
    }

    const message = new Message({
      conversationId,
      senderId: req.user.id,
      content,
      messageType
    });

    await message.save();
    
    // Update conversation last message and timestamp
    conversation.lastMessage = message._id;
    conversation.updatedAt = new Date();
    await conversation.save();

    // Populate sender info
    await message.populate('senderId', 'name profileImage');

    if (recipientId) {
      await Notification.createNotification({
        userId: recipientId,
        type: 'message',
        title: 'New Message',
        message: `You have a new message from ${req.user.name}`,
        relatedId: conversationId,
        relatedType: 'conversation',
        priority: 'high'
      });
    }

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      data: { message }
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send message'
    });
  }
});

// Get messages for conversation
app.get('/api/messages/conversation/:conversationId', authenticateToken, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;

    // Verify user is part of conversation
    const conversation = await Conversation.findById(conversationId);
    if (!conversation || !conversation.participants.includes(req.user.id)) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized for this conversation'
      });
    }

    const messages = await Message.find({ conversationId })
      .populate('senderId', 'name profileImage')
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    // Mark messages as read if they're from other participants
    await Message.updateMany(
      {
        conversationId,
        senderId: { $ne: req.user.id },
        status: { $ne: 'read' }
      },
      { status: 'read' }
    );

    res.json({
      success: true,
      data: {
        messages: messages.reverse(), // Return in chronological order
        pagination: {
          currentPage: page,
          limit,
          totalPages: Math.ceil(await Message.countDocuments({ conversationId }) / limit)
        }
      }
    });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch messages'
    });
  }
});

// Get user conversations
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
  try {
    const conversations = await Conversation.find({
      participants: req.user.id
    })
    .populate('participants', 'name email profileImage online')
    .populate('lastMessage')
    .sort({ updatedAt: -1 });

    res.json({
      success: true,
      data: { conversations }
    });
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch conversations'
    });
  }
});

app.post('/api/service-requests', authenticateToken, async (req, res) => {
  try {
    const {
      serviceType,
      description,
      location,
      coordinates,
      urgency,
      timeframe,
      budget,
      contactInfo,
      category
    } = req.body;

    // Validate required fields
    if (!serviceType || !description || !location) {
      return res.status(400).json({
        success: false,
        message: 'Service type, description, and location are required'
      });
    }

    // Get customer information from authenticated user
    const customer = await User.findById(req.user.id);
    if (!customer) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Create new service request with proper status
    const newRequest = new ServiceRequest({
      serviceType,
      description,
      location,
      coordinates: coordinates || { lat: 0, lng: 0 },
      urgency: urgency || 'normal',
      timeframe: timeframe || 'ASAP',
      budget: budget || 'Not specified',
      contactInfo: {
        name: contactInfo?.name || customer.name,
        phone: contactInfo?.phone || customer.phoneNumber || 'Not provided',
        email: contactInfo?.email || customer.email
      },
      customerId: req.user.id,
      category: category || 'general',
      status: 'pending' // This ensures the job will be visible to providers
    });

    const savedRequest = await newRequest.save();
    
    // Populate customer info for immediate response
    await savedRequest.populate('customerId', 'name email phoneNumber');

    res.status(201).json({
      success: true,
      message: 'Service request created successfully',
      data: savedRequest
    });
  } catch (error) {
    console.error('Create service request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create service request',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/service-requests/customer', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;

    let filter = { customerId: req.user.id };
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: { 
        path: 'customerId', 
        select: 'name email phoneNumber profileImage' 
      }
    };

    // Use ServiceRequest model to fetch jobs
    const result = await ServiceRequest.paginate(filter, options);

    // Add cache control headers to prevent 304 responses
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

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
    console.error('Get customer service requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch customer service requests',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});



// Get all service requests (for provider dashboard)
app.get('/api/service-requests', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;
    const serviceType = req.query.serviceType;
    const category = req.query.category;

    // Default filter shows only pending requests to providers
    let filter = { status: 'pending' };
    
    // Allow filtering by different statuses
    if (status && status !== 'all') {
      filter.status = status;
    }
    
    // Filter by service type
    if (serviceType && serviceType !== 'all') {
      filter.serviceType = { $regex: serviceType, $options: 'i' };
    }
    
    // Filter by category
    if (category && category !== 'all') {
      filter.category = category;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: { 
        path: 'customerId', 
        select: 'name email phoneNumber profileImage' 
      }
    };

    // Use pagination
    const result = await ServiceRequest.paginate(filter, options);

    res.json({
      success: true,
      data: {
        requests: result.docs,
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
    console.error('Get service requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch service requests',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


app.get('/api/jobs/applied', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        appliedJobIds: user.appliedJobs || []
      }
    });
  } catch (error) {
    console.error('Get applied jobs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch applied jobs'
    });
  }
});


app.post('/api/jobs/apply', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.body;
    
    if (!jobId) {
      return res.status(400).json({
        success: false,
        message: 'Job ID is required'
      });
    }
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    // Add job to applied jobs if not already there
    if (!user.appliedJobs) {
      user.appliedJobs = [];
    }
    
    if (!user.appliedJobs.includes(jobId)) {
      user.appliedJobs.push(jobId);
      await user.save();
    }
    
    res.json({
      success: true,
      message: 'Application submitted successfully'
    });
  } catch (error) {
    console.error('Job application error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit application'
    });
  }
});


// Get a single service request
app.get('/api/service-requests/:id', authenticateToken, async (req, res) => {
  try {
    const request = await ServiceRequest.findById(req.params.id)
      .populate('customerId', 'name email phoneNumber profileImage');

    if (!request) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    res.json({
      success: true,
      data: request
    });
  } catch (error) {
    console.error('Get service request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch service request'
    });
  }
});


// Update service request status (for providers to accept/reject)
app.patch('/api/service-requests/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status, providerId } = req.body;

    if (!status || !['pending', 'accepted', 'rejected', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Valid status is required'
      });
    }

    const request = await ServiceRequest.findById(req.params.id);

    if (!request) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // If accepting a request, assign the provider
    if (status === 'accepted' && providerId) {
      request.providerId = providerId;
      request.acceptedAt = new Date();
    }

    request.status = status;
    request.updatedAt = new Date();

    const updatedRequest = await request.save();
    await updatedRequest.populate('customerId', 'name email phoneNumber');
    await updatedRequest.populate('providerId', 'name email phoneNumber');

    res.json({
      success: true,
      message: `Service request ${status} successfully`,
      data: updatedRequest
    });
  } catch (error) {
    console.error('Update service request status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update service request status'
    });
  }
});


// Get service requests for a specific customer
app.get('/api/service-requests/customer/:customerId', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;

    let filter = { customerId: req.params.customerId };
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 }
    };

    const result = await ServiceRequest.paginate(filter, options);

    res.json({
      success: true,
      data: {
        requests: result.docs,
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
    console.error('Get customer service requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch customer service requests'
    });
  }
});

// Get service requests for a specific provider
app.get('/api/service-requests/provider/:providerId', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const status = req.query.status;

    let filter = { providerId: req.params.providerId };
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: { path: 'customerId', select: 'name email phoneNumber profileImage' }
    };

    const result = await ServiceRequest.paginate(filter, options);

    res.json({
      success: true,
      data: {
        requests: result.docs,
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
    console.error('Get provider service requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider service requests'
    });
  }
});

app.get('/api/debug/fix-test-user', async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { email: 'alex@example.com' },
      { 
        $set: {
          isEmailVerified: true,
          emailVerificationToken: null,
          emailVerificationExpires: null
        }
      },
      { new: true }
    );
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Test user not found. Creating new test user...'
      });
    }
    
    console.log('Fixed test user:', {
      id: user._id,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
      hasVerificationToken: !!user.emailVerificationToken
    });
    
    res.json({
      success: true,
      message: 'Test user verification status fixed',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        isEmailVerified: user.isEmailVerified,
        emailVerificationToken: user.emailVerificationToken,
        emailVerificationExpires: user.emailVerificationExpires
      }
    });
  } catch (error) {
    console.error('Fix test user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fix test user',
      error: error.message
    });
  }
});

// Also add this endpoint to create a fresh test user if needed
app.post('/api/debug/create-test-user', async (req, res) => {
  try {
    // Delete existing test user
    await User.deleteOne({ email: 'alex@example.com' });
    
    const bcrypt = await import('bcryptjs');
    const hashedPassword = await bcrypt.hash('Password123', 10);
    
    const testUser = new User({
      name: 'Alex Johnson',
      email: 'alex@example.com',
      password: hashedPassword,
      userType: 'provider',
      country: 'USA',
      isEmailVerified: true,
      emailVerificationToken: null,
      emailVerificationExpires: null,
      services: ['House Cleaning', 'Garden Maintenance'],
      hourlyRate: 25,
      experience: '3 years',
      profileImage: '',
      isActive: true
    });
    
    const savedUser = await testUser.save();
    
    res.json({
      success: true,
      message: 'Fresh test user created and verified',
      user: {
        id: savedUser._id,
        email: savedUser.email,
        name: savedUser.name,
        isEmailVerified: savedUser.isEmailVerified,
        userType: savedUser.userType
      }
    });
  } catch (error) {
    console.error('Create test user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create test user',
      error: error.message
    });
  }
});

// Search conversations
app.get('/api/messages/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    if (!query) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required'
      });
    }

    const conversations = await Conversation.find({
      participants: req.user.id,
      $text: { $search: query }
    })
    .populate('participants', 'name email profileImage')
    .populate('lastMessage');

    res.json({
      success: true,
      data: { conversations }
    });
  } catch (error) {
    console.error('Search conversations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to search conversations'
    });
  }
});

// WebRTC signaling endpoints for free peer-to-peer calls
const activeCalls = new Map();

app.post('/api/calls/offer', authenticateToken, async (req, res) => {
  try {
    const { toUserId, offer } = req.body;
    
    // Store the offer for the callee
    activeCalls.set(`offer-${toUserId}-${req.user.id}`, {
      offer,
      from: req.user.id,
      timestamp: Date.now()
    });

    // Clean up old offers (older than 1 minute)
    cleanupOldCalls();

    res.json({
      success: true,
      message: 'Offer sent successfully'
    });
  } catch (error) {
    console.error('Call offer error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send call offer'
    });
  }
});

app.post('/api/calls/answer', authenticateToken, async (req, res) => {
  try {
    const { toUserId, answer } = req.body;
    
    // Store the answer for the caller
    activeCalls.set(`answer-${toUserId}-${req.user.id}`, {
      answer,
      from: req.user.id,
      timestamp: Date.now()
    });

    res.json({
      success: true,
      message: 'Answer sent successfully'
    });
  } catch (error) {
    console.error('Call answer error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send call answer'
    });
  }
});

app.get('/api/calls/check-offer/:fromUserId', authenticateToken, async (req, res) => {
  try {
    const { fromUserId } = req.params;
    const offerKey = `offer-${req.user.id}-${fromUserId}`;
    const offer = activeCalls.get(offerKey);
    
    if (offer) {
      activeCalls.delete(offerKey); // Remove after retrieving
      res.json({
        success: true,
        data: { offer }
      });
    } else {
      res.json({
        success: true,
        data: { offer: null }
      });
    }
  } catch (error) {
    console.error('Check offer error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check for call offers'
    });
  }
});

app.get('/api/calls/check-answer/:fromUserId', authenticateToken, async (req, res) => {
  try {
    const { fromUserId } = req.params;
    const answerKey = `answer-${req.user.id}-${fromUserId}`;
    const answer = activeCalls.get(answerKey);
    
    if (answer) {
      activeCalls.delete(answerKey); // Remove after retrieving
      res.json({
        success: true,
        data: { answer }
      });
    } else {
      res.json({
        success: true,
        data: { answer: null }
      });
    }
  } catch (error) {
    console.error('Check answer error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check for call answers'
    });
  }
});

// Clean up old call data
function cleanupOldCalls() {
  const now = Date.now();
  for (const [key, value] of activeCalls.entries()) {
    if (now - value.timestamp > 60000) { // 1 minute
      activeCalls.delete(key);
    }
  }
}

// Clean up every 5 minutes
setInterval(cleanupOldCalls, 300000);
// Profile endpoints
// app.get('/api/auth/profile', authenticateToken, async (req, res) => {
//   try {
//     const user = await User.findById(req.user.id).select('-password');
//     if (!user) {
//       return res.status(404).json({
//         success: false,
//         message: 'User not found'
//       });
//     }

//     const userWithProfileImage = {
//       ...user.toObject(),
//       profileImage: user.profilePicture || ''
//     };

//     res.json({
//       success: true,
//       data: { user: userWithProfileImage }
//     });
//   } catch (error) {
//     console.error('Profile error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to fetch user profile'
//     });
//   }
// });

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const profileData = {
      name: user.name,
      email: user.email,
      phone: user.phoneNumber || '',
      address: user.address || '',
      bio: user.bio || '',
      avatar: user.profileImage ? `${req.protocol}://${req.get('host')}${user.profileImage}` : '',
      role: user.userType || 'customer',
      city: user.city || '',
      state: user.state || '',
      country: user.country || ''
    };

    res.json({
      success: true,
      data: { user: profileData }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user profile'
    });
  }
});



// Keep your existing PUT endpoint
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, address, bio, city, state, country } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phone !== undefined) updateData.phoneNumber = phone;
    if (address !== undefined) updateData.address = address;
    if (bio !== undefined) updateData.bio = bio;
    if (city !== undefined) updateData.city = city;
    if (state !== undefined) updateData.state = state;
    if (country !== undefined) updateData.country = country;

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

    const profileData = {
      name: updatedUser.name,
      email: updatedUser.email,
      phone: updatedUser.phoneNumber || '',
      address: updatedUser.address || '',
      bio: updatedUser.bio || '',
      avatar: updatedUser.profileImage ? `${req.protocol}://${req.get('host')}${updatedUser.profileImage}` : '',
      role: updatedUser.userType || 'customer',
      city: updatedUser.city || '',
      state: updatedUser.state || '',
      country: updatedUser.country || ''
    };

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: profileData }
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


app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    await user.save();

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
});

// Preferences endpoints
app.put('/api/auth/preferences', authenticateToken, async (req, res) => {
  try {
    const { preferences } = req.body;

    if (!preferences) {
      return res.status(400).json({
        success: false,
        message: 'Preferences data is required'
      });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Update user preferences
    user.preferences = {
      ...user.preferences,
      ...preferences
    };

    // Also update notification settings for compatibility
    user.notificationSettings = {
      ...user.notificationSettings,
      ...preferences
    };

    await user.save();

    res.json({
      success: true,
      message: 'Preferences updated successfully',
      data: {
        preferences: user.preferences
      }
    });
  } catch (error) {
    console.error('Update preferences error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update preferences'
    });
  }
});



// Activity endpoints
app.get('/api/auth/activity', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get user bookings as activity
    const bookings = await Booking.find({
      $or: [
        { customerId: req.user.id },
        { providerId: req.user.id }
      ]
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .populate('customerId', 'name profileImage')
    .populate('providerId', 'name profileImage');

    // Get service requests as activity
    const serviceRequests = await ServiceRequest.find({
      $or: [
        { customerId: req.user.id },
        { providerId: req.user.id }
      ]
    })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .populate('customerId', 'name profileImage')
    .populate('providerId', 'name profileImage');

    // Get messages as activity
    const messages = await Message.find({
      $or: [
        { senderId: req.user.id },
        { conversationId: { 
            $in: await Conversation.find({ participants: req.user.id }).select('_id') 
        }}
      ]
    })
    .sort({ timestamp: -1 })
    .skip(skip)
    .limit(limit)
    .populate('senderId', 'name profileImage');

    // Combine and format activities
    const activities = [];

    // Add bookings to activities
    bookings.forEach(booking => {
      const isCustomer = booking.customerId?._id.toString() === req.user.id;
      activities.push({
        id: booking._id,
        type: 'booking',
        action: isCustomer ? `Booked ${booking.serviceType}` : `Received booking for ${booking.serviceType}`,
        provider: booking.providerId?.name || 'Unknown Provider',
        customer: booking.customerId?.name || 'Unknown Customer',
        date: booking.createdAt,
        status: booking.status,
        timestamp: booking.createdAt
      });
    });

    // Add service requests to activities
    serviceRequests.forEach(request => {
      const isCustomer = request.customerId?._id.toString() === req.user.id;
      activities.push({
        id: request._id,
        type: 'service_request',
        action: isCustomer ? `Posted ${request.serviceType} request` : `Applied for ${request.serviceType} request`,
        provider: request.providerId?.name || 'Unknown Provider',
        customer: request.customerId?.name || 'Unknown Customer',
        date: request.createdAt,
        status: request.status,
        timestamp: request.createdAt
      });
    });

    // Add messages to activities (only unique conversations)
    const uniqueConversations = new Set();
    messages.forEach(message => {
      const conversationKey = message.conversationId.toString();
      if (!uniqueConversations.has(conversationKey)) {
        uniqueConversations.add(conversationKey);
        const isSender = message.senderId?._id.toString() === req.user.id;
        activities.push({
          id: message._id,
          type: 'message',
          action: isSender ? 'Message sent' : 'Message received',
          provider: !isSender ? message.senderId?.name : 'You',
          customer: isSender ? 'You' : message.senderId?.name,
          date: message.timestamp,
          status: 'delivered',
          timestamp: message.timestamp
        });
      }
    });

    // Sort all activities by timestamp and limit to requested count
    activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    const paginatedActivities = activities.slice(0, limit);

    // Format dates for display
    const formattedActivities = paginatedActivities.map(activity => ({
      ...activity,
      displayDate: formatActivityDate(activity.timestamp)
    }));

    res.json({
      success: true,
      data: {
        activities: formattedActivities,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(activities.length / limit),
          totalActivities: activities.length
        }
      }
    });
  } catch (error) {
    console.error('Get activity error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch activity'
    });
  }
});

function formatActivityDate(date) {
  const now = new Date();
  const activityDate = new Date(date);
  const diffInMs = now - activityDate;
  const diffInHours = diffInMs / (1000 * 60 * 60);
  const diffInDays = diffInHours / 24;

  if (diffInHours < 1) {
    return 'Just now';
  } else if (diffInHours < 24) {
    const hours = Math.floor(diffInHours);
    return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
  } else if (diffInDays < 7) {
    const days = Math.floor(diffInDays);
    return `${days} ${days === 1 ? 'day' : 'days'} ago`;
  } else if (diffInDays < 30) {
    const weeks = Math.floor(diffInDays / 7);
    return `${weeks} ${weeks === 1 ? 'week' : 'weeks'} ago`;
  } else {
    return activityDate.toLocaleDateString();
  }
}


app.post('/api/bookings/reschedule', authenticateToken, async (req, res) => {
  try {
    const { bookingId, newDate, newTime, reason, providerId, customerId } = req.body;

    // Validate required fields
    if (!bookingId || !newDate || !newTime || !reason) {
      return res.status(400).json({
        success: false,
        message: 'Booking ID, new date, new time, and reason are required'
      });
    }

    // Find the booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify the user owns this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to reschedule this booking'
      });
    }

    // Create reschedule request (you might want to create a separate RescheduleRequest model)
    const rescheduleRequest = {
      bookingId,
      originalDate: booking.requestedAt,
      newDate: new Date(`${newDate} ${newTime}`),
      reason,
      requestedBy: req.user.id,
      status: 'pending',
      createdAt: new Date()
    };

    // Update booking status to indicate reschedule request
    booking.status = 'reschedule_requested';
    booking.rescheduleRequests = booking.rescheduleRequests || [];
    booking.rescheduleRequests.push(rescheduleRequest);
    
    await booking.save();

    // Send notification to provider (you can implement this)
    console.log(`Reschedule request submitted for booking: ${bookingId}`);

    res.json({
      success: true,
      message: 'Reschedule request submitted successfully',
      data: { rescheduleRequest }
    });

  } catch (error) {
    console.error('Reschedule booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit reschedule request',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/service-requests/:id/proposals', authenticateToken, async (req, res) => {
  try {
    const serviceRequestId = req.params.id;
    
    // Verify the user owns this service request
    const serviceRequest = await ServiceRequest.findById(serviceRequestId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    if (serviceRequest.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view proposals for this service request'
      });
    }

    // In a real implementation, you would have a Proposal model
    // For now, return mock data or implement your Proposal model
    const proposals = []; // This would be populated from your Proposal model

    res.json({
      success: true,
      data: { proposals }
    });
  } catch (error) {
    console.error('Get proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch proposals'
    });
  }
});

app.put('/api/service-requests/:id', authenticateToken, async (req, res) => {
  try {
    const { serviceType, description, location, budget, category, urgency, timeframe } = req.body;
    
    const serviceRequest = await ServiceRequest.findById(req.params.id);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Verify the user owns this service request
    if (serviceRequest.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this service request'
      });
    }

    // Update fields
    if (serviceType) serviceRequest.serviceType = serviceType;
    if (description) serviceRequest.description = description;
    if (location) serviceRequest.location = location;
    if (budget) serviceRequest.budget = budget;
    if (category) serviceRequest.category = category;
    if (urgency) serviceRequest.urgency = urgency;
    if (timeframe) serviceRequest.timeframe = timeframe;

    await serviceRequest.save();

    res.json({
      success: true,
      message: 'Service request updated successfully',
      data: serviceRequest
    });
  } catch (error) {
    console.error('Update service request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update service request'
    });
  }
});


app.delete('/api/service-requests/:id', authenticateToken, async (req, res) => {
  try {
    const serviceRequest = await ServiceRequest.findById(req.params.id);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Verify the user owns this service request
    if (serviceRequest.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete this service request'
      });
    }

    await ServiceRequest.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Service request deleted successfully'
    });
  } catch (error) {
    console.error('Delete service request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete service request'
    });
  }
});

app.post('/api/proposals/:id/accept', authenticateToken, async (req, res) => {
  try {
    // In a real implementation, you would update the proposal status
    // and potentially create a booking
    
    res.json({
      success: true,
      message: 'Proposal accepted successfully'
    });
  } catch (error) {
    console.error('Accept proposal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to accept proposal'
    });
  }
});


app.get('/api/debug/sms-config', (req, res) => {
  const config = {
    environment: process.env.NODE_ENV,
    twilio: {
      accountSid: process.env.TWILIO_ACCOUNT_SID ? 'Set' : 'Not set',
      authToken: process.env.TWILIO_AUTH_TOKEN ? 'Set' : 'Not set', 
      phoneNumber: process.env.TWILIO_PHONE_NUMBER ? 'Set' : 'Not set'
    },
    smsService: {
      initialized: !!smsService.client,
      mode: process.env.NODE_ENV === 'production' ? 'Production' : 'Development'
    }
  };
  
  res.json({ success: true, data: config });
});
// ADD THIS NEW POST ENDPOINT RIGHT AFTER THE PUT ENDPOINT
app.post('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { 
      name, 
      phoneNumber, 
      address, 
      city, 
      state, 
      country, 
      services, 
      hourlyRate, 
      experience, 
      profileImage 
    } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;
    if (city) updateData.city = city;
    if (state) updateData.state = state;
    if (country) updateData.country = country;
    if (services) updateData.services = services;
    if (hourlyRate !== undefined) updateData.hourlyRate = hourlyRate;
    if (experience) updateData.experience = experience;
    if (profileImage) updateData.profileImage = profileImage;

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

app.post('/api/debug/test-sms', async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    
    if (!phoneNumber) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }

    const testToken = '123456';
    const result = await smsService.sendVerificationCode(phoneNumber, testToken);
    
    res.json({
      success: true,
      message: 'SMS test completed',
      data: result
    });
  } catch (error) {
    console.error('SMS test error:', error);
    res.status(500).json({
      success: false,
      message: 'SMS test failed',
      error: error.message
    });
  }
});

app.post('/api/debug/test-phone-formats', async (req, res) => {
  try {
    const { baseNumber } = req.body; // e.g., '9070510149'
    
    const testFormats = [
      `+234${baseNumber}`,      // +2349070510149
      `234${baseNumber}`,       // 2349070510149
      `+2340${baseNumber}`,     // +23409070510149
      `0${baseNumber}`,         // 09070510149
    ];

    const results = [];
    
    for (const format of testFormats) {
      try {
        const testToken = '123456';
        const result = await smsService.sendVerificationCode(format, testToken);
        results.push({ format, success: true, provider: result.provider });
      } catch (error) {
        results.push({ format, success: false, error: error.message });
      }
    }
    
    res.json({ success: true, results });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Add this test endpoint to server.js
app.post('/api/debug/test-nigerian-numbers', async (req, res) => {
  try {
    const testNumbers = [
      '+2349070510149',    // Your current format
      '+2349012345678',    // Test with a known good format  
      '+2348091234567',    // Another format
      '+2347081234567',    // MTN format
      '+2348181234567',    // Airtel format
    ];

    const results = [];
    
    for (const number of testNumbers) {
      try {
        console.log(`🧪 Testing: ${number}`);
        const testToken = '123456';
        const result = await smsService.sendVerificationCode(number, testToken);
        results.push({ 
          number, 
          success: true, 
          provider: result.provider,
          messageId: result.messageId 
        });
        console.log(`✅ Success: ${number}`);
      } catch (error) {
        results.push({ 
          number, 
          success: false, 
          error: error.message,
          code: error.code 
        });
        console.log(`❌ Failed: ${number} - ${error.message}`);
      }
    }
    
    res.json({ 
      success: true, 
      message: 'Nigerian number test completed',
      results 
    });
  } catch (error) {
    console.error('Test error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/debug/twilio-number', (req, res) => {
  const fromNumber = process.env.TWILIO_PHONE_NUMBER;
  const isValid = fromNumber && fromNumber.startsWith('+');
  
  res.json({
    success: true,
    data: {
      twilioNumber: fromNumber,
      isValid: isValid,
      expectedFormat: 'Must start with + (E.164 format)',
      currentFormat: isValid ? '✅ Valid' : '❌ Invalid'
    }
  });
});

// Add this POST endpoint for updating profile - place it near your other profile endpoints


// Availability endpoints
app.post('/api/availability', authenticateToken, async (req, res) => {
  try {
    const { date, startTime, endTime, serviceType, notes } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const newSlot = {
      date: new Date(date),
      startTime,
      endTime,
      serviceType,
      notes: notes || '',
      status: 'available'
    };

    user.availability.push(newSlot);
    await user.save();

    res.status(201).json({
      success: true,
      message: 'Availability slot added successfully',
      data: { slot: user.availability[user.availability.length - 1] }
    });
  } catch (error) {
    console.error('Add availability error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add availability slot'
    });
  }
});

app.get('/api/availability', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('availability');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: { availability: user.availability }
    });
  } catch (error) {
    console.error('Get availability error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch availability'
    });
  }
});

// Stats endpoint
app.get('/api/stats/users', authenticateToken, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const verifiedUsers = await User.countDocuments({ isEmailVerified: true });
    const customerCount = await User.countDocuments({ userType: 'customer' });
    const providerCount = await User.countDocuments({ userType: 'provider' });
    const bothCount = await User.countDocuments({ userType: 'both' });
    
    const usersByCountry = await User.aggregate([
      { $group: { _id: '$country', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const recentRegistrations = await User.countDocuments({
      createdAt: { $gte: thirtyDaysAgo }
    });

    const serviceStats = await User.aggregate([
      { $match: { userType: { $in: ['provider', 'both'] } } },
      { $unwind: { path: '$services', preserveNullAndEmptyArrays: true } },
      { $match: { services: { $exists: true, $ne: null } } },
      { $group: { _id: '$services', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    res.json({
      success: true,
      data: {
        totalUsers,
        verifiedUsers,
        userTypes: {
          customer: customerCount,
          provider: providerCount,
          both: bothCount
        },
        usersByCountry,
        recentRegistrations,
        popularServices: serviceStats
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics'
    });
  }
});

// Delete account endpoint
app.delete('/api/auth/account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'Account deleted successfully'
    });
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete account'
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'HomeHero API with Email Verification',
    version: '2.0.0',
    features: ['Email Verification', 'Password Reset', 'User Management', 'Role Switching'],
    endpoints: {
      health: 'GET /api/health',
      uploadHealth: 'GET /api/health/upload',
      auth: {
        signup: 'POST /api/auth/signup',
        login: 'POST /api/auth/login',
        verifyEmail: 'POST /api/auth/verify-email',
        resendVerification: 'POST /api/auth/resend-verification',
        profile: 'GET /api/auth/profile',
        updateProfile: 'PUT /api/auth/profile',
        switchRole: 'POST /api/auth/switch-role',
        forgotPassword: 'POST /api/auth/forgot-email',
        resetPassword: 'POST /api/auth/reset-password',
        logout: 'POST /api/auth/logout',
        deleteAccount: 'DELETE /api/auth/account'
      },
      users: 'GET /api/users',
      availability: {
        get: 'GET /api/availability',
        add: 'POST /api/availability'
      },
      stats: 'GET /api/stats/users',
      earnings: 'GET /api/earnings',
      schedule: 'GET /api/user/schedule',
      dashboard: 'GET /api/user/dashboard'
    }
  });
});

// API 404 handler (should come after all API routes)
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found'
  });
});

// ==================== STATIC FILES (PRODUCTION ONLY) ====================

// Static files (only in production)
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/dist')));
}

// Catch-all handler for SPA (only in production)
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/dist', 'index.html'));
  });
}

// ==================== ERROR HANDLING ====================

// Multer and file upload error handling middleware
app.use((error, req, res, next) => {
  // Handle Multer errors
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        success: false,
        message: 'File too large. Maximum size is 5MB.'
      });
    }
    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        success: false,
        message: 'Unexpected file field'
      });
    }
  }
  
  // Handle busboy errors (from express-fileupload)
  if (error.message === 'Unexpected end of form') {
    return res.status(400).json({
      success: false,
      message: 'Invalid form data. Please check your upload.'
    });
  }
  
  // Handle file size limit errors from express-fileupload
  if (error.code === 'LIMIT_FILE_SIZE' || error.message.includes('File too large')) {
    return res.status(413).json({
      success: false,
      message: 'File too large. Maximum size is 5MB.'
    });
  }
  
  next(error);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      success: false,
      message: 'CORS error: Origin not allowed',
      origin: req.headers.origin
    });
  }
  
  res.status(500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Something went wrong!' : err.message
  });
});

// Debug middleware for file uploads
// 
app.use((req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Content-Security-Policy', "default-src 'self'");
  }
  
  next();
});



app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (process.env.NODE_ENV !== 'production') return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    
    console.warn('CORS blocked origin:', origin);
    return callback(new Error('Not allowed by CORS'), false);
  },
  credentials: true
}));

app.options('*', (req, res) => {
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  
  res.status(200).end();
});

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  console.log('Origin:', req.headers.origin);
  console.log('User-Agent:', req.headers['user-agent']);
  
  if (req.method === 'OPTIONS') {
    console.log('OPTIONS Preflight Request Headers:', {
      'access-control-request-method': req.headers['access-control-request-method'],
      'access-control-request-headers': req.headers['access-control-request-headers']
    });
  }
  
  next();
});


// 404 handler for non-API routes
app.use('*', (req, res) => {
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      message: 'API endpoint not found'
    });
  }
  
  if (process.env.NODE_ENV === 'production') {
    return res.sendFile(path.join(__dirname, 'client/dist', 'index.html'));
  }
  
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    availableEndpoints: {
      health: 'GET /api/health',
      uploadHealth: 'GET /api/health/upload',
      auth: 'POST /api/auth/signup, POST /api/auth/login, POST /api/auth/verify-email, POST /api/auth/switch-role',
      users: 'GET /api/users',
      profile: 'GET /api/auth/profile, PUT /api/auth/profile',
      availability: 'GET /api/availability, POST /api/availability',
      stats: 'GET /api/stats/users',
      earnings: 'GET /api/earnings',
      schedule: 'GET /api/user/schedule',
      dashboard: 'GET /api/user/dashboard'
    }
  });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\nShutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  } catch (error) {
    console.error('Error during shutdown:', error);
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  } catch (error) {
    console.error('Error during shutdown:', error);
  }
  process.exit(0);
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`HomeHero API server running on http://localhost:${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`Upload health check: http://localhost:${PORT}/api/health/upload`);
  console.log(`Email verification enabled: ${!!process.env.EMAIL_USER && !!process.env.EMAIL_PASSWORD}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use.`);
    console.log(`Try: PORT=3002 npm run dev`);
    console.log(`Or kill process: lsof -ti:${PORT} | xargs kill -9`);
    process.exit(1);
  } else {
    console.error('Server error:', err);
  }
});

process.on('unhandledRejection', (err, promise) => {
  console.error('Unhandled Promise Rejection:', err);
  if (process.env.NODE_ENV === 'production') {
    server.close(() => {
      process.exit(1);
    });
  }
});

export default app;