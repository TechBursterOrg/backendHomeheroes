import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001; // Render will use process.env.PORT, localhost uses 3001
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/homehero';

// Validate JWT_SECRET in production
if (process.env.NODE_ENV === 'production') {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error('❌ JWT_SECRET must be at least 32 characters long in production');
    process.exit(1);
  }
  if (!process.env.MONGODB_URI) {
    console.error('❌ MONGODB_URI is required in production');
    process.exit(1);
  }
  console.log('🚀 Running in PRODUCTION mode');
} else {
  console.log('🔧 Running in DEVELOPMENT mode');
}

// Trust proxy for Render deployment
app.set('trust proxy', 1);

// MongoDB User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 50
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
    minlength: 6
  },
  userType: {
    type: String,
    required: true,
    enum: ['customer', 'provider', 'both'],
    default: 'customer'
  },
  country: {
    type: String,
    required: true,
    enum: ['UK', 'USA', 'CANADA', 'NIGERIA']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  profilePicture: {
    type: String,
    default: null
  },
  phoneNumber: {
    type: String,
    default: null
  },
  address: {
    street: String,
    city: String,
    state: String,
    zipCode: String
  },
  // Provider-specific fields
  services: [{
    type: String,
    enum: ['House Cleaning', 'Plumbing Repair', 'Garden Maintenance', 'Electrical Work', 'Painting', 'General Maintenance', 'Other']
  }],
  hourlyRate: {
    type: Number,
    default: null
  },
  experience: {
    type: String,
    default: null
  },
  certifications: [{
    name: String,
    issuer: String,
    date: Date
  }],
  availability: [{
    date: Date,
    startTime: String,
    endTime: String,
    serviceType: String,
    notes: String,
    status: {
      type: String,
      enum: ['available', 'booked', 'completed'],
      default: 'available'
    }
  }]
}, {
  timestamps: true
});

// Create indexes for better performance
userSchema.index({ userType: 1 });
userSchema.index({ country: 1 });
userSchema.index({ services: 1 });

// Create User model
const User = mongoose.model('User', userSchema);

// Connect to MongoDB with better error handling
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI, {
      // Modern Mongoose handles connection options automatically
    });
    console.log('✅ MongoDB connected successfully');
    console.log(`📊 Database: ${conn.connection.name}`);
    console.log(`🌐 MongoDB Host: ${conn.connection.host}`);
    
    // Create a test user if none exists (only in development)
    if (process.env.NODE_ENV !== 'production') {
      const userCount = await User.countDocuments();
      if (userCount === 0) {
        const hashedPassword = await bcrypt.hash('Password123', 10);
        const testUser = new User({
          name: 'Alex Johnson',
          email: 'alex@example.com',
          password: hashedPassword,
          userType: 'provider',
          country: 'USA',
          services: ['House Cleaning', 'Garden Maintenance'],
          hourlyRate: 25,
          experience: '3 years'
        });
        await testUser.save();
        console.log('🧪 Test user created: alex@example.com / Password123');
      }
    }
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    // In production, let the service restart; in development, exit
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
};

// Initialize database connection
connectDB();

// Middleware
// Logging - different for production vs development
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined')); // Detailed logs for production
} else {
  app.use(morgan('dev')); // Concise logs for development
}

// FIXED CORS configuration - allows development frontend to connect
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    // Always allow development origins for testing
    const developmentOrigins = [
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:3001',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:3001'
    ];
    
    if (developmentOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    if (process.env.NODE_ENV === 'production') {
      // In production, also allow production frontend URLs
      const productionOrigins = [
        process.env.FRONTEND_URL,
        'https://your-frontend-domain.com',
        'https://your-frontend-domain.netlify.app',
        'https://your-frontend-domain.vercel.app',
      ].filter(Boolean);
      
      if (productionOrigins.includes(origin)) {
        return callback(null, true);
      }
      
      // Log blocked origins for debugging
      console.log(`CORS blocked origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    } else {
      // In development, allow all origins
      return callback(null, true);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Helper function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { 
      id: user._id, 
      email: user.email, 
      userType: user.userType 
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
};

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

// JWT Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
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

// Routes

// Enhanced health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
    const userCount = await User.countDocuments();
    const providerCount = await User.countDocuments({ userType: { $in: ['provider', 'both'] } });
    const customerCount = await User.countDocuments({ userType: { $in: ['customer', 'both'] } });
    
    const healthData = { 
      status: 'OK', 
      message: 'HomeHero API is running',
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
      uptime: Math.floor(process.uptime()),
      database: {
        status: dbStatus,
        name: mongoose.connection.name,
        host: mongoose.connection.host || 'localhost'
      },
      statistics: {
        totalUsers: userCount,
        providers: providerCount,
        customers: customerCount
      },
      timestamp: new Date().toISOString()
    };

    // Set appropriate status code
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

// Get all users endpoint
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const userType = req.query.userType;
    const country = req.query.country;
    const search = req.query.search;

    // Build filter object
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

// Login endpoint
app.post('/api/auth/login', loginValidation, async (req, res) => {
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

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          userType: user.userType,
          country: user.country,
          profilePicture: user.profilePicture,
          lastLogin: user.lastLogin,
          services: user.services,
          hourlyRate: user.hourlyRate
        },
        token,
        redirectTo: user.userType === 'provider' || user.userType === 'both' ? '/dashboard' : '/customer'
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

// Signup endpoint
app.post('/api/auth/signup', signupValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { name, email, password, userType, country } = req.body;

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.'
      });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      userType,
      country
    });

    const savedUser = await newUser.save();
    const token = generateToken(savedUser);

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      data: {
        user: {
          id: savedUser._id,
          name: savedUser.name,
          email: savedUser.email,
          userType: savedUser.userType,
          country: savedUser.country,
          createdAt: savedUser.createdAt
        },
        token,
        redirectTo: userType === 'provider' || userType === 'both' ? '/dashboard' : '/customer'
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email already exists.'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Internal server error. Please try again later.'
    });
  }
});

// Get user profile endpoint
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: { user }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user profile'
    });
  }
});

// Update user profile endpoint
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phoneNumber, address, services, hourlyRate, experience } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;
    if (services) updateData.services = services;
    if (hourlyRate !== undefined) updateData.hourlyRate = hourlyRate;
    if (experience) updateData.experience = experience;

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
      message: 'Failed to update profile'
    });
  }
});

// Add availability slot endpoint
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

// Get user's availability slots
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

// Get user statistics endpoint
app.get('/api/stats/users', authenticateToken, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
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

    // Service distribution for providers
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

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});

// Delete user account
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

// Add a root route for basic API info
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'HomeHero API is running',
    version: '1.0.0',
    endpoints: {
      health: 'GET /api/health',
      auth: {
        login: 'POST /api/auth/login',
        signup: 'POST /api/auth/signup',
        profile: 'GET /api/auth/profile',
        updateProfile: 'PUT /api/auth/profile',
        logout: 'POST /api/auth/logout',
        deleteAccount: 'DELETE /api/auth/account'
      },
      users: 'GET /api/users',
      availability: {
        get: 'GET /api/availability',
        add: 'POST /api/availability'
      },
      stats: 'GET /api/stats/users'
    }
  });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔄 Shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('📊 MongoDB connection closed');
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🔄 SIGTERM received, shutting down gracefully...');
  try {
    await mongoose.connection.close();
    console.log('📊 MongoDB connection closed');
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
  }
  process.exit(0);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // CORS error
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

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    availableEndpoints: {
      health: 'GET /api/health',
      auth: 'POST /api/auth/login, POST /api/auth/signup',
      users: 'GET /api/users',
      profile: 'GET /api/auth/profile, PUT /api/auth/profile',
      availability: 'GET /api/availability, POST /api/availability',
      stats: 'GET /api/stats/users'
    }
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 HomeHero API server running on http://localhost:${PORT}`);
  console.log(`📚 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Auth endpoints available`);
  console.log(`👥 Users management endpoints available`);
  console.log(`📊 Statistics endpoints available`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use.`);
    console.log(`💡 Try: PORT=3002 npm run dev`);
    console.log(`💡 Or kill process: lsof -ti:${PORT} | xargs kill -9`);
    process.exit(1);
  } else {
    console.error('Server error:', err);
  }
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
  console.error('Unhandled Promise Rejection:', err);
  if (process.env.NODE_ENV === 'production') {
    // Close server & exit process
    server.close(() => {
      process.exit(1);
    });
  }
});

export default app;