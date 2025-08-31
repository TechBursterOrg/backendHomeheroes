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

// Import models
import User from './models/User.js';
import Job from './models/Jobs.js';
import Review from './models/Review.js';

// Import routes
import authRoutes from './routes/auth.routes.js';
import { initializeEmailTransporter } from './utils/emailService.js';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load the appropriate .env file based on environment
const envFile = process.env.NODE_ENV === 'production' 
  ? '.env.production' 
  : '.env';

dotenv.config({ path: path.resolve(__dirname, envFile) });
process.setMaxListeners(0);
// Debug: Check which file is being loaded
console.log(`📁 Loading environment from: ${envFile}`);
console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL}`);
console.log(`🏭 Environment: ${process.env.NODE_ENV || 'development'}`);

const app = express();
const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/homehero';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Initialize email transporter
initializeEmailTransporter();

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
    const conn = await mongoose.connect(MONGODB_URI);
    console.log('✅ MongoDB connected successfully');
    console.log(`📊 Database: ${conn.connection.name}`);
    console.log(`🌐 MongoDB Host: ${conn.connection.host}`);
    
    // Create test user in development
    if (process.env.NODE_ENV !== 'production') {
      try {
        const bcrypt = await import('bcryptjs');
        const userCount = await User.countDocuments();
        if (userCount === 0) {
          const hashedPassword = await bcrypt.hash('Password123', 10);
          const testUser = new User({
            name: 'Alex Johnson',
            email: 'alex@example.com',
            password: hashedPassword,
            userType: 'provider',
            country: 'USA',
            isEmailVerified: true,
            services: ['House Cleaning', 'Garden Maintenance'],
            hourlyRate: 25,
            experience: '3 years',
            profileImage: '' // Added profileImage field
          });
          await testUser.save();
          console.log('🧪 Test user created: alex@example.com / Password123');
        }
      } catch (error) {
        console.log('Note: Test user creation skipped - User model not available yet');
      }
    }
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
};

connectDB();

// CORS configuration - MUST come before routes
const allowedOrigins = process.env.NODE_ENV === 'production' 
  ? [
      'https://homeheroes.help',
      'https://www.homeheroes.help',
      // Add other production domains as needed
    ]
  : [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:5173',
      'http://localhost:4173' // Vite preview
    ];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

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

// ==================== API ROUTES ====================

// Auth routes
app.use('/api/auth', authRoutes);

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
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    // Move the file to the upload directory
    await profileImage.mv(uploadPath);

    // Update user profile with image path
    const imageUrl = `/uploads/profiles/${fileName}`;
    await User.findByIdAndUpdate(req.user.id, { profileImage: imageUrl });

    res.json({
      success: true,
      message: 'Profile image uploaded successfully',
      data: { imageUrl }
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
    const protocol = req.protocol;
    const host = req.get('host');
    
    const imagesWithFullUrl = result.docs.map(image => {
      const imageObj = image.toObject();
      
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
      res.setHeader('Access-Control-Allow-Origin', '*'); // Allow all origins to access images
    }
  }
}));

app.use('/uploads', (req, res, next) => {
  const filePath = path.join(__dirname, 'uploads', req.path);
  
  if (!fs.existsSync(filePath)) {
    console.log(`File not found: ${filePath}`);
    
    // Return a JSON response instead of trying to serve a placeholder image
    res.status(404).json({
      success: false,
      message: 'Image not found',
      path: req.path
    });
  } else {
    next();
  }
});

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
        profileImage: user.profilePicture || '' // Use profilePicture field
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
    
    // Fetch user to get currency preference
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });


    }

    

    




    
    // Calculate earnings data
    const completedJobs = await Job.countDocuments({ 
      providerId: userId, 
      status: 'completed' 
    });
    
    const totalEarningsResult = await Job.aggregate([
      { $match: { providerId: new mongoose.Types.ObjectId(userId), status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
    const thisMonth = new Date();
    thisMonth.setDate(1);
    const thisMonthEarningsResult = await Job.aggregate([
      { 
        $match: { 
          providerId: new mongoose.Types.ObjectId(userId), 
          status: 'completed',
          date: { $gte: thisMonth }
        } 
      },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
    const lastMonth = new Date();
    lastMonth.setMonth(lastMonth.getMonth() - 1);
    lastMonth.setDate(1);
    const lastMonthEarningsResult = await Job.aggregate([
      { 
        $match: { 
          providerId: new mongoose.Types.ObjectId(userId), 
          status: 'completed',
          date: { 
            $gte: lastMonth,
            $lt: thisMonth
          }
        } 
      },
      { $group: { _id: null, total: { $sum: '$payment' } } }
    ]);
    
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
      { $match: { providerId: new mongoose.Types.ObjectId(userId), status: 'completed' } },
      { $group: { _id: null, average: { $avg: '$payment' } } }
    ]);
    
    // Calculate growth percentage
    const thisMonthEarnings = thisMonthEarningsResult.length > 0 ? thisMonthEarningsResult[0].total : 0;
    const lastMonthEarnings = lastMonthEarningsResult.length > 0 ? lastMonthEarningsResult[0].total : 0;
    const growth = lastMonthEarnings > 0 
      ? ((thisMonthEarnings - lastMonthEarnings) / lastMonthEarnings) * 100 
      : 0;
    
    // Get recent transactions
    const recentTransactions = await Job.find({ providerId: userId })
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
      method: transaction.paymentMethod || 'Unknown',
      category: transaction.category || 'other'
    }));
    
    // Prepare response
    const earningsData = {
      total: totalEarningsResult.length > 0 ? totalEarningsResult[0].total : 0,
      thisMonth: thisMonthEarnings,
      lastMonth: lastMonthEarnings,
      pending: pendingEarningsResult.length > 0 ? pendingEarningsResult[0].total : 0,
      growth: Math.round(growth * 10) / 10,
      avgPerJob: avgPerJobResult.length > 0 ? Math.round(avgPerJobResult[0].average) : 0,
      currency: user.currency || 'USD'
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
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const userWithProfileImage = {
      ...user.toObject(),
      profileImage: user.profilePicture || ''
    };

    res.json({
      success: true,
      data: { user: userWithProfileImage }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user profile'
    });
  }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phoneNumber, address, services, hourlyRate, experience, profileImage } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;
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
      message: 'Failed to update profile'
    });
  }
});

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
app.use((req, res, next) => {
  if (req.originalUrl.includes('/api/gallery/upload')) {
    console.log('=== GALLERY UPLOAD DEBUG ===');
    console.log('Content-Type:', req.headers['content-type']);
    console.log('Auth header present:', !!req.headers.authorization);
    console.log('Body keys:', Object.keys(req.body));
    next();
  } else {
    next();
  }
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