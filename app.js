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
const allowedOrigins = process.env.NODE_ENV === 'production' 
  ? [
      'https://homeheroes.help',
      'https://www.homeheroes.help',
      'https://backendhomeheroes.onrender.com',
    ]
  : [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:5173',
      'http://localhost:4173',
      'http://localhost:5174',
      'http://127.0.0.1:3000',
      'http://localhost:3001'
    ];



app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? true // Allow all origins in production
    : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

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

    // FIXED: Use consistent URL construction
    const protocol = req.secure ? 'https' : 'http';
    const host = req.get('host');
    const imageUrl = `/uploads/profiles/${fileName}`;
    const fullImageUrl = `${protocol}://${host}${imageUrl}`;

    // Update user profile with both relative and absolute URLs
    await User.findByIdAndUpdate(req.user.id, { 
      profileImage: imageUrl,
      profileImageFull: fullImageUrl // Store full URL for redundancy
    });

    res.json({
      success: true,
      message: 'Profile image uploaded successfully',
      data: { 
        imageUrl,
        fullImageUrl 
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
    
    // Handle profile images
    if (req.path.includes('/profiles/')) {
      const filename = path.basename(req.path);
      const userId = filename.split('-')[1];
      
      if (userId && mongoose.Types.ObjectId.isValid(userId)) {
        return User.findById(userId)
          .then(user => {
            if (user && user.profileImageFull) {
              return res.redirect(user.profileImageFull);
            }
            return res.redirect('https://via.placeholder.com/400x400/e2e8f0/64748b?text=Profile+Image');
          })
          .catch(() => {
            return res.redirect('https://via.placeholder.com/400x400/e2e8f0/64748b?text=Profile+Image');
          });
      }
    }
    
    // NEW: Handle gallery images
    if (req.path.includes('/gallery/')) {
      const filename = path.basename(req.path);
      // Try to find the gallery image by filename
      return Gallery.findOne({ imageUrl: `/uploads/gallery/${filename}` })
        .then(image => {
          if (image && image.fullImageUrl) {
            return res.redirect(image.fullImageUrl);
          }
          return res.redirect('https://via.placeholder.com/600x400/e2e8f0/64748b?text=Gallery+Image');
        })
        .catch(() => {
          return res.redirect('https://via.placeholder.com/600x400/e2e8f0/64748b?text=Gallery+Image');
        });
    }
    
    // Return placeholder for other images
    return res.redirect('https://via.placeholder.com/400x400/e2e8f0/64748b?text=Image+Not+Found');
  }
  next();
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

// In your server.js file, update the /api/providers endpoint:

// app.get('/api/providers', async (req, res) => {
//   try {
//     const { 
//       service, 
//       location, 
//       availableNow, // This will be 'true' for immediate service type
//       page = 1,
//       limit = 50
//     } = req.query;
    
//     console.log('📥 Provider query params:', { service, location, availableNow });
    
//     // Base query - show all active providers by default
//     let query = { 
//       userType: { $in: ['provider', 'both'] },
//       isActive: true 
//     };
    
//     console.log('🔍 Base query before filters:', JSON.stringify(query));
    
//     let currentUserId = null;
//     try {
//       const authHeader = req.headers['authorization'];
//       if (authHeader) {
//         const token = authHeader.split(' ')[1];
//         if (token) {
//           const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production');
//           currentUserId = decoded.id;
//           console.log('👤 Current user ID:', currentUserId);
          
//           // Exclude current user from results
//           query._id = { $ne: new mongoose.Types.ObjectId(currentUserId) };
//           console.log('🚫 Excluding current user from provider results');
//         }
//       }
//     } catch (tokenError) {
//       console.log('🔐 No valid auth token or token error, not excluding any users');
//     }
    
//     // Filter by service if provided and not empty
//     if (service && service.trim() !== '' && service !== 'all') {
//       query.services = { 
//         $in: [new RegExp(service, 'i')] 
//       };
//       console.log('🔍 Added service filter:', service);
//     } else {
//       console.log('🔧 No service filter applied');
//     }
    
//     // Filter by location if provided and not empty
//     if (location && location.trim() !== '' && location !== 'all') {
//       const locationLower = location.toLowerCase();
//       query.$or = [
//         { city: { $regex: locationLower, $options: 'i' } },
//         { state: { $regex: locationLower, $options: 'i' } },
//         { country: { $regex: locationLower, $options: 'i' } },
//         { address: { $regex: locationLower, $options: 'i' } }
//       ];
//       console.log('🔍 Added location filter:', location);
//     } else {
//       console.log('🌍 No location filter applied');
//     }
    
//     // CRITICAL FIX: Only filter by availability if explicitly requested
//     // For immediate service type, availableNow will be 'true'
//     if (availableNow === 'true') {
//       // Include providers who are available now OR providers who don't have this field set
//       query.$or = [
//         { isAvailableNow: true },
//         { isAvailableNow: { $exists: false } }, // Include providers without this field
//         { isAvailableNow: null } // Include providers with null value
//       ];
//       console.log('🔍 Added availability filter: now (including providers without availability field)');
//     } else {
//       console.log('⏰ No availability filter applied - showing all providers');
//       // Don't filter by availability at all - show all providers
//     }
    
//     console.log('📋 Final MongoDB query:', JSON.stringify(query, null, 2));
    
//     const skip = (parseInt(page) - 1) * parseInt(limit);
    
//     // Get providers with the query
//     const providers = await User.find(query)
//       .select('name email services hourlyRate averageRating city state country profileImage isAvailableNow experience phoneNumber address reviewCount completedJobs isVerified isTopRated responseTime rating _id')
//       .skip(skip)
//       .limit(parseInt(limit));
    
//     const totalProviders = await User.countDocuments(query);
    
//     console.log('✅ Providers found with query:', providers.length);
//     console.log('📊 Providers details:', providers.map(p => ({
//       name: p.name,
//       email: p.email,
//       services: p.services && p.services.length > 0 ? p.services : ['No services'],
//       city: p.city || 'No city',
//       state: p.state || 'No state', 
//       country: p.country || 'No country',
//       isAvailableNow: p.isAvailableNow
//     })));
    
//     // Calculate match scores and sort providers
//     const scoredProviders = providers.map((provider) => {
//       let score = 50; // Base score for all providers
      
//       // Service match scoring
//       if (service && service.trim() !== '') {
//         const serviceLower = service.toLowerCase();
//         const providerServices = Array.isArray(provider.services) ? provider.services : [];
        
//         if (providerServices.length === 0) {
//           // Give some score even if no services specified
//           score += 5;
//         } else {
//           // Exact match gets highest score
//           if (providerServices.some(s => s.toLowerCase() === serviceLower)) {
//             score += 100;
//           }
//           // Partial match gets medium score
//           else if (providerServices.some(s => s.toLowerCase().includes(serviceLower))) {
//             score += 50;
//           }
//           // Any service match gets base score
//           else {
//             score += 10;
//           }
//         }
//       } else if (Array.isArray(provider.services) && provider.services.length > 0) {
//         // Bonus for having services defined when no specific service filter
//         score += 15;
//       }
      
//       // Location match scoring
//       if (location && location.trim() !== '') {
//         const locationLower = location.toLowerCase().trim();
//         const providerAddress = (provider.address || '').toLowerCase();
//         const providerCity = (provider.city || '').toLowerCase();
//         const providerState = (provider.state || '').toLowerCase();
//         const providerCountry = (provider.country || '').toLowerCase();
        
//         // Check for exact matches
//         if (providerCity === locationLower) score += 80;
//         else if (providerState === locationLower) score += 70;
//         else if (providerCountry === locationLower) score += 60;
//         // Check for partial matches
//         else if (providerCity.includes(locationLower)) score += 40;
//         else if (providerState.includes(locationLower)) score += 30;
//         else if (providerCountry.includes(locationLower)) score += 20;
//         else if (providerAddress.includes(locationLower)) score += 50;
//       }
      
//       // Availability scoring (for immediate service type)
//       if (availableNow === 'true') {
//         if (provider.isAvailableNow === true) {
//           score += 60;
//         } else if (provider.isAvailableNow === undefined || provider.isAvailableNow === null) {
//           score += 20; // Some score for providers without availability info
//         }
//       }
      
//       // Rating scoring (higher ratings get better scores)
//       const rating = provider.averageRating || provider.rating || 4.0;
//       score += rating * 10;
      
//       // Verified providers get bonus
//       if (provider.isVerified) {
//         score += 25;
//       }
      
//       // Top-rated providers get bonus
//       if (provider.isTopRated) {
//         score += 35;
//       }
      
//       // More reviews indicate more experience
//       const reviewCount = provider.reviewCount || 0;
//       score += Math.min(reviewCount / 10, 20);
      
//       return {
//         ...provider.toObject(),
//         _matchScore: score
//       };
//     });
    
//     // Sort by match score (highest first), then by rating, then by review count
//     scoredProviders.sort((a, b) => {
//       if (b._matchScore !== a._matchScore) {
//         return b._matchScore - a._matchScore;
//       }
      
//       const ratingA = a.averageRating || a.rating || 4.0;
//       const ratingB = b.averageRating || b.rating || 4.0;
//       if (ratingB !== ratingA) {
//         return ratingB - ratingA;
//       }
      
//       const reviewsA = a.reviewCount || 0;
//       const reviewsB = b.reviewCount || 0;
//       return reviewsB - reviewsA;
//     });
    
//     // Transform providers to ensure consistent format
//     const transformedProviders = scoredProviders.map((provider) => {
//       // Ensure services is always an array
//       let services = [];
//       if (Array.isArray(provider.services)) {
//         services = provider.services;
//       } else if (typeof provider.services === 'string') {
//         services = [provider.services];
//       }
      
//       return {
//         ...provider,
//         _matchScore: undefined, // Remove from final output
//         services: services,
//         averageRating: provider.averageRating || provider.rating || 4.0,
//         reviewCount: provider.reviewCount || 0,
//         completedJobs: provider.completedJobs || 0,
//         isVerified: provider.isVerified !== undefined ? provider.isVerified : false,
//         isTopRated: provider.isTopRated !== undefined ? provider.isTopRated : false,
//         isAvailableNow: provider.isAvailableNow !== undefined ? provider.isAvailableNow : true,
//         responseTime: provider.responseTime || 'within 1 hour',
//         hourlyRate: provider.hourlyRate || 0
//       };
//     });
    
//     console.log('📍 Search location was:', location);
//     console.log('🔧 Search service was:', service);
//     console.log('⏰ Available now filter:', availableNow);
//     console.log('🏆 All providers count:', transformedProviders.length);
//     console.log('📋 All providers:', transformedProviders.map(p => p.name));
    
//     res.json({
//       success: true,
//       data: {
//         providers: transformedProviders,
//         pagination: {
//           currentPage: parseInt(page),
//           totalPages: Math.ceil(totalProviders / parseInt(limit)),
//           totalProviders,
//           hasNextPage: parseInt(page) < Math.ceil(totalProviders / parseInt(limit)),
//           hasPrevPage: parseInt(page) > 1,
//           limit: parseInt(limit)
//         }
//       }
//     });
    
//   } catch (error) {
//     console.error('❌ Error fetching providers:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to fetch providers',
//       error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
//     });
//   }
// });

// In your server.js file, update the location filtering part of the /api/providers endpoint:

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

// Favorites endpoint
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

// Keep your existing PUT endpoint
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  console.log('Sending data to backend:', {
  ...editForm,
  city: editForm.city,
  state: editForm.state,
  country: editForm.country
});
  try {
    const { 
      name, 
      phoneNumber, 
      address, 
      city,        // Make sure these are included
      state,       // in the destructuring
      country,     // here
      services, 
      hourlyRate, 
      experience, 
      profileImage 
    } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name.trim();
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (address) updateData.address = address;
    if (city) updateData.city = city;           // Make sure these are
    if (state) updateData.state = state;        // being added to
    if (country) updateData.country = country;  // updateData object
    
    // ... rest of the code
  } catch (error) {
    // error handling
  }
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
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Check if origin is allowed
  if (allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
      return res.status(200).end();
    }
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