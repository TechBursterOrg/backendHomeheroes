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
import Gallery from './models/Gallery.js';
import multer from 'multer'; // Added for error handling
import { Message } from './models/Message.js';
import { Conversation } from './models/Conversation.js';
import ServiceRequest from './models/ServiceRequest.js';
import Booking from './models/Booking.js';
import nodemailer from 'nodemailer';
import messageRoutes from './routes/messages.routes.js';
import jobRoutes from './routes/jobs.routes.js';
import bcrypt from 'bcryptjs';
import Notification from './models/Notification.js';
import Rating from './models/Rating.js';
import { Storage } from '@google-cloud/storage';
import ratingRoutes from './routes/ratings.routes.js';
import Schedule from './models/Schedule.js'; // Adjust path as needed
import providerRoutes from './routes/providers.routes.js';
import cron from 'node-cron';
import favoritesRoutes from './routes/favorites.js';


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
  ? '.env.production'  // Correct file name with dot
  : '.env';

console.log('🔍 Searching for service account key files...\n');

// Common locations to check
const searchLocations = [
  __dirname, // Current directory
  path.join(__dirname, '..'), // Parent directory
  path.join(process.env.HOME, 'Downloads'), // Downloads folder
  path.join(process.env.HOME, 'Desktop'), // Desktop
  path.join(process.env.HOME), // Home directory
];

const filePatterns = [
  '*.json',
  'service-account*.json',
  'google*.json',
  'key*.json',
  'gcs*.json',
  'lofty-object*.json',
  'decent-carving*.json'
];

let foundFiles = [];

searchLocations.forEach(location => {
  if (fs.existsSync(location)) {
    console.log(`📁 Searching: ${location}`);
    
    try {
      const files = fs.readdirSync(location);
      
      files.forEach(file => {
        const filePath = path.join(location, file);
        const stat = fs.statSync(filePath);
        
        if (stat.isFile() && file.endsWith('.json')) {
          // Check if it looks like a service account key
          try {
            const content = fs.readFileSync(filePath, 'utf8');
            const jsonData = JSON.parse(content);
            
            if (jsonData.type === 'service_account' && 
                jsonData.project_id && 
                jsonData.private_key) {
              console.log(`✅ FOUND SERVICE ACCOUNT KEY: ${filePath}`);
              foundFiles.push({
                path: filePath,
                project: jsonData.project_id,
                email: jsonData.client_email
              });
            }
          } catch (e) {
            // Not a valid JSON or service account file
          }
        }
      });
    } catch (error) {
      console.log(`   Cannot read directory: ${error.message}`);
    }
  }
});
console.log('\n📊 Search Results:');
if (foundFiles.length > 0) {
  foundFiles.forEach((file, index) => {
    console.log(`${index + 1}. ${file.path}`);
    console.log(`   Project: ${file.project}`);
    console.log(`   Email: ${file.email}\n`);
  });
} else {
  console.log('❌ No service account key files found.');
  console.log('\n💡 You need to download a service account key from Google Cloud Console.');
}
const envFiles = ['.env', '.env.production', '.env.development'];

console.log(`Loading environment from: ${envFile}`);
console.log(`Current directory: ${__dirname}`);
console.log(`File exists: ${fs.existsSync(path.resolve(__dirname, envFile))}`);

dotenv.config({ path: path.resolve(__dirname, envFile) });

const app = express();
const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://homehero:7cuMFr33u7jhrbOh@homehero.b4bixqd.mongodb.net/homehero?retryWrites=true&w=majority';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secure-jwt-secret-key-change-in-production-2025';

const storage = new Storage({
  keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
  projectId: 'decent-carving-474920-v0' // This must match your service account file
});

console.log('🔍 Environment Diagnostic Report:');
console.log('================================');


envFiles.forEach(envFile => {
  const envPath = path.join(__dirname, envFile);
  if (fs.existsSync(envPath)) {
    console.log(`\n📁 Found: ${envFile}`);
    const envContent = fs.readFileSync(envPath, 'utf8');
    const lines = envContent.split('\n').filter(line => 
      line.trim() && !line.startsWith('#') && line.includes('=')
    );
    
    lines.forEach(line => {
      const [key] = line.split('=');
      if (key.includes('GOOGLE') || key.includes('GCLOUD') || key.includes('BUCKET')) {
        console.log(`   ${line}`);
      }
    });
  }
});

app.use('/api/providers', favoritesRoutes);
console.log('\n🔧 Current Process Environment:');
console.log('GOOGLE_APPLICATION_CREDENTIALS:', process.env.GOOGLE_APPLICATION_CREDENTIALS || 'NOT SET');
console.log('GCLOUD_PROJECT_ID:', process.env.GCLOUD_PROJECT_ID || 'NOT SET');
console.log('GCLOUD_BUCKET_NAME:', process.env.GCLOUD_BUCKET_NAME || 'NOT SET');
console.log('NODE_ENV:', process.env.NODE_ENV || 'NOT SET');

// Check if the key file exists

try {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    const keyExists = fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS);
    if (!keyExists) {
      console.log('⚠️ Google Cloud key file not found, disabling GCS features');
      // Set a flag to disable GCS-dependent routes
      process.env.GCS_DISABLED = 'true';
    }
  }
} catch (error) {
  console.log('⚠️ GCS initialization skipped:', error.message);
  process.env.GCS_DISABLED = 'true';
}


if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  const keyExists = fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS);
  console.log('\n🔑 Service Account Key File:');
  console.log('Exists:', keyExists);
  if (keyExists) {
    try {
      const keyContent = fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, 'utf8');
      const keyData = JSON.parse(keyContent);
      console.log('Project ID in key:', keyData.project_id);
      console.log('Client Email:', keyData.client_email);
      console.log('Key Type:', keyData.type);
    } catch (error) {
      console.log('❌ Error reading key file:', error.message);
    }
  }
}

const bucketName = process.env.GCLOUD_BUCKET_NAME || 'home-heroes-bucket';
const bucket = storage.bucket(bucketName);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

const uploadToGCS = (file, folder = 'gallery') => {
  return new Promise((resolve, reject) => {
    try {
      console.log('📤 Starting GCS upload...', {
        originalName: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
        folder: folder,
        bucket: bucketName
      });

      if (!file || !file.buffer) {
        throw new Error('Invalid file object');
      }

      const extension = path.extname(file.originalname) || '.jpg';
      const filename = `${folder}/${Date.now()}-${Math.round(Math.random() * 1E9)}${extension}`;
      
      console.log('📝 Generated filename:', filename);

      const blob = bucket.file(filename);
      
      // Remove ALL ACL-related settings
      const blobStream = blob.createWriteStream({
        metadata: {
          contentType: file.mimetype || 'application/octet-stream',
          metadata: {
            originalName: file.originalname,
            uploadedAt: new Date().toISOString(),
            uploadedBy: 'homehero-app'
          }
        },
        resumable: false,
        validation: 'md5'
      });

      let uploadSuccess = false;

      blobStream.on('error', (error) => {
        console.error('❌ GCS Upload Stream Error:', error);
        if (!uploadSuccess) {
          reject(new Error(`Unable to upload image: ${error.message}`));
        }
      });

      blobStream.on('finish', async () => {
        try {
          uploadSuccess = true;
          console.log('✅ File uploaded successfully, verifying...');
          
          // Verify the file was uploaded
          const [exists] = await blob.exists();
          if (!exists) {
            throw new Error('File upload verification failed');
          }

          // REMOVED: blob.makePublic() - No ACL operations!
          
          // If bucket is public, this URL will work
          const publicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
          
          console.log('✅ File available at:', publicUrl);
          
          resolve({
            filename: blob.name,
            url: publicUrl,
            bucket: bucket.name,
            size: file.size,
            contentType: file.mimetype,
            uploadedAt: new Date().toISOString()
          });
        } catch (error) {
          console.error('❌ GCS Upload Verification Error:', error);
          try {
            await blob.delete();
          } catch (deleteError) {
            console.error('❌ Failed to cleanup file:', deleteError);
          }
          reject(new Error('Unable to verify file upload'));
        }
      });

      console.log('🚀 Starting file upload to GCS...');
      blobStream.end(file.buffer);
      
    } catch (error) {
      console.error('❌ GCS Upload Setup Error:', error);
      reject(error);
    }
  });
};
app.get('/api/test-providers', async (req, res) => {
  try {
    console.log('✅ Test endpoint hit from origin:', req.headers.origin);
    
    const { limit = 20, availableNow } = req.query;
    
    // Set proper CORS headers
    res.header('Access-Control-Allow-Origin', req.headers.origin || 'http://localhost:5173');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    // Simple query
    let query = { userType: { $in: ['provider', 'both'] } };
    
    if (availableNow === 'true') {
      query.isAvailableNow = true;
    }
    
    const providers = await User.find(query)
      .select('name email services hourlyRate city state country profileImage isAvailableNow experience rating reviewCount phoneNumber address completedJobs isVerified isTopRated responseTime')
      .limit(parseInt(limit))
      .lean();
    
    res.json({
      success: true,
      data: {
        providers: providers.map(p => ({
          ...p,
          id: p._id,
          averageRating: p.rating || 0,
          location: `${p.city || ''}, ${p.state || ''}`.trim() || 'Location not specified'
        }))
      }
    });
  } catch (error) {
    console.error('Test providers error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch test providers'
    });
  }
});

app.get('/api/cors-test', (req, res) => {
  console.log('🌐 CORS Test Request:', {
    origin: req.headers.origin,
    host: req.headers.host,
    method: req.method,
    url: req.url
  });
  
  res.header('Access-Control-Allow-Origin', req.headers.origin || 'http://localhost:5173');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  res.json({
    success: true,
    message: 'CORS test successful!',
    data: {
      timestamp: new Date().toISOString(),
      origin: req.headers.origin,
      allowed: true,
      environment: process.env.NODE_ENV
    }
  });
});

app.get('/api/debug/gcs-setup', async (req, res) => {
  try {
    const keyFilePath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    const keyFileExists = fs.existsSync(keyFilePath);
    
    let serviceAccountInfo = null;
    if (keyFileExists) {
      const keyFileContent = fs.readFileSync(keyFilePath, 'utf8');
      serviceAccountInfo = JSON.parse(keyFileContent);
    }

    const config = {
      keyFilePath: keyFilePath,
      keyFileExists: keyFileExists,
      projectId: process.env.GCLOUD_PROJECT_ID,
      bucketName: process.env.GCLOUD_BUCKET_NAME,
      serviceAccount: serviceAccountInfo ? {
        project_id: serviceAccountInfo.project_id,
        client_email: serviceAccountInfo.client_email,
        private_key_id: serviceAccountInfo.private_key_id ? 'Set' : 'Missing'
      } : 'No service account file found'
    };

    console.log('🔧 GCS Setup Debug:', config);
    
    res.json({
      success: true,
      data: config
    });
  } catch (error) {
    console.error('GCS setup debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Test bucket connectivity
app.get('/api/debug/gcs-test', async (req, res) => {
  try {
    console.log('🧪 Testing GCS connectivity...');
    
    // Test 1: Check if we can access the storage API
    const [buckets] = await storage.getBuckets();
    console.log('✅ Can list buckets');
    
    // Test 2: Check if our specific bucket exists
    const [exists] = await bucket.exists();
    if (!exists) {
      throw new Error(`Bucket ${bucketName} does not exist in project decent-carving-474920-v0`);
    }
    console.log('✅ Bucket exists:', bucketName);
    
    // Test 3: Try to get bucket metadata
    const [metadata] = await bucket.getMetadata();
    console.log('✅ Can access bucket metadata');
    
    res.json({
      success: true,
      message: 'GCS connectivity test passed',
      data: {
        bucketExists: exists,
        bucketName: bucketName,
        location: metadata.location,
        storageClass: metadata.storageClass
      }
    });
    
  } catch (error) {
    console.error('❌ GCS test failed:', error);
    res.status(500).json({
      success: false,
      message: 'GCS test failed',
      error: error.message,
      suggestion: 'Make sure the service account has access to the bucket in the Google Cloud Console'
    });
  }
});

app.get('/api/debug/service-account-info', (req, res) => {
  try {
    const keyFilePath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    const keyFileContent = fs.readFileSync(keyFilePath, 'utf8');
    const serviceAccount = JSON.parse(keyFileContent);
    
    const info = {
      serviceAccountProject: serviceAccount.project_id,
      clientEmail: serviceAccount.client_email,
      privateKeyId: serviceAccount.private_key_id,
      envProjectId: process.env.GCLOUD_PROJECT_ID,
      bucketName: process.env.GCLOUD_BUCKET_NAME,
      projectMatch: serviceAccount.project_id === process.env.GCLOUD_PROJECT_ID
    };
    
    console.log('🔍 Service Account Analysis:', info);
    
    res.json({
      success: true,
      data: info
    });
  } catch (error) {
    console.error('Service account analysis error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


const deleteFromGCS = async (fileUrl) => {
  try {
    if (!fileUrl) {
      console.log('⚠️ No file URL provided for deletion');
      return false;
    }

    console.log('🗑️ Attempting to delete from GCS:', fileUrl);

    let filename;
    
    // Extract filename from different URL formats
    if (fileUrl.includes('storage.googleapis.com')) {
      // https://storage.googleapis.com/bucket-name/folder/filename.jpg
      const urlParts = fileUrl.split('/');
      filename = urlParts.slice(4).join('/'); // Remove https://storage.googleapis.com/bucket-name/
    } else if (fileUrl.includes(bucketName)) {
      // Direct bucket reference
      filename = fileUrl.split(`${bucketName}/`)[1];
    } else {
      // Assume it's already a filename
      filename = fileUrl;
    }

    if (!filename) {
      console.log('⚠️ Could not extract filename from URL');
      return false;
    }

    console.log('📝 Extracted filename for deletion:', filename);

    const file = bucket.file(filename);
    const [exists] = await file.exists();

    if (!exists) {
      console.log('⚠️ File does not exist in GCS:', filename);
      return false;
    }

    await file.delete();
    console.log('✅ Successfully deleted file from GCS:', filename);
    return true;

  } catch (error) {
    console.error('❌ GCS delete error:', error);
    
    // Don't throw error for delete failures in production
    if (process.env.NODE_ENV === 'production') {
      console.log('⚠️ Delete failed but continuing...');
      return false;
    }
    throw error;
  }
};


app.get('/api/debug/gcs-quick-test', async (req, res) => {
  try {
    console.log('🧪 Quick GCS Test...');
    
    // Test basic authentication
    const [buckets] = await storage.getBuckets();
    console.log('✅ Authentication successful');
    
    // Test specific bucket access
    const [bucketExists] = await bucket.exists();
    console.log('✅ Bucket exists:', bucketExists);
    
    res.json({
      success: true,
      message: 'GCS connection successful!',
      projectId: 'decent-carving-474920-v0',
      bucketName: bucketName,
      bucketExists: bucketExists
    });
    
  } catch (error) {
    console.error('❌ Quick test failed:', error.message);
    res.status(500).json({
      success: false,
      message: 'GCS test failed',
      error: error.message,
      currentProject: 'decent-carving-474920-v0',
      suggestion: 'Check if bucket exists in this project and service account has permissions'
    });
  }
});

// Service account verification endpoint
app.get('/api/debug/verify-service-account', (req, res) => {
  try {
    const keyFilePath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    const keyFileContent = fs.readFileSync(keyFilePath, 'utf8');
    const serviceAccount = JSON.parse(keyFileContent);
    
    const config = {
      serviceAccountProject: serviceAccount.project_id,
      configuredProject: 'decent-carving-474920-v0',
      clientEmail: serviceAccount.client_email,
      matches: serviceAccount.project_id === 'decent-carving-474920-v0'
    };
    
    console.log('🔍 Service Account Verification:', config);
    
    res.json({
      success: true,
      data: config,
      message: config.matches ? '✅ Project IDs match!' : '❌ Project IDs do not match!'
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


// Initialize email transporter
console.log('🚀 Starting email service initialization...');
initializeEmailTransporter().then(success => {
  if (success) {
    console.log('✅ Email service initialized successfully');
  } else {
    console.log('⚠️ Email service running in simulation mode');
  }
});

//...app.use

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.NODE_ENV === 'production' 
      ? [
          'https://homeheroes.help',
          'https://www.homeheroes.help',
          'https://backendhomeheroes.onrender.com'
        ]
      : [
          'http://localhost:5173',
          'http://localhost:5174',
          'http://localhost:3000',
          'http://localhost:5175'
        ];
    
    if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('localhost')) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));



app.options('*', cors());

// Then body parsers - CRITICAL FIX
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

// Then other middleware
app.use(morgan('dev'));
app.use(cookieParser());

// Debug middleware to check body parsing
app.use((req, res, next) => {
  // Skip favicon requests
  if (req.url === '/favicon.ico') {
    return res.status(204).end();
  }
  next();
});


app.use((error, req, res, next) => {
  console.error('🚨 Unhandled Error:', {
    url: req.url,
    method: req.method,
    error: error.message,
    stack: error.stack,
    body: req.body
  });
  next(error);
});


// ==================== UPLOAD DIRECTORY SETUP ====================

app.post('/api/gallery/upload', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    console.log('=== GALLERY UPLOAD TO GOOGLE CLOUD STORAGE ===');
    
    if (!req.file) {
      console.log('❌ No image file uploaded');
      return res.status(400).json({
        success: false,
        message: 'No image file provided. Please select an image.'
      });
    }

    const { title, description, category, tags, featured } = req.body;

    // Validate required fields
    if (!title || !title.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Title is required'
      });
    }

    // Validate file
    if (!req.file.mimetype.startsWith('image/')) {
      return res.status(400).json({
        success: false,
        message: 'Only image files are allowed'
      });
    }

    if (req.file.size > 5 * 1024 * 1024) {
      return res.status(400).json({
        success: false,
        message: 'File size must be less than 5MB'
      });
    }

    console.log('📤 Uploading to Google Cloud Storage...');
    
    // Upload to Google Cloud Storage with retry logic
    let uploadResult;
    try {
      uploadResult = await uploadToGCS(req.file, 'gallery');
      console.log('✅ Image uploaded to GCS:', uploadResult.url);
    } catch (uploadError) {
      console.error('❌ GCS upload failed:', uploadError);
      return res.status(500).json({
        success: false,
        message: 'Failed to upload image to cloud storage',
        error: process.env.NODE_ENV === 'development' ? uploadError.message : 'Storage service error'
      });
    }

    // Create gallery entry with GCS URL
    const newImage = new Gallery({
      title: title.trim(),
      description: description ? description.trim() : '',
      category: category || 'other',
      imageUrl: uploadResult.url,
      fullImageUrl: uploadResult.url,
      userId: req.user.id,
      tags: tags ? tags.split(',').map(tag => tag.trim()).filter(tag => tag) : [],
      featured: featured === 'true' || featured === true,
      storageInfo: {
        provider: 'gcs',
        bucket: uploadResult.bucket,
        filename: uploadResult.filename,
        uploadedAt: uploadResult.uploadedAt
      }
    });

    // Save to database
    const savedImage = await newImage.save();
    await savedImage.populate('userId', 'name profileImage');

    console.log('💾 Image saved to database:', savedImage._id);

    res.status(201).json({
      success: true,
      message: 'Image uploaded successfully to cloud storage',
      data: savedImage
    });
    
  } catch (error) {
    console.error('❌ Gallery upload error:', error);
    
    let errorMessage = 'Failed to upload image';
    let statusCode = 500;
    
    if (error.name === 'ValidationError') {
      errorMessage = 'Invalid data: ' + Object.values(error.errors).map(e => e.message).join(', ');
      statusCode = 400;
    } else if (error.message.includes('Only image files')) {
      errorMessage = 'Only image files are allowed (jpg, png, gif, etc.)';
      statusCode = 400;
    } else if (error.message.includes('File too large')) {
      errorMessage = 'File size must be less than 5MB';
      statusCode = 400;
    }
    
    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
});


app.post('/api/auth/profile/image', authenticateToken, upload.single('profileImage'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No image file provided'
      });
    }

    console.log('📤 Uploading profile image to Google Cloud Storage...');
    
    // Upload to Google Cloud Storage
    let uploadResult;
    try {
      uploadResult = await uploadToGCS(req.file, 'profiles');
      console.log('✅ Profile image uploaded to GCS:', uploadResult.url);
    } catch (uploadError) {
      console.error('❌ Profile image upload failed:', uploadError);
      return res.status(500).json({
        success: false,
        message: 'Failed to upload profile image to cloud storage'
      });
    }

    // Update user profile with the GCS URL
    await User.findByIdAndUpdate(req.user.id, { 
      profileImage: uploadResult.url,
      profileImageFull: uploadResult.url
    });

    res.json({
      success: true,
      message: 'Profile image uploaded successfully to cloud storage',
      data: { 
        imageUrl: uploadResult.url
      }
    });
  } catch (error) {
    console.error('❌ Profile image upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload profile image',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/gcs/stats', authenticateToken, async (req, res) => {
  try {
    const [files] = await bucket.getFiles({ 
      prefix: 'gallery/',
      maxResults: 1000 
    });
    
    const [profileFiles] = await bucket.getFiles({
      prefix: 'profiles/',
      maxResults: 1000
    });

    const galleryCount = files.length;
    const profileCount = profileFiles.length;

    // Calculate total size
    let totalSize = 0;
    files.forEach(file => totalSize += file.metadata.size || 0);
    profileFiles.forEach(file => totalSize += file.metadata.size || 0);

    res.json({
      success: true,
      data: {
        bucket: bucketName,
        totalFiles: galleryCount + profileCount,
        galleryFiles: galleryCount,
        profileFiles: profileCount,
        totalSize: totalSize,
        totalSizeMB: (totalSize / (1024 * 1024)).toFixed(2)
      }
    });
  } catch (error) {
    console.error('GCS stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get storage statistics'
    });
  }
});

app.post('/api/gcs/cleanup', authenticateToken, async (req, res) => {
  try {
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const [allFiles] = await bucket.getFiles();
    const galleryImages = await Gallery.find({});
    const users = await User.find({ profileImage: { $ne: '' } });

    // Extract URLs from database
    const dbImageUrls = new Set();
    galleryImages.forEach(img => {
      if (img.imageUrl) dbImageUrls.add(img.imageUrl);
      if (img.fullImageUrl) dbImageUrls.add(img.fullImageUrl);
    });
    users.forEach(user => {
      if (user.profileImage) dbImageUrls.add(user.profileImage);
      if (user.profileImageFull) dbImageUrls.add(user.profileImageFull);
    });

    let deletedCount = 0;
    const deletionErrors = [];

    for (const file of allFiles) {
      const fileUrl = `https://storage.googleapis.com/${bucketName}/${file.name}`;
      
      if (!dbImageUrls.has(fileUrl)) {
        try {
          await file.delete();
          deletedCount++;
          console.log(`🗑️ Deleted orphaned file: ${file.name}`);
        } catch (error) {
          deletionErrors.push({ file: file.name, error: error.message });
        }
      }
    }

    res.json({
      success: true,
      message: `Cleanup completed. Deleted ${deletedCount} orphaned files.`,
      data: {
        deletedCount,
        errors: deletionErrors
      }
    });

  } catch (error) {
    console.error('GCS cleanup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cleanup storage'
    });
  }
});

//payment

console.log('🔧 Payment Configuration Check:');
console.log('STRIPE_SECRET_KEY:', process.env.STRIPE_SECRET_KEY ? 'Set' : 'NOT SET');
console.log('STRIPE_PUBLISHABLE_KEY:', process.env.STRIPE_PUBLISHABLE_KEY ? 'Set' : 'NOT SET');
console.log('PAYSTACK_SECRET_KEY:', process.env.PAYSTACK_SECRET_KEY ? 'Set' : 'NOT SET');
console.log('NODE_ENV:', process.env.NODE_ENV);

// Add this endpoint to debug payment processor initialization
app.get('/api/debug/payment-processors', (req, res) => {
  res.json({
    success: true,
    data: {
      paystack: {
        configured: !!process.env.PAYSTACK_SECRET_KEY,
        initialized: !!paymentProcessors?.paystack,
        secretKey: process.env.PAYSTACK_SECRET_KEY ? '***' + process.env.PAYSTACK_SECRET_KEY.slice(-4) : 'NOT SET'
      },
      stripe: {
        configured: !!process.env.STRIPE_SECRET_KEY,
        initialized: !!paymentProcessors?.stripe
      },
      environment: process.env.NODE_ENV
    }
  });
});

const initializePaymentProcessors = async () => {
  const processors = {
    stripe: null,
    paystack: null
  };

  console.log('💰 Payment Processor Initialization Starting...', {
    environment: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  });

  // Initialize Stripe
  if (process.env.STRIPE_SECRET_KEY) {
    try {
      const { default: Stripe } = await import('stripe');
      processors.stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
        apiVersion: '2025-09-30.clover',
      });
      console.log('✅ Stripe initialized successfully');
    } catch (error) {
      console.error('❌ Stripe initialization failed:', error.message);
    }
  } else {
    console.log('⚠️ Stripe secret key not configured');
  }

  // Initialize Paystack with production-specific handling
  const paystackSecretKey = 
    process.env.PAYSTACK_SECRET_KEY || 
    process.env.PAYSTACK_SECRET || 
    process.env.PAYSTACK_KEY;

  if (paystackSecretKey) {
    try {
      console.log('🔧 Initializing Paystack for environment:', process.env.NODE_ENV);
      
      // Enhanced validation for production
      if (!paystackSecretKey.startsWith('sk_')) {
        const errorMsg = 'Invalid Paystack secret key format';
        console.error('❌', errorMsg);
        
        // In production, we need to be more strict
        if (process.env.NODE_ENV === 'production') {
          throw new Error(errorMsg);
        } else {
          console.warn('⚠️ Continuing in development despite invalid key format');
        }
      }

      console.log('🔑 Paystack secret key format is valid');
      
      // Create Paystack client with retry logic for production
      let retryCount = 0;
      const maxRetries = process.env.NODE_ENV === 'production' ? 3 : 1;
      
      while (retryCount < maxRetries) {
        try {
          processors.paystack = await createPaystackClient();
          break;
        } catch (error) {
          retryCount++;
          console.warn(`⚠️ Paystack initialization attempt ${retryCount} failed:`, error.message);
          
          if (retryCount === maxRetries) {
            throw error;
          }
          
          // Wait before retry (exponential backoff)
          await new Promise(resolve => setTimeout(resolve, 1000 * retryCount));
        }
      }
      
      if (!processors.paystack) {
        throw new Error('Paystack client creation failed after retries');
      }

      console.log('✅ Paystack initialized successfully for environment:', process.env.NODE_ENV);
      
    } catch (error) {
      console.error('❌ Paystack initialization failed in environment:', process.env.NODE_ENV);
      console.error('Error details:', error.message);
      
      // In production, we might want to continue without Paystack
      // but log the error for monitoring
      processors.paystack = null;
      
      // Send alert in production (you can integrate with your monitoring system)
      if (process.env.NODE_ENV === 'production') {
        console.error('🚨 PRODUCTION ALERT: Paystack initialization failed');
      }
    }
  } else {
    console.log('⚠️ Paystack secret key not configured in environment:', process.env.NODE_ENV);
    processors.paystack = null;
  }

  console.log('💰 Payment Processor Status:', {
    environment: process.env.NODE_ENV,
    stripe: !!processors.stripe,
    paystack: !!processors.paystack,
    timestamp: new Date().toISOString()
  });

  return processors;
};



app.post('/api/payments/reinitialize', async (req, res) => {
  try {
    console.log('🔄 Manually reinitializing payment processors...');
    
    // Reinitialize payment processors
    const newProcessors = await initializePaymentProcessors();
    
    // Update the global paymentProcessors
    paymentProcessors = newProcessors;
    
    res.json({
      success: true,
      message: 'Payment processors reinitialized',
      data: {
        paystack: {
          configured: !!process.env.PAYSTACK_SECRET_KEY,
          initialized: !!paymentProcessors.paystack
        },
        stripe: {
          configured: !!process.env.STRIPE_SECRET_KEY,
          initialized: !!paymentProcessors.stripe
        }
      }
    });
    
  } catch (error) {
    console.error('Reinitialization error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reinitialize payment processors',
      error: error.message
    });
  }
});



let paymentProcessors;

const initializeAllServices = async () => {
  try {
    console.log('🚀 Initializing all payment services...');
    
    // Step 1: Initialize payment processors
    paymentProcessors = await initializePaymentProcessors();
    
    console.log('💰 Payment processors initialized:', {
      stripe: !!paymentProcessors.stripe,
      paystack: !!paymentProcessors.paystack
    });

    // Step 2: Initialize company account ONLY if Paystack is available
    if (paymentProcessors.paystack) {
      console.log('🏢 Proceeding with company account initialization...');
      await initializeCompanyAccount();
    } else {
      console.log('⚠️ Skipping company account initialization: Paystack not available');
    }

    console.log('✅ All services initialized successfully');
    
  } catch (error) {
    console.error('❌ Failed to initialize services:', error);
    // Don't throw here - we want the server to start even if payment processors fail
  }
};

// Call this when your server starts
initializeAllServices();

app.post('/api/bookings/:bookingId/create-payment-fallback', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { amount } = req.body;

    console.log('🔄 Using fallback payment method for booking:', bookingId);

    // Generate a simple payment reference
    const paymentReference = `HH_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
    
    const paymentResult = {
      success: true,
      processor: 'manual',
      paymentIntentId: paymentReference,
      authorizationUrl: `${process.env.FRONTEND_URL}/manual-payment?reference=${paymentReference}&amount=${amount}`,
      amount: parseFloat(amount),
      currency: 'NGN',
      status: 'requires_payment_method',
      instructions: 'Please make payment via bank transfer and upload proof'
    };

    // Update booking
    const booking = await Booking.findById(bookingId);
    booking.payment = {
      processor: 'manual',
      paymentIntentId: paymentReference,
      amount: paymentResult.amount,
      currency: paymentResult.currency,
      status: paymentResult.status,
      initiatedAt: new Date()
    };
    await booking.save();

    res.json({
      success: true,
      message: 'Manual payment instructions generated',
      data: paymentResult
    });

  } catch (error) {
    console.error('Fallback payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create fallback payment'
    });
  }
});

app.get('/api/debug/env-check', (req, res) => {
  // Check ALL possible environment variable names
  const envVars = {
    // Paystack variables
    PAYSTACK_SECRET_KEY: process.env.PAYSTACK_SECRET_KEY ? '***' + process.env.PAYSTACK_SECRET_KEY.slice(-4) : 'NOT SET',
    PAYSTACK_SECRET_KEY_LENGTH: process.env.PAYSTACK_SECRET_KEY ? process.env.PAYSTACK_SECRET_KEY.length : 0,
    PAYSTACK_PUBLIC_KEY: process.env.PAYSTACK_PUBLIC_KEY ? '***' + process.env.PAYSTACK_PUBLIC_KEY.slice(-4) : 'NOT SET',
    
    // Common alternative names
    PAYSTACK_SECRET: process.env.PAYSTACK_SECRET ? '***' + process.env.PAYSTACK_SECRET.slice(-4) : 'NOT SET',
    PAYSTACK_KEY: process.env.PAYSTACK_KEY ? '***' + process.env.PAYSTACK_KEY.slice(-4) : 'NOT SET',
    
    // Environment
    NODE_ENV: process.env.NODE_ENV,
    RENDER: process.env.RENDER, // Render.com specific
    RENDER_EXTERNAL_URL: process.env.RENDER_EXTERNAL_URL,
    
    // Payment processors status
    paymentProcessorsExists: !!paymentProcessors,
    paystackInitialized: !!paymentProcessors?.paystack
  };

  console.log('🔍 Environment Check:', envVars);
  
  res.json({
    success: true,
    data: envVars
  });
});

app.get('/api/debug/module-check', async (req, res) => {
  try {
    const moduleCheck = {};
    
    // Test axios import
    try {
      const axiosModule = await import('axios');
      moduleCheck.axios = {
        available: true,
        version: axiosModule.default?.VERSION || 'unknown'
      };
    } catch (error) {
      moduleCheck.axios = {
        available: false,
        error: error.message
      };
    }
    
    // Test bcrypt import
    try {
      const bcryptModule = await import('bcryptjs');
      moduleCheck.bcrypt = {
        available: true
      };
    } catch (error) {
      moduleCheck.bcrypt = {
        available: false,
        error: error.message
      };
    }
    
    console.log('📦 Module Check:', moduleCheck);
    
    res.json({
      success: true,
      data: moduleCheck
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});



app.get('/api/payments/status', (req, res) => {
  res.json({
    success: true,
    data: {
      stripe: {
        configured: !!process.env.STRIPE_SECRET_KEY,
        initialized: !!paymentProcessors.stripe,
        publishableKey: !!process.env.STRIPE_PUBLISHABLE_KEY
      },
      paystack: {
        configured: !!process.env.PAYSTACK_SECRET_KEY,
        initialized: !!paymentProcessors.paystack,
        companyAccount: {
          initialized: !!COMPANY_ACCOUNT.paystackRecipientCode,
          recipientCode: COMPANY_ACCOUNT.paystackRecipientCode,
          accountNumber: COMPANY_ACCOUNT.kudaAccountNumber,
          accountName: COMPANY_ACCOUNT.accountName
        }
      },
      gcs: {
        configured: !!process.env.GOOGLE_APPLICATION_CREDENTIALS,
        bucket: process.env.GCLOUD_BUCKET_NAME,
        project: process.env.GCLOUD_PROJECT_ID
      }
    }
  });
});

initializeAllServices();

const initializePaystackWithAxios = async () => {
  try {
    const axios = await import('axios');
    
    const paystackInstance = axios.create({
      baseURL: 'https://api.paystack.co',
      headers: {
        'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    // Create a compatible interface
    return {
      transaction: {
        initialize: (data) => paystackInstance.post('/transaction/initialize', data),
        verify: (reference) => paystackInstance.get(`/transaction/verify/${reference}`),
        list: (params) => paystackInstance.get('/transaction', { params })
      },
      recipient: {
        create: (data) => paystackInstance.post('/transferrecipient', data),
        list: (params) => paystackInstance.get('/transferrecipient', { params })
      },
      transfer: {
        create: (data) => paystackInstance.post('/transfer', data),
        finalize: (data) => paystackInstance.post('/transfer/finalize_transfer', data)
      }
    };
  } catch (error) {
    console.error('❌ Axios-based Paystack initialization failed:', error);
    return null;
  }
};

// Debug endpoint to check Paystack instance
app.get('/api/debug/paystack-instance', (req, res) => {
  try {
    const paystackInfo = {
      initialized: !!paymentProcessors?.paystack,
      hasRecipient: !!paymentProcessors?.paystack?.recipient,
      methods: paymentProcessors?.paystack ? Object.keys(paymentProcessors.paystack) : [],
      recipientMethods: paymentProcessors?.paystack?.recipient ? Object.keys(paymentProcessors.paystack.recipient) : [],
      companyAccount: {
        recipientCode: COMPANY_ACCOUNT.paystackRecipientCode,
        accountNumber: COMPANY_ACCOUNT.kudaAccountNumber,
        accountName: COMPANY_ACCOUNT.accountName
      }
    };

    console.log('🔍 Paystack Debug Info:', paystackInfo);
    
    res.json({
      success: true,
      data: paystackInfo
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Test Paystack recipient creation
app.post('/api/debug/test-recipient-creation', async (req, res) => {
  try {
    if (!paymentProcessors?.paystack) {
      return res.status(400).json({
        success: false,
        message: 'Paystack not initialized'
      });
    }

    // Test with a dummy account first
    const testRecipient = {
      type: 'nuban',
      name: 'Test Account',
      account_number: '0123456789', // Test account number
      bank_code: '058', // GTBank code for testing
      currency: 'NGN'
    };

    console.log('🧪 Testing recipient creation with:', testRecipient);
    
    const result = await paymentProcessors.paystack.recipient.create(testRecipient);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('❌ Recipient creation test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});

app.post('/api/debug/paystack-raw-response', async (req, res) => {
  try {
    const { amount, email } = req.body;
    
    if (!paymentProcessors.paystack) {
      return res.status(400).json({
        success: false,
        message: 'Paystack not initialized'
      });
    }

    const testPayload = {
      amount: Math.round((amount || 10000)), // 100 NGN
      email: email || 'test@example.com',
      currency: 'NGN',
      callback_url: `${process.env.FRONTEND_URL}/payment-verify`
    };

    console.log('🧪 Testing Paystack with payload:', testPayload);

    const response = await paymentProcessors.paystack.transaction.initialize(testPayload);

    console.log('🔍 FULL RAW PAYSTACK RESPONSE STRUCTURE:');
    console.log('Response object keys:', Object.keys(response));
    console.log('Response data keys:', response.data ? Object.keys(response.data) : 'No data');
    console.log('Full response:', JSON.stringify(response, null, 2));

    res.json({
      success: true,
      data: {
        fullResponse: response,
        status: response.status,
        data: response.data,
        authorization_url: response.data?.authorization_url,
        reference: response.data?.reference
      }
    });

  } catch (error) {
    console.error('❌ Paystack raw test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});


app.get('/api/debug/paystack-health', async (req, res) => {
  try {
    if (!paymentProcessors.paystack) {
      return res.json({
        success: false,
        message: 'Paystack not initialized',
        configured: !!process.env.PAYSTACK_SECRET_KEY
      });
    }

    // Test Paystack connection
    const testResponse = await paymentProcessors.paystack.transaction.list({ 
      perPage: 1 
    });

    res.json({
      success: true,
      message: 'Paystack is working correctly',
      data: {
        configured: true,
        testSuccessful: true,
        canListTransactions: testResponse.status
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Paystack health check failed',
      error: error.message,
      configured: !!process.env.PAYSTACK_SECRET_KEY
    });
  }
});

// app.post('/api/bookings/:bookingId/create-payment', authenticateToken, async (req, res) => {
//   try {
//     const { bookingId } = req.params;
//     const { amount, customerCountry = 'NIGERIA' } = req.body;

//     console.log('🔍 Payment Creation Debug:', {
//       bookingId,
//       amount,
//       customerCountry,
//       user: req.user.id,
//       body: req.body
//     });

//     // Input validation
//     if (!bookingId || !mongoose.Types.ObjectId.isValid(bookingId)) {
//       console.log('❌ Invalid booking ID:', bookingId);
//       return res.status(400).json({
//         success: false,
//         message: 'Valid booking ID is required',
//         code: 'INVALID_BOOKING_ID'
//       });
//     }

//     if (!amount || isNaN(amount) || amount <= 0) {
//       console.log('❌ Invalid amount:', amount);
//       return res.status(400).json({
//         success: false,
//         message: 'Valid payment amount is required',
//         code: 'INVALID_AMOUNT'
//       });
//     }

//     // Find booking
//     const booking = await Booking.findById(bookingId).populate('customerId', 'email');
//     if (!booking) {
//       console.log('❌ Booking not found:', bookingId);
//       return res.status(404).json({
//         success: false,
//         message: 'Booking not found',
//         code: 'BOOKING_NOT_FOUND'
//       });
//     }

//     console.log('✅ Booking found:', {
//       bookingId: booking._id,
//       customerId: booking.customerId?._id,
//       currentUserId: req.user.id,
//       bookingStatus: booking.status,
//       existingPayment: booking.payment
//     });

//     // Check authorization
//     if (booking.customerId._id.toString() !== req.user.id) {
//       console.log('❌ Authorization failed:', {
//         bookingCustomer: booking.customerId._id.toString(),
//         currentUser: req.user.id
//       });
//       return res.status(403).json({
//         success: false,
//         message: 'Not authorized to pay for this booking',
//         code: 'UNAUTHORIZED_PAYMENT'
//       });
//     }

//     console.log('✅ Authorization passed, proceeding with payment...');

//     const paymentAmount = parseFloat(amount);
//     const isNigeria = customerCountry === 'NG' || customerCountry === 'Nigeria';
    
//     let paymentResult;

//     if (isNigeria) {
//       // PAYSTACK PAYMENT (Nigeria)
//       console.log('🌍 Using Paystack for Nigerian customer');
      
//       if (!paymentProcessors.paystack) {
//         console.log('❌ Paystack processor not configured');
//         return res.status(503).json({
//           success: false,
//           message: 'Paystack payment processor is not configured',
//           code: 'PAYMENT_PROCESSOR_UNAVAILABLE'
//         });
//       }

//       try {
//         const paystackPayload = {
//           amount: Math.round(paymentAmount * 100),
//           email: req.user.email || booking.customerId.email,
//           currency: 'NGN',
//           metadata: {
//             bookingId: bookingId,
//             customerId: req.user.id,
//             paymentType: 'escrow'
//           },
//           callback_url: `${process.env.FRONTEND_URL}/customer/payment-status?bookingId=${bookingId}&processor=paystack`
//         };

//         console.log('📤 Paystack request payload:', paystackPayload);

//         // Make the Paystack API call
//         const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

//         console.log('📥 Paystack FULL response structure:', {
//           status: paystackResponse.status,
//           dataExists: !!paystackResponse.data,
//           dataKeys: paystackResponse.data ? Object.keys(paystackResponse.data) : 'no data',
//           hasDataData: !!(paystackResponse.data && paystackResponse.data.data),
//           dataDataKeys: paystackResponse.data?.data ? Object.keys(paystackResponse.data.data) : 'no data.data'
//         });

//         // CRITICAL FIX: Handle different Paystack response structures
//         let authorizationUrl, paymentReference;

//         // Method 1: Standard Paystack response (most common)
//         if (paystackResponse.data && paystackResponse.data.status === true) {
//           authorizationUrl = paystackResponse.data.data.authorization_url;
//           paymentReference = paystackResponse.data.data.reference;
//           console.log('✅ URL extracted via standard response structure');
//         }
//         // Method 2: Direct data structure
//         else if (paystackResponse.data && paystackResponse.data.authorization_url) {
//           authorizationUrl = paystackResponse.data.authorization_url;
//           paymentReference = paystackResponse.data.reference;
//           console.log('✅ URL extracted via direct data structure');
//         }
//         // Method 3: Nested data structure
//         else if (paystackResponse.data && paystackResponse.data.data && paystackResponse.data.data.authorization_url) {
//           authorizationUrl = paystackResponse.data.data.authorization_url;
//           paymentReference = paystackResponse.data.data.reference;
//           console.log('✅ URL extracted via nested data structure');
//         }
//         // Method 4: Root level (unlikely but possible)
//         else if (paystackResponse.authorization_url) {
//           authorizationUrl = paystackResponse.authorization_url;
//           paymentReference = paystackResponse.reference;
//           console.log('✅ URL extracted via root level');
//         }

//         console.log('🔍 Extracted values:', { 
//           authorizationUrl: authorizationUrl ? 'PRESENT' : 'MISSING', 
//           paymentReference 
//         });

//         // VALIDATION: Ensure we have the required values
//         if (!authorizationUrl) {
//           console.error('❌ FAILED TO EXTRACT AUTHORIZATION URL');
//           console.error('Full Paystack response:', JSON.stringify(paystackResponse, null, 2));
//           throw new Error('Paystack did not return a payment URL. Please try again.');
//         }

//         if (!authorizationUrl.includes('checkout.paystack.com')) {
//           console.error('❌ INVALID PAYSTACK URL:', authorizationUrl);
//           throw new Error('Invalid payment URL received from Paystack');
//         }

//         if (!paymentReference) {
//           console.error('❌ MISSING PAYMENT REFERENCE');
//           // Generate a fallback reference
//           paymentReference = `HH_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
//           console.log('🔄 Using fallback reference:', paymentReference);
//         }

//         console.log('✅ Valid Paystack URL received:', authorizationUrl);

//         paymentResult = {
//           success: true,
//           processor: 'paystack',
//           paymentIntentId: paymentReference,
//           authorizationUrl: authorizationUrl,
//           amount: paymentAmount,
//           currency: 'NGN',
//           status: 'requires_payment_method'
//         };

//       } catch (paystackError) {
//         console.error('❌ Paystack payment creation failed:', {
//           error: paystackError.message,
//           stack: paystackError.stack,
//           response: paystackError.response?.data
//         });
//         return res.status(502).json({
//           success: false,
//           message: 'Paystack payment service unavailable',
//           error: process.env.NODE_ENV === 'development' ? paystackError.message : undefined,
//           code: 'PAYSTACK_SERVICE_ERROR'
//         });
//       }
//     } else {
//       // STRIPE PAYMENT (International) - your existing Stripe code
//       console.log('🌍 Using Stripe for international customer');
//       // ... keep your existing Stripe code
//     }

//     // Update booking with payment info
//     console.log('💾 Updating booking with payment information...');
    
//     booking.payment = {
//       processor: isNigeria ? 'paystack' : 'stripe',
//       paymentIntentId: paymentResult.paymentIntentId,
//       amount: paymentResult.amount,
//       currency: paymentResult.currency,
//       status: paymentResult.status,
//       initiatedAt: new Date(),
//       autoRefundAt: new Date(Date.now() + 4 * 60 * 60 * 1000),
//       authorizationUrl: paymentResult.authorizationUrl
//     };

//     // Add payment history
//     booking.paymentHistory = booking.paymentHistory || [];
//     booking.paymentHistory.push({
//       action: 'payment_initiated',
//       processor: booking.payment.processor,
//       paymentIntentId: paymentResult.paymentIntentId,
//       amount: paymentResult.amount,
//       currency: paymentResult.currency,
//       status: paymentResult.status,
//       timestamp: new Date()
//     });

//     await booking.save();

//     console.log('✅ Booking updated successfully with payment info:', {
//       bookingId: booking._id,
//       paymentIntentId: paymentResult.paymentIntentId,
//       processor: booking.payment.processor
//     });

//     res.json({
//       success: true,
//       message: 'Payment intent created successfully',
//       data: paymentResult
//     });

//   } catch (error) {
//     console.error('❌ Create payment error details:', {
//       error: error.message,
//       stack: error.stack,
//       bookingId: req.params.bookingId,
//       user: req.user.id,
//       timestamp: new Date().toISOString()
//     });
    
//     res.status(500).json({
//       success: false,
//       message: 'Failed to create payment intent',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined,
//       code: 'PAYMENT_CREATION_FAILED'
//     });
//   }
// });

app.post('/api/bookings/:bookingId/create-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { amount, customerCountry = 'NIGERIA' } = req.body;

    console.log('💰 Payment creation request:', {
      bookingId,
      amount,
      customerCountry,
      environment: process.env.NODE_ENV,
      paystackAvailable: !!paymentProcessors?.paystack
    });

    // Input validation
    if (!bookingId || !mongoose.Types.ObjectId.isValid(bookingId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid booking ID is required',
        code: 'INVALID_BOOKING_ID'
      });
    }

    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid payment amount is required',
        code: 'INVALID_AMOUNT'
      });
    }

    // Find booking
    const booking = await Booking.findById(bookingId).populate('customerId', 'email');
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found',
        code: 'BOOKING_NOT_FOUND'
      });
    }

    // Check authorization
    if (booking.customerId._id.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to pay for this booking',
        code: 'UNAUTHORIZED_PAYMENT'
      });
    }

    const paymentAmount = parseFloat(amount);
    
    // Country detection
    const isNigeria = () => {
      const country = customerCountry?.toLowerCase()?.trim();
      return country === 'ng' || 
             country === 'nigeria' || 
             country === 'ngn' ||
             country === 'naija' ||
             country.includes('nigeria');
    };

    console.log('🌍 Country detection:', {
      received: customerCountry,
      isNigeria: isNigeria()
    });

    let paymentResult;

    if (isNigeria()) {
      // PAYSTACK PAYMENT (Nigeria)
      console.log('🌍 Using Paystack for Nigerian customer');
      
      if (!paymentProcessors?.paystack) {
        console.log('❌ Paystack processor not available');
        return res.status(503).json({
          success: false,
          message: 'Paystack payment processor is not available',
          code: 'PAYMENT_PROCESSOR_UNAVAILABLE'
        });
      }

      try {
        const paystackPayload = {
          amount: Math.round(paymentAmount * 100), // Convert to kobo
          email: req.user.email || booking.customerId.email,
          currency: 'NGN',
          metadata: {
            bookingId: bookingId,
            customerId: req.user.id,
            paymentType: 'escrow'
          },
          callback_url: `${process.env.FRONTEND_URL}/customer/payment-status?bookingId=${bookingId}&processor=paystack`
        };

        console.log('📤 Paystack request payload:', {
          ...paystackPayload,
          amount: paystackPayload.amount,
          email: paystackPayload.email
        });

        // Make the Paystack API call
        const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

        console.log('📥 Paystack response:', {
          status: paystackResponse.status,
          dataStatus: paystackResponse.data?.status,
          reference: paystackResponse.data?.data?.reference
        });

        // Handle Paystack response
        if (!paystackResponse.data || paystackResponse.data.status !== true) {
          throw new Error(paystackResponse.data?.message || 'Paystack initialization failed');
        }

        const paymentData = paystackResponse.data.data;
        const authorizationUrl = paymentData.authorization_url;
        const paymentReference = paymentData.reference;

        if (!authorizationUrl) {
          throw new Error('No authorization URL received from Paystack');
        }

        paymentResult = {
          success: true,
          processor: 'paystack',
          paymentIntentId: paymentReference,
          authorizationUrl: authorizationUrl,
          amount: paymentAmount,
          currency: 'NGN',
          status: 'requires_payment_method'
        };

        console.log('✅ Paystack payment initialized successfully');

      } catch (paystackError) {
        console.error('❌ Paystack payment creation failed:', {
          error: paystackError.message,
          response: paystackError.response?.data
        });
        
        return res.status(502).json({
          success: false,
          message: 'Paystack payment service unavailable',
          error: process.env.NODE_ENV === 'development' ? paystackError.message : undefined,
          code: 'PAYSTACK_SERVICE_ERROR'
        });
      }
    } else {
      // STRIPE PAYMENT (International) - your existing Stripe code
      console.log('🌍 Using Stripe for international customer');
      
      if (!paymentProcessors?.stripe) {
        return res.status(503).json({
          success: false,
          message: 'Stripe payment processor is not configured',
          code: 'PAYMENT_PROCESSOR_UNAVAILABLE'
        });
      }

      try {
        const isUK = customerCountry === 'GB' || customerCountry === 'UK';
        const currency = isUK ? 'gbp' : 'usd';
        
        const stripePayload = {
          amount: Math.round(paymentAmount * 100),
          currency: currency,
          capture_method: 'manual',
          metadata: {
            bookingId: bookingId,
            customerId: req.user.id,
            paymentType: 'escrow'
          },
          automatic_payment_methods: {
            enabled: true,
          }
        };

        const paymentIntent = await paymentProcessors.stripe.paymentIntents.create(stripePayload);

        paymentResult = {
          success: true,
          processor: 'stripe',
          paymentIntentId: paymentIntent.id,
          clientSecret: paymentIntent.client_secret,
          amount: paymentAmount,
          currency: currency.toUpperCase(),
          status: paymentIntent.status
        };

      } catch (stripeError) {
        console.error('❌ Stripe payment creation failed:', stripeError);
        return res.status(502).json({
          success: false,
          message: 'Stripe payment service unavailable',
          code: 'STRIPE_SERVICE_ERROR'
        });
      }
    }

    // Update booking with payment info
    booking.payment = {
      processor: isNigeria() ? 'paystack' : 'stripe',
      paymentIntentId: paymentResult.paymentIntentId,
      amount: paymentResult.amount,
      currency: paymentResult.currency,
      status: paymentResult.status,
      initiatedAt: new Date(),
      autoRefundAt: new Date(Date.now() + 4 * 60 * 60 * 1000),
      authorizationUrl: paymentResult.authorizationUrl,
      clientSecret: paymentResult.clientSecret
    };

    // Add payment history
    booking.paymentHistory = booking.paymentHistory || [];
    booking.paymentHistory.push({
      action: 'payment_initiated',
      processor: booking.payment.processor,
      paymentIntentId: paymentResult.paymentIntentId,
      amount: paymentResult.amount,
      currency: paymentResult.currency,
      status: paymentResult.status,
      timestamp: new Date()
    });

    await booking.save();

    console.log('✅ Booking updated successfully with payment info');

    res.json({
      success: true,
      message: 'Payment intent created successfully',
      data: paymentResult
    });

  } catch (error) {
    console.error('❌ Create payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment intent',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined,
      code: 'PAYMENT_CREATION_FAILED'
    });
  }
});

app.get('/api/debug/test-paystack', async (req, res) => {
  try {
    if (!paymentProcessors?.paystack) {
      return res.json({
        success: false,
        message: 'Paystack not initialized'
      });
    }

    console.log('🧪 Testing Paystack directly...');
    
    // Test with a small amount
    const testPayload = {
      amount: 10000, // 100 NGN
      email: 'test@example.com',
      currency: 'NGN',
      callback_url: `${process.env.FRONTEND_URL}/payment-test`
    };

    const response = await paymentProcessors.paystack.transaction.initialize(testPayload);
    
    console.log('📥 Paystack test response:', {
      status: response.status,
      dataStatus: response.data?.status,
      reference: response.data?.data?.reference,
      authorizationUrl: response.data?.data?.authorization_url
    });

    res.json({
      success: true,
      data: {
        response: response.data,
        authorizationUrl: response.data?.data?.authorization_url,
        reference: response.data?.data?.reference
      }
    });

  } catch (error) {
    console.error('❌ Paystack test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});


app.post('/api/jobs/create', authenticateToken, async (req, res) => {
  try {
    const {
      serviceType,
      description,
      location,
      urgency = 'normal',
      timeframe = 'ASAP',
      budget,
      category,
      skillsRequired = [],
      estimatedDuration,
      preferredSchedule
    } = req.body;

    console.log('📝 Creating new job posting:', {
      serviceType,
      customerId: req.user.id,
      location,
      budget
    });

    // Validate required fields
    if (!serviceType || !description || !location) {
      return res.status(400).json({
        success: false,
        message: 'Service type, description, and location are required'
      });
    }

    // Extract budget amount for payment processing
    let budgetAmount = 0;
    if (budget) {
      const numericMatch = budget.match(/(\d+)/);
      if (numericMatch) {
        budgetAmount = parseInt(numericMatch[1]);
      }
    }

    // Create service request
    const serviceRequest = new ServiceRequest({
      serviceType,
      description,
      location,
      urgency,
      timeframe,
      budget,
      budgetAmount,
      category: category || 'general',
      customerId: req.user.id,
      skillsRequired: Array.isArray(skillsRequired) ? skillsRequired : [skillsRequired],
      estimatedDuration,
      preferredSchedule,
      status: 'pending',
      canRefund: true
    });

    await serviceRequest.save();
    await serviceRequest.populate('customerId', 'name email phoneNumber');

    console.log('✅ Job posting created:', serviceRequest._id);

    res.status(201).json({
      success: true,
      message: 'Job posted successfully',
      data: {
        job: serviceRequest,
        requiresPayment: budgetAmount > 0,
        nextStep: budgetAmount > 0 ? 'Make payment to secure your job posting' : 'Job is now live'
      }
    });

  } catch (error) {
    console.error('❌ Create job posting error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create job posting',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/jobs/:jobId/create-payment', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { amount, customerCountry = 'NIGERIA' } = req.body;

    console.log('💰 Job payment creation:', {
      jobId,
      amount,
      customerCountry,
      user: req.user.id
    });

    // Validate job exists and user owns it
    const job = await ServiceRequest.findById(jobId);
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }

    if (job.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to pay for this job'
      });
    }

    // Check if job already has payment
    if (job.payment && job.payment.status === 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment already made for this job'
      });
    }

    const paymentAmount = parseFloat(amount);
    
    // Determine payment processor based on country
    const isNigeria = () => {
      const country = customerCountry?.toLowerCase()?.trim();
      return country === 'ng' || country === 'nigeria' || country === 'ngn';
    };

    const isUK = customerCountry === 'GB' || customerCountry === 'UK';

    console.log('🌍 Payment processor selection:', {
      country: customerCountry,
      isNigeria: isNigeria(),
      isUK: isUK
    });

    let paymentResult;

    if (isNigeria()) {
      // PAYSTACK PAYMENT (Nigeria)
      console.log('🇳🇬 Using Paystack for Nigerian customer');

      if (!paymentProcessors?.paystack) {
        return res.status(503).json({
          success: false,
          message: 'Paystack payment processor not available'
        });
      }

      try {
        const paystackPayload = {
          amount: Math.round(paymentAmount * 100), // Convert to kobo
          email: req.user.email,
          currency: 'NGN',
          metadata: {
            jobId: jobId,
            customerId: req.user.id,
            type: 'job_posting'
          },
          callback_url: `${process.env.FRONTEND_URL}/job-payment-status?jobId=${jobId}&processor=paystack`
        };

        console.log('📤 Paystack job payment payload:', paystackPayload);

        const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

        if (!paystackResponse.data || paystackResponse.data.status !== true) {
          throw new Error(paystackResponse.data?.message || 'Paystack initialization failed');
        }

        const paymentData = paystackResponse.data.data;
        
        paymentResult = {
          success: true,
          processor: 'paystack',
          paymentIntentId: paymentData.reference,
          authorizationUrl: paymentData.authorization_url,
          amount: paymentAmount,
          currency: 'NGN',
          status: 'requires_payment_method'
        };

        console.log('✅ Paystack job payment initialized');

      } catch (paystackError) {
        console.error('❌ Paystack job payment failed:', paystackError);
        throw new Error(`Paystack payment failed: ${paystackError.message}`);
      }
    } else if (isUK) {
      // STRIPE PAYMENT (UK)
      console.log('🇬🇧 Using Stripe for UK customer');

      if (!paymentProcessors?.stripe) {
        return res.status(503).json({
          success: false,
          message: 'Stripe payment processor not available'
        });
      }

      try {
        const stripePayload = {
          amount: Math.round(paymentAmount * 100), // Convert to pence
          currency: 'gbp',
          metadata: {
            jobId: jobId,
            customerId: req.user.id,
            type: 'job_posting'
          },
          automatic_payment_methods: {
            enabled: true,
          }
        };

        const paymentIntent = await paymentProcessors.stripe.paymentIntents.create(stripePayload);

        paymentResult = {
          success: true,
          processor: 'stripe',
          paymentIntentId: paymentIntent.id,
          clientSecret: paymentIntent.client_secret,
          amount: paymentAmount,
          currency: 'GBP',
          status: paymentIntent.status
        };

        console.log('✅ Stripe job payment initialized');

      } catch (stripeError) {
        console.error('❌ Stripe job payment failed:', stripeError);
        throw new Error(`Stripe payment failed: ${stripeError.message}`);
      }
    } else {
      return res.status(400).json({
        success: false,
        message: 'Payment not supported for your country'
      });
    }

    // Update job with payment info
    job.payment = {
      processor: isNigeria() ? 'paystack' : 'stripe',
      paymentIntentId: paymentResult.paymentIntentId,
      amount: paymentResult.amount,
      currency: paymentResult.currency,
      status: 'pending',
      authorizationUrl: paymentResult.authorizationUrl,
      clientSecret: paymentResult.clientSecret
    };

    job.autoRefundAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days for refund
    await job.save();

    console.log('✅ Job payment info updated');

    res.json({
      success: true,
      message: 'Payment initialized successfully',
      data: paymentResult
    });

  } catch (error) {
    console.error('❌ Job payment creation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/jobs/:jobId/proposals', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const {
      proposalText,
      proposedAmount,
      estimatedDuration,
      proposedSchedule
    } = req.body;

    console.log('📨 New proposal submission:', {
      jobId,
      providerId: req.user.id,
      proposedAmount
    });

    // Validate user is a provider
    const user = await User.findById(req.user.id);
    if (!user.userType.includes('provider') && user.userType !== 'both') {
      return res.status(403).json({
        success: false,
        message: 'Only providers can submit proposals'
      });
    }

    // Find job
    const job = await ServiceRequest.findById(jobId);
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }

    // Check if job is still open
    if (job.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'This job is no longer accepting proposals'
      });
    }

    // Check if provider already submitted a proposal
    const existingProposal = job.proposals.find(
      proposal => proposal.providerId.toString() === req.user.id
    );

    if (existingProposal) {
      return res.status(400).json({
        success: false,
        message: 'You have already submitted a proposal for this job'
      });
    }

    // Add new proposal
    job.proposals.push({
      providerId: req.user.id,
      proposalText,
      proposedAmount,
      estimatedDuration,
      proposedSchedule,
      status: 'pending',
      submittedAt: new Date()
    });

    await job.save();
    await job.populate('proposals.providerId', 'name profileImage rating reviewCount');

    console.log('✅ Proposal submitted successfully');

    // Notify customer about new proposal
    await Notification.createNotification({
      userId: job.customerId,
      type: 'new_proposal',
      title: 'New Proposal Received',
      message: `${user.name} has submitted a proposal for your ${job.serviceType} job`,
      relatedId: job._id,
      relatedType: 'job',
      priority: 'medium'
    });

    res.json({
      success: true,
      message: 'Proposal submitted successfully',
      data: {
        proposal: job.proposals[job.proposals.length - 1]
      }
    });

  } catch (error) {
    console.error('❌ Proposal submission error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit proposal'
    });
  }
});


app.post('/api/jobs/:jobId/proposals/:proposalId/accept', authenticateToken, async (req, res) => {
  try {
    const { jobId, proposalId } = req.params;
    const userId = req.user.id;

    console.log('🔄 Unified proposal acceptance:', { jobId, proposalId, userId });

    // First try ServiceRequest
    let serviceRequest = await ServiceRequest.findById(jobId);
    if (serviceRequest) {
      console.log('✅ Found in ServiceRequest, calling ServiceRequest endpoint logic...');
      
      // Instead of redirecting with require(), duplicate the logic here
      // Check if user owns the service request
      if (serviceRequest.customerId.toString() !== userId) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to accept proposals for this job'
        });
      }

      // Find the proposal
      let proposal = null;
      for (const p of serviceRequest.proposals) {
        if (p._id.toString() === proposalId) {
          proposal = p;
          break;
        }
      }

      if (!proposal) {
        return res.status(404).json({
          success: false,
          message: 'Proposal not found'
        });
      }

      // Check if already accepted
      if (proposal.status === 'accepted') {
        return res.json({
          success: true,
          message: 'Proposal was already accepted',
          data: {
            serviceRequestId: serviceRequest._id,
            proposalId: proposal._id,
            providerId: proposal.providerId,
            alreadyAccepted: true
          }
        });
      }

      // Accept the proposal
      proposal.status = 'accepted';
      proposal.acceptedAt = new Date();
      serviceRequest.status = 'awaiting_hero';
      serviceRequest.providerId = proposal.providerId;
      serviceRequest.acceptedAt = new Date();
      serviceRequest.acceptedProposalId = proposal._id;

      // Reject other proposals
      serviceRequest.proposals.forEach(p => {
        if (p._id.toString() !== proposalId && p.status === 'pending') {
          p.status = 'rejected';
        }
      });

      await serviceRequest.save();

      // Send notification
      try {
        await Notification.createNotification({
          userId: proposal.providerId,
          type: 'proposal_accepted',
          title: 'Proposal Accepted!',
          message: `Your proposal for "${serviceRequest.serviceType}" has been accepted by the customer`,
          relatedId: serviceRequest._id,
          relatedType: 'job'
        });
      } catch (notifError) {
        console.error('❌ Notification error:', notifError);
      }

      return res.json({
        success: true,
        message: 'Proposal accepted successfully',
        data: {
          serviceRequestId: serviceRequest._id,
          proposalId: proposal._id,
          providerId: proposal.providerId
        }
      });
    }

    // If not found in ServiceRequest, try Job collection
    console.log('🔄 ServiceRequest not found, trying Job collection...');
    const job = await Job.findById(jobId);
    if (!job) {
      console.log('❌ Job not found in any collection:', jobId);
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }

    console.log('✅ Found in Job collection:', {
      id: job._id,
      customerId: job.customerId,
      applicationsCount: job.applications?.length
    });

    // Check if user owns the job
    if (job.customerId.toString() !== userId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to accept proposals for this job'
      });
    }

    // Check if applications exist
    if (!job.applications || job.applications.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'No applications found for this job'
      });
    }

    // Find the application
    let application = null;
    for (const app of job.applications) {
      if (app._id.toString() === proposalId) {
        application = app;
        break;
      }
    }

    if (!application) {
      console.log('❌ Application not found:', proposalId);
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    // Check if application is already accepted
    if (application.status === 'accepted') {
      return res.json({
        success: true,
        message: 'Application already accepted',
        data: {
          jobId: job._id,
          applicationId: application._id,
          providerId: application.providerId,
          alreadyAccepted: true
        }
      });
    }

    // Update application status to accepted
    application.status = 'accepted';

    // Update job status and assign provider
    job.status = 'accepted';
    job.providerId = application.providerId;

    // Reject all other pending applications
    if (job.applications && job.applications.length > 0) {
      job.applications.forEach(app => {
        if (app._id.toString() !== proposalId && app.status === 'pending') {
          app.status = 'rejected';
        }
      });
    }

    await job.save();

    // Send notification to provider
    try {
      await Notification.createNotification({
        userId: application.providerId,
        type: 'proposal_accepted',
        title: 'Proposal Accepted!',
        message: `Your proposal for "${job.title}" has been accepted by the customer`,
        relatedId: job._id,
        relatedType: 'job'
      });
    } catch (notifError) {
      console.error('❌ Notification error:', notifError);
    }

    console.log('✅ Job application accepted successfully');

    res.json({
      success: true,
      message: 'Proposal accepted successfully',
      data: {
        jobId: job._id,
        applicationId: application._id,
        providerId: application.providerId
      }
    });

  } catch (error) {
    console.error('❌ Unified accept proposal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to accept proposal',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/service-requests/:jobId/hero-here', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const userId = req.user.id;

    console.log('🎯 Customer confirming provider arrival:', { jobId, userId });

    const serviceRequest = await ServiceRequest.findById(jobId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check if user owns the service request
    if (serviceRequest.customerId.toString() !== userId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this service request'
      });
    }

    // Check if job is in correct status
    if (serviceRequest.status !== 'awaiting_hero') {
      return res.status(400).json({
        success: false,
        message: 'Service request is not in awaiting hero status'
      });
    }

    // Update status to in_progress
    serviceRequest.status = 'in_progress';
    serviceRequest.startedAt = new Date();

    await serviceRequest.save();

    // Send notification to provider
    await Notification.createNotification({
      userId: serviceRequest.providerId,
      type: 'job_started',
      title: 'Job Started!',
      message: `The customer has confirmed your arrival and the job has started`,
      relatedId: serviceRequest._id,
      relatedType: 'job'
    });

    console.log('✅ Hero Here confirmed, job status updated to in_progress');

    res.json({
      success: true,
      message: 'Provider arrival confirmed, job started!',
      data: {
        serviceRequestId: serviceRequest._id,
        status: serviceRequest.status,
        startedAt: serviceRequest.startedAt
      }
    });

  } catch (error) {
    console.error('❌ Hero Here confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm provider arrival',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});
app.post('/api/jobs/:jobId/request-refund', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { reason } = req.body;

    console.log('🔄 Refund request:', { jobId, reason });

    // Find job
    const job = await ServiceRequest.findById(jobId).populate('customerId', 'name email');
    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }

    // Check if user owns the job
    if (job.customerId._id.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to request refund for this job'
      });
    }

    // Check if refund is allowed
    if (!job.canRefund) {
      return res.status(400).json({
        success: false,
        message: 'Refund is not available for this job. A proposal has already been accepted.'
      });
    }

    // Check if payment exists and is held
    if (!job.payment || job.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'No payment found or payment is not in held status'
      });
    }

    // Process refund based on payment processor
    let refundResult;

    if (job.payment.processor === 'paystack') {
      // Paystack refund
      try {
        const refundResponse = await paymentProcessors.paystack.refund.create({
          transaction: job.payment.paymentIntentId,
          amount: Math.round(job.payment.amount * 100)
        });

        if (refundResponse.data.status === 'processed') {
          refundResult = {
            success: true,
            processor: 'paystack',
            refundId: refundResponse.data.data.id
          };
        } else {
          throw new Error(refundResponse.data.message);
        }
      } catch (paystackError) {
        console.error('❌ Paystack refund failed:', paystackError);
        throw new Error(`Paystack refund failed: ${paystackError.message}`);
      }
    } else if (job.payment.processor === 'stripe') {
      // Stripe refund
      try {
        const refund = await paymentProcessors.stripe.refunds.create({
          payment_intent: job.payment.paymentIntentId
        });

        refundResult = {
          success: true,
          processor: 'stripe',
          refundId: refund.id
        };
      } catch (stripeError) {
        console.error('❌ Stripe refund failed:', stripeError);
        throw new Error(`Stripe refund failed: ${stripeError.message}`);
      }
    }

    // Update job status
    job.status = 'cancelled';
    job.payment.status = 'refunded';
    job.payment.refundedAt = new Date();
    job.refundRequested = true;
    job.refundReason = reason;

    await job.save();

    console.log('✅ Refund processed successfully');

    res.json({
      success: true,
      message: 'Refund processed successfully',
      data: {
        refund: refundResult,
        job: {
          id: job._id,
          status: job.status,
          payment: job.payment
        }
      }
    });

  } catch (error) {
    console.error('❌ Refund request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process refund',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/jobs/payment-verify', async (req, res) => {
  try {
    const { reference, jobId, processor } = req.query;

    console.log('🔍 Verifying job payment:', { reference, jobId, processor });

    let paymentVerified = false;
    let job;

    if (processor === 'paystack') {
      // Verify Paystack payment
      const verification = await paymentProcessors.paystack.transaction.verify(reference);
      
      if (verification.data.status === 'success') {
        paymentVerified = true;
        job = await ServiceRequest.findById(jobId);
        
        if (job) {
          job.payment.status = 'held';
          job.payment.heldAt = new Date();
          job.status = 'pending'; // Job is now live with payment held
          await job.save();
        }
      }
    } else if (processor === 'stripe') {
      // For Stripe, we typically use webhooks, but this is a simple verification
      job = await ServiceRequest.findById(jobId);
      if (job && job.payment) {
        job.payment.status = 'held';
        job.payment.heldAt = new Date();
        job.status = 'pending';
        await job.save();
        paymentVerified = true;
      }
    }

    if (paymentVerified && job) {
      console.log('✅ Job payment verified, job is now live');
      
      // Redirect to job page
      res.redirect(`${process.env.FRONTEND_URL}/jobs/${jobId}?payment=success`);
    } else {
      res.redirect(`${process.env.FRONTEND_URL}/jobs/${jobId}?payment=failed`);
    }

  } catch (error) {
    console.error('❌ Job payment verification error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/jobs?payment=error`);
  }
});

app.get('/api/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;

    const job = await ServiceRequest.findById(jobId)
      .populate('customerId', 'name email profileImage')
      .populate('providerId', 'name email profileImage rating reviewCount')
      .populate('proposals.providerId', 'name profileImage rating reviewCount completedJobs');

    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found'
      });
    }

    // Check if user can view this job
    const canView = job.customerId._id.toString() === req.user.id || 
                   (job.providerId && job.providerId._id.toString() === req.user.id) ||
                   req.user.userType.includes('provider');

    if (!canView) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this job'
      });
    }

    res.json({
      success: true,
      data: {
        job,
        canSubmitProposal: req.user.userType.includes('provider') && 
                          job.status === 'pending' &&
                          job.customerId._id.toString() !== req.user.id,
        canRequestRefund: job.customerId._id.toString() === req.user.id && 
                         job.canRefund && 
                         job.payment?.status === 'held'
      }
    });

  } catch (error) {
    console.error('❌ Get job error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch job details'
    });
  }
});



// Production fallback handler
async function handleProductionFallbackPayment(bookingId, amount, userId, res) {
  try {
    const paymentReference = `HH_PROD_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
    
    const paymentResult = {
      success: true,
      processor: 'manual_bank_transfer',
      paymentIntentId: paymentReference,
      authorizationUrl: `${process.env.FRONTEND_URL}/manual-payment?reference=${paymentReference}`,
      amount: parseFloat(amount),
      currency: 'NGN',
      status: 'requires_payment_method',
      instructions: 'Please make payment via bank transfer to our company account',
      bankDetails: {
        bankName: 'Kuda Bank',
        accountNumber: '2045836972',
        accountName: 'Peter Adeol Okusanya'
      },
      note: 'Upload proof of payment after transfer'
    };

    // Update booking
    const booking = await Booking.findById(bookingId);
    booking.payment = {
      processor: 'manual_bank_transfer',
      paymentIntentId: paymentReference,
      amount: paymentResult.amount,
      currency: paymentResult.currency,
      status: paymentResult.status,
      initiatedAt: new Date(),
      fallbackUsed: true
    };
    await booking.save();

    console.log('✅ Production fallback payment created:', paymentReference);

    return res.json({
      success: true,
      message: 'Manual payment instructions generated',
      data: paymentResult,
      fallback: true
    });

  } catch (error) {
    console.error('❌ Production fallback payment error:', error);
    throw error;
  }
}


app.get('/api/payments/health', async (req, res) => {
  try {
    const health = {
      paystack: {
        configured: !!process.env.PAYSTACK_SECRET_KEY,
        initialized: !!paymentProcessors?.paystack,
        test: null
      },
      stripe: {
        configured: !!process.env.STRIPE_SECRET_KEY,
        initialized: !!paymentProcessors?.stripe
      },
      timestamp: new Date().toISOString()
    };

    // Test Paystack if configured
    if (paymentProcessors?.paystack) {
      try {
        const test = await paymentProcessors.paystack.transaction.list({ perPage: 1 });
        health.paystack.test = test.data?.status === true ? 'healthy' : 'unhealthy';
      } catch (error) {
        health.paystack.test = 'error: ' + error.message;
      }
    }

    res.json({
      success: true,
      data: health
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/debug/paystack-init', async (req, res) => {
  try {
    console.log('🔍 Debugging Paystack initialization...');
    
    const debugInfo = {
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        PAYSTACK_SECRET_KEY: process.env.PAYSTACK_SECRET_KEY ? '***' + process.env.PAYSTACK_SECRET_KEY.slice(-4) : 'NOT SET',
        PAYSTACK_SECRET_KEY_LENGTH: process.env.PAYSTACK_SECRET_KEY ? process.env.PAYSTACK_SECRET_KEY.length : 0
      },
      currentState: {
        paymentProcessorsExists: !!paymentProcessors,
        paystackInitialized: !!paymentProcessors?.paystack,
        paystackType: paymentProcessors?.paystack ? typeof paymentProcessors.paystack : 'undefined'
      }
    };

    // Test Paystack initialization directly
    if (process.env.PAYSTACK_SECRET_KEY) {
      try {
        console.log('🧪 Testing direct Paystack initialization...');
        const testClient = await createPaystackClient();
        
        debugInfo.directTest = {
          success: true,
          clientCreated: !!testClient,
          methods: testClient ? Object.keys(testClient) : []
        };

        // Test API call
        const testResponse = await testClient.transaction.list({ perPage: 1 });
        debugInfo.apiTest = {
          success: true,
          status: testResponse.data?.status,
          message: testResponse.data?.message
        };

      } catch (testError) {
        debugInfo.directTest = {
          success: false,
          error: testError.message,
          stack: testError.stack
        };
      }
    }

    console.log('📊 Paystack Debug Info:', debugInfo);
    
    res.json({
      success: true,
      data: debugInfo
    });

  } catch (error) {
    console.error('Paystack debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});



app.post('/api/debug/check-payment-response', authenticateToken, async (req, res) => {
  try {
    const { bookingId, amount } = req.body;
    
    // Simulate exactly what your payment endpoint does
    const paystackPayload = {
      amount: Math.round(amount * 100),
      email: req.user.email,
      currency: 'NGN',
      callback_url: `${process.env.FRONTEND_URL}/customer/payment-status?bookingId=${bookingId}&processor=paystack`
    };

    console.log('🧪 Testing Paystack with payload:', paystackPayload);

    const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

    console.log('🔍 Paystack raw response:', JSON.stringify(paystackResponse.data, null, 2));

    // Extract authorization URL
    let authorizationUrl = null;
    if (paystackResponse.data && paystackResponse.data.data && paystackResponse.data.data.authorization_url) {
      authorizationUrl = paystackResponse.data.data.authorization_url;
    }

    // Return what the frontend should receive
    const responseToFrontend = {
      success: true,
      message: 'Payment intent created successfully',
      data: {
        success: true,
        processor: 'paystack',
        paymentIntentId: paystackResponse.data.data.reference,
        authorizationUrl: authorizationUrl, // This is what's missing!
        amount: amount,
        currency: 'NGN',
        status: 'requires_payment_method'
      }
    };

    console.log('📤 What frontend will receive:', JSON.stringify(responseToFrontend, null, 2));

    res.json(responseToFrontend);

  } catch (error) {
    console.error('Debug payment error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/debug/test-paystack-response', authenticateToken, async (req, res) => {
  try {
    const { amount, email, bookingId } = req.body;
    
    console.log('🧪 Testing Paystack response structure...');
    
    const paystackPayload = {
      amount: Math.round(amount || 10000),
      email: email || 'test@example.com',
      currency: 'NGN',
      metadata: {
        bookingId: bookingId || 'test-booking',
        customerId: req.user.id,
        paymentType: 'escrow'
      },
      callback_url: `${process.env.FRONTEND_URL}/customer/payment-status?bookingId=${bookingId}&processor=paystack`
    };

    console.log('📤 Paystack request:', paystackPayload);

    const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

    console.log('🔍 FULL PAYSTACK RAW RESPONSE:');
    console.log('Response status:', paystackResponse.status);
    console.log('Response data:', paystackResponse.data);
    console.log('Response data.data:', paystackResponse.data?.data);
    console.log('Response keys:', Object.keys(paystackResponse));
    
    // Try to extract authorization URL
    let authorizationUrl = null;
    
    // Method 1: Standard structure
    if (paystackResponse.data?.data?.authorization_url) {
      authorizationUrl = paystackResponse.data.data.authorization_url;
      console.log('✅ Found URL via data.data.authorization_url');
    }
    // Method 2: Alternative structure
    else if (paystackResponse.data?.authorization_url) {
      authorizationUrl = paystackResponse.data.authorization_url;
      console.log('✅ Found URL via data.authorization_url');
    }
    // Method 3: Direct structure
    else if (paystackResponse.authorization_url) {
      authorizationUrl = paystackResponse.authorization_url;
      console.log('✅ Found URL via direct authorization_url');
    }
    // Method 4: Check for access_code
    else if (paystackResponse.data?.data?.access_code) {
      authorizationUrl = `https://checkout.paystack.com/${paystackResponse.data.data.access_code}`;
      console.log('✅ Constructed URL from access_code');
    }

    console.log('🔗 Final authorizationUrl:', authorizationUrl);

    res.json({
      success: true,
      data: {
        fullResponse: paystackResponse,
        authorizationUrl: authorizationUrl,
        extractedSuccessfully: !!authorizationUrl
      }
    });

  } catch (error) {
    console.error('❌ Paystack test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});



app.post('/api/bookings/:id/provider-confirm', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm this booking'
      });
    }

    // Check if payment is held
    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Update booking status to confirmed by provider
    booking.status = 'confirmed';
    booking.providerConfirmed = true;
    booking.providerConfirmedAt = new Date();
    
    // Cancel the auto-refund timer since provider confirmed
    booking.autoRefundAt = undefined;
    
    await booking.save();

    // Notify customer that provider accepted
    await Notification.createNotification({
      userId: booking.customerId,
      type: 'provider_accepted',
      title: 'Booking Confirmed!',
      message: `${booking.providerName} has accepted your booking request`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Booking confirmed successfully. Payment will be held until service completion.',
      data: booking
    });

  } catch (error) {
    console.error('Provider confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm booking'
    });
  }
});

app.post('/api/bookings/:id/customer-confirm-service', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm service for this booking'
      });
    }

    // Check if provider has confirmed the booking first
    if (!booking.providerConfirmed) {
      return res.status(400).json({
        success: false,
        message: 'Provider has not confirmed this booking yet'
      });
    }

    // Update booking with customer confirmation
    booking.customerConfirmedService = true;
    booking.customerConfirmedAt = new Date();
    booking.status = 'service_confirmed';
    
    await booking.save();

    // Notify provider that customer confirmed service
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'customer_confirmed_service',
      title: 'Customer Confirmed Service!',
      message: 'The customer has confirmed your service. You can now mark the job as completed.',
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Service confirmation recorded successfully. Provider can now complete the job.',
      data: booking
    });

  } catch (error) {
    console.error('Customer service confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm service'
    });
  }
});
app.get('/api/debug/paystack-credentials', async (req, res) => {
  try {
    if (!paymentProcessors.paystack) {
      return res.json({
        success: false,
        message: 'Paystack not initialized'
      });
    }

    // Test with a simple transaction list to verify credentials
    const testResponse = await paymentProcessors.paystack.transaction.list({ 
      perPage: 1 
    });

    console.log('🔍 Paystack credentials test:', {
      hasSecretKey: !!process.env.PAYSTACK_SECRET_KEY,
      testResponseStatus: testResponse.status,
      testResponseData: testResponse.data
    });

    res.json({
      success: true,
      data: {
        configured: true,
        secretKeySet: !!process.env.PAYSTACK_SECRET_KEY,
        testSuccessful: testResponse.status,
        testResponse: testResponse.data
      }
    });
  } catch (error) {
    console.error('❌ Paystack credentials test failed:', error);
    res.status(500).json({
      success: false,
      message: 'Paystack test failed',
      error: error.message,
      response: error.response?.data
    });
  }
});

app.post('/api/bookings/:id/complete-job', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId).populate('providerId');
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to complete this job'
      });
    }

    // CRITICAL FIX: Check if customer has confirmed "Hero Here"
    if (!booking.heroHereConfirmed) {
      return res.status(400).json({
        success: false,
        message: 'Customer has not confirmed "Hero Here" yet. Please wait for customer confirmation.'
      });
    }

    // Check if customer has confirmed seeing provider (additional check)
    if (!booking.customerSeenProvider) {
      return res.status(400).json({
        success: false,
        message: 'Customer has not confirmed seeing you yet'
      });
    }

    // Check if payment is still held
    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Update booking status to completed by provider
    booking.status = 'provider_completed';
    booking.providerCompletedAt = new Date();
    
    await booking.save();

    // Notify customer to confirm completion
    await Notification.createNotification({
      userId: booking.customerId,
      type: 'job_completed_by_provider',
      title: 'Service Completed!',
      message: `${booking.providerName} has marked the service as completed. Please confirm the service is completed to release payment.`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Job marked as completed. Waiting for customer confirmation to release payment.',
      data: booking
    });

  } catch (error) {
    console.error('Provider job completion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete job'
    });
  }
});
app.post('/api/debug/paystack-response-test', authenticateToken, async (req, res) => {
  try {
    const { amount = 10000, email = 'test@example.com' } = req.body;
    
    if (!paymentProcessors.paystack) {
      return res.status(400).json({
        success: false,
        message: 'Paystack not initialized'
      });
    }

    const testPayload = {
      amount: Math.round(amount),
      email: email,
      currency: 'NGN',
      callback_url: `${process.env.FRONTEND_URL}/payment-verify`
    };

    console.log('🧪 Testing Paystack with payload:', testPayload);

    const response = await paymentProcessors.paystack.transaction.initialize(testPayload);

    console.log('🔍 FULL PAYSTACK RESPONSE ANALYSIS:');
    console.log('Response type:', typeof response);
    console.log('Response keys:', Object.keys(response));
    
    if (response.data) {
      console.log('Response.data keys:', Object.keys(response.data));
      console.log('Response.data.status:', response.data.status);
      console.log('Response.data.message:', response.data.message);
    }
    
    if (response.data && response.data.data) {
      console.log('Response.data.data keys:', Object.keys(response.data.data));
      console.log('Response.data.data.authorization_url:', response.data.data.authorization_url);
      console.log('Response.data.data.reference:', response.data.data.reference);
    }

    // Try multiple ways to extract the authorization URL
    let authorizationUrl = null;
    let reference = null;

    // Method 1: Direct from response.data.data
    if (response.data && response.data.data && response.data.data.authorization_url) {
      authorizationUrl = response.data.data.authorization_url;
      reference = response.data.data.reference;
      console.log('✅ Found URL via response.data.data');
    }
    // Method 2: From response.data
    else if (response.data && response.data.authorization_url) {
      authorizationUrl = response.data.authorization_url;
      reference = response.data.reference;
      console.log('✅ Found URL via response.data');
    }
    // Method 3: Direct from response
    else if (response.authorization_url) {
      authorizationUrl = response.authorization_url;
      reference = response.reference;
      console.log('✅ Found URL via direct response');
    }

    console.log('🔗 Final extracted authorizationUrl:', authorizationUrl);
    console.log('📝 Final extracted reference:', reference);

    res.json({
      success: true,
      data: {
        fullResponse: response,
        authorizationUrl,
        reference,
        extractedSuccessfully: !!authorizationUrl
      }
    });

  } catch (error) {
    console.error('❌ Paystack test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});

app.get('/api/debug/booking-payment/:bookingId', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check authorization
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this booking'
      });
    }

    const paymentInfo = {
      bookingId: booking._id,
      status: booking.status,
      payment: booking.payment,
      paymentHistory: booking.paymentHistory,
      canRetry: booking.payment && ['requires_payment_method', 'failed'].includes(booking.payment.status),
      retryCount: booking.payment?.retryCount || 0,
      initiatedAt: booking.payment?.initiatedAt,
      timeSinceInitiation: booking.payment?.initiatedAt ? 
        Date.now() - new Date(booking.payment.initiatedAt).getTime() : null
    };

    res.json({
      success: true,
      data: paymentInfo
    });

  } catch (error) {
    console.error('Debug payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment debug info'
    });
  }
});

// Add this temporary debug endpoint to reset the payment
app.post('/api/debug/reset-payment/:bookingId', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Reset payment to allow fresh retry
    booking.payment = undefined;
    await booking.save();

    console.log('✅ Payment reset for booking:', bookingId);

    res.json({
      success: true,
      message: 'Payment reset successfully. You can now retry payment with a fresh reference.'
    });

  } catch (error) {
    console.error('Reset payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset payment'
    });
  }
});
app.get('/api/bookings/:bookingId/payment-status', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    if (!booking.payment) {
      return res.status(400).json({
        success: false,
        message: 'No payment found for this booking'
      });
    }

    // If payment is in requires_payment_method status for more than 1 hour, allow retry
    const canRetry = booking.payment.status === 'requires_payment_method' && 
                    booking.payment.initiatedAt && 
                    (new Date() - new Date(booking.payment.initiatedAt)) > 3600000; // 1 hour

    res.json({
      success: true,
      data: {
        payment: booking.payment,
        canRetry: canRetry,
        retryCount: booking.payment.retryCount || 0
      }
    });

  } catch (error) {
    console.error('Get payment status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment status'
    });
  }
});

// Paystack webhook for refunds
app.post('/api/payments/paystack-webhook-refund', async (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    
    if (!signature) {
      return res.status(400).send('No signature');
    }

    // Verify webhook signature
    const crypto = require('crypto');
    const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                      .update(JSON.stringify(req.body))
                      .digest('hex');
    
    if (hash !== signature) {
      return res.status(400).send('Invalid signature');
    }

    const event = req.body;
    console.log('🔔 Paystack refund webhook received:', event.event);

    if (event.event === 'refund.processed') {
      const { reference, amount, status } = event.data;
      
      // Find booking by Paystack reference
      const booking = await Booking.findOne({
        'payment.paymentIntentId': reference
      });

      if (booking && status === 'processed') {
        // Update booking payment status to refunded
        booking.payment.status = 'refunded';
        booking.payment.refundedAt = new Date();
        booking.status = 'cancelled';
        await booking.save();

        console.log('✅ Paystack refund processed for booking:', booking._id);
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error('❌ Paystack refund webhook error:', error);
    res.status(500).send('Webhook error');
  }
});

app.post('/api/test-body-parsing', (req, res) => {
  console.log('🧪 Body Parsing Test:', {
    body: req.body,
    headers: req.headers,
    contentType: req.headers['content-type']
  });
  
  res.json({
    success: true,
    message: 'Body parsing test',
    bodyReceived: req.body,
    contentType: req.headers['content-type']
  });
});

app.post('/api/bookings/:bookingId/retry-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    console.log('🔄 Payment retry requested for booking:', bookingId);

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check authorization
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to pay for this booking'
      });
    }

    if (!booking.payment) {
      return res.status(400).json({
        success: false,
        message: 'No payment found for this booking'
      });
    }

    // Only allow retry for failed or requires_payment_method payments
    if (!['requires_payment_method', 'failed'].includes(booking.payment.status)) {
      return res.status(400).json({
        success: false,
        message: 'Payment cannot be retried in its current state'
      });
    }

    let paymentResult;

    if (booking.payment.processor === 'paystack') {
      try {
        // IMPORTANT: For Paystack retry, ALWAYS create a new reference
        const newReference = `HH_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
        
        const paystackPayload = {
          amount: Math.round(booking.payment.amount * 100),
          email: req.user.email || booking.customerEmail,
          currency: 'NGN',
          reference: newReference, // ALWAYS new reference for retry
          metadata: {
            bookingId: bookingId,
            customerId: req.user.id,
            paymentType: 'escrow',
            isRetry: true,
            originalReference: booking.payment.paymentIntentId,
            retryCount: (booking.payment.retryCount || 0) + 1
          },
          callback_url: `${process.env.FRONTEND_URL}/customer/payment-status?bookingId=${bookingId}&processor=paystack&isRetry=true`
        };

        console.log('📤 Paystack retry payload:', paystackPayload);

        const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

        // VALIDATE THE AUTHORIZATION URL
        const authorizationUrl = paystackResponse.data.authorization_url;
        console.log('🔗 Paystack retry authorization URL:', authorizationUrl);

        if (!authorizationUrl) {
          throw new Error('No authorization URL received from Paystack');
        }

        // Ensure it's a valid Paystack URL
        if (!authorizationUrl.includes('checkout.paystack.com')) {
          console.error('❌ INVALID Paystack URL received:', authorizationUrl);
          throw new Error('Invalid Paystack payment URL received');
        }

        // Update booking with new payment intent
        booking.payment.paymentIntentId = newReference;
        booking.payment.authorizationUrl = authorizationUrl;
        booking.payment.status = 'requires_payment_method';
        booking.payment.retryCount = (booking.payment.retryCount || 0) + 1;
        booking.payment.lastRetryAt = new Date();
        booking.payment.initiatedAt = new Date(); // Reset the initiation time

        // Add to payment history
        booking.paymentHistory = booking.paymentHistory || [];
        booking.paymentHistory.push({
          action: 'payment_retry',
          processor: 'paystack',
          paymentIntentId: newReference,
          amount: booking.payment.amount,
          currency: booking.payment.currency,
          status: 'requires_payment_method',
          timestamp: new Date(),
          isRetry: true,
          originalReference: booking.payment.paymentIntentId,
          retryCount: booking.payment.retryCount
        });

        await booking.save();

        paymentResult = {
          success: true,
          processor: 'paystack',
          paymentIntentId: newReference,
          authorizationUrl: authorizationUrl,
          amount: booking.payment.amount,
          currency: booking.payment.currency,
          status: 'requires_payment_method',
          isRetry: true,
          retryCount: booking.payment.retryCount
        };

        console.log('✅ Payment retry initialized successfully with new reference:', newReference);

      } catch (paystackError) {
        console.error('❌ Paystack retry failed:', paystackError);
        throw new Error(`Payment retry failed: ${paystackError.message}`);
      }
    } else {
      return res.status(400).json({
        success: false,
        message: 'Retry not implemented for this payment processor'
      });
    }

    res.json({
      success: true,
      message: 'Payment retry initialized successfully',
      data: paymentResult
    });

  } catch (error) {
    console.error('❌ Payment retry error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retry payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/bookings/:id/confirm-arrival', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm arrival for this booking'
      });
    }

    // Check if booking is in correct status
    if (booking.status !== 'confirmed' && booking.status !== 'accepted') {
      return res.status(400).json({
        success: false,
        message: 'Booking is not in confirmed status'
      });
    }

    // Check if provider already confirmed arrival
    if (booking.providerArrived) {
      return res.status(400).json({
        success: false,
        message: 'Arrival already confirmed'
      });
    }

    // Update booking with provider arrival confirmation
    booking.providerArrived = true;
    booking.providerArrivedAt = new Date();
    
    // Make "Hero Here" button visible to customer
    booking.showHeroHereButton = true;
    
    await booking.save();

    // Notify customer that provider has arrived
    // Use a valid notification type based on your schema
    try {
      await Notification.createNotification({
        userId: booking.customerId,
        type: 'booking_confirmed', // Changed to valid type
        title: 'Your Hero Has Arrived!',
        message: `${booking.providerName} has arrived at your location. Please confirm they are here to start the service.`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'high'
      });
    } catch (notificationError) {
      console.log('⚠️ Using fallback notification type:', notificationError.message);
      // Try with a different type if the first one fails
      await Notification.createNotification({
        userId: booking.customerId,
        type: 'booking_update', // Another possible valid type
        title: 'Your Hero Has Arrived!',
        message: `${booking.providerName} has arrived at your location. Please confirm they are here to start the service.`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'high'
      });
    }

    res.json({
      success: true,
      message: 'Arrival confirmed successfully. Customer can now confirm you are here.',
      data: {
        providerArrived: true,
        providerArrivedAt: booking.providerArrivedAt,
        showHeroHereButton: true
      }
    });

  } catch (error) {
    console.error('Confirm arrival error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm arrival'
    });
  }
});

app.post('/api/bookings/:id/confirm-hero-here', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm service for this booking'
      });
    }

    // Check if provider has confirmed arrival first
    if (!booking.providerArrived) {
      return res.status(400).json({
        success: false,
        message: 'Provider has not confirmed arrival yet'
      });
    }

    // Check if "Hero Here" button should be visible
    if (!booking.showHeroHereButton) {
      return res.status(400).json({
        success: false,
        message: 'Cannot confirm hero here at this time'
      });
    }

    // Update booking with customer confirmation
    booking.customerConfirmedHeroHere = true;
    booking.customerConfirmedAt = new Date();
    booking.heroHereConfirmed = true;
    
    // Set auto-refund timer (4 hours from now)
    booking.autoRefundAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
    
    await booking.save();

    // Notify provider that customer confirmed their arrival
    await Notification.createNotification({
  userId: booking.providerId,
  type: 'booking_confirmed', // Changed to valid type
  title: 'Customer Confirmed Your Arrival!',
  message: 'The customer has confirmed you are at the location. Service can begin.',
  relatedId: booking._id,
  relatedType: 'booking',
  priority: 'high'
});

    res.json({
      success: true,
      message: 'Hero here confirmed successfully. Payment will be held for 4 hours for service completion.',
      data: {
        autoRefundAt: booking.autoRefundAt,
        heroHereConfirmed: true
      }
    });

  } catch (error) {
    console.error('Confirm hero here error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm hero here'
    });
  }
});

app.post('/api/payments/release-to-provider', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.body;

    console.log('💰 Releasing payment for booking:', bookingId);

    const booking = await Booking.findById(bookingId).populate('providerId');
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify user is authorized (admin or customer)
    if (booking.customerId.toString() !== req.user.id && req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to release this payment'
      });
    }

    // Check if payment is held
    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    const provider = booking.providerId;

    // Check if provider has bank account set up
    if (!provider.paymentSettings?.paystackRecipientCode) {
      return res.status(400).json({
        success: false,
        message: 'Provider has not set up their bank account for payments. Payment will be held until provider adds account.'
      });
    }

    // Calculate amounts (15% platform fee, 85% to provider)
    const totalAmount = booking.payment.amount;
    const platformFee = totalAmount * 0.15;
    const providerAmount = totalAmount * 0.85;

    console.log('💰 Payment Split:', {
      totalAmount,
      platformFee,
      providerAmount
    });

    // Process BOTH transfers simultaneously
    let platformTransferResult, providerTransferResult;

    try {
      // Transfer 15% to platform account
      platformTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(platformFee * 100), // Convert to kobo
        recipient: COMPANY_ACCOUNT.paystackRecipientCode,
        reason: `Home Heroes Platform Fee - Booking ${bookingId}`
      });

      if (!platformTransferResult.status) {
        throw new Error(`Platform transfer failed: ${platformTransferResult.message}`);
      }

      console.log('✅ Platform fee transfer initiated:', platformTransferResult.data.transfer_code);

    } catch (platformTransferError) {
      console.error('❌ Platform transfer failed:', platformTransferError);
      return res.status(500).json({
        success: false,
        message: 'Failed to transfer platform fee: ' + platformTransferError.message,
        code: 'PLATFORM_TRANSFER_FAILED'
      });
    }

    try {
      // Transfer 85% to provider account
      providerTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(providerAmount * 100), // Convert to kobo
        recipient: provider.paymentSettings.paystackRecipientCode,
        reason: `Payment for ${booking.serviceType} service - Booking ${bookingId}`
      });

      if (!providerTransferResult.status) {
        throw new Error(`Provider transfer failed: ${providerTransferResult.message}`);
      }

      console.log('✅ Provider transfer initiated:', providerTransferResult.data.transfer_code);

    } catch (providerTransferError) {
      console.error('❌ Provider transfer failed:', providerTransferError);
      
      // If provider transfer fails, try to reverse the platform transfer
      try {
        if (platformTransferResult?.data?.transfer_code) {
          await paymentProcessors.paystack.transfer.reverse({
            transfer_code: platformTransferResult.data.transfer_code
          });
          console.log('✅ Reversed platform transfer due to provider transfer failure');
        }
      } catch (reverseError) {
        console.error('❌ Failed to reverse platform transfer:', reverseError);
      }

      return res.status(500).json({
        success: false,
        message: 'Failed to transfer payment to provider: ' + providerTransferError.message,
        code: 'PROVIDER_TRANSFER_FAILED'
      });
    }

    // Update provider earnings (only their 85% portion)
    provider.providerFinancials = provider.providerFinancials || {};
    provider.providerFinancials.totalEarnings = (provider.providerFinancials.totalEarnings || 0) + providerAmount;
    provider.providerFinancials.availableBalance = (provider.providerFinancials.availableBalance || 0) + providerAmount;
    await provider.save();

    // Update booking payment status
    booking.payment.status = 'released';
    booking.payment.releasedAt = new Date();
    booking.payment.platformFee = platformFee;
    booking.payment.providerAmount = providerAmount;
    booking.payment.platformTransferCode = platformTransferResult.data.transfer_code;
    booking.payment.providerTransferCode = providerTransferResult.data.transfer_code;
    booking.paymentReleased = true;
    booking.paymentReleasedAt = new Date();
    booking.status = 'completed';
    
    await booking.save();

    // Notify provider
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'payment_released',
      title: 'Payment Released!',
      message: `Payment of ${booking.payment.currency}${providerAmount} has been released to your bank account (85% of total). Platform fee: ${booking.payment.currency}${platformFee}`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    // Notify customer
    await Notification.createNotification({
      userId: booking.customerId,
      type: 'payment_completed',
      title: 'Payment Completed',
      message: `Payment has been released to ${provider.name} for the completed service.`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'medium'
    });

    res.json({
      success: true,
      message: 'Payment released successfully - 15% platform fee, 85% to provider',
      data: {
        totalAmount,
        platformFee,
        providerAmount,
        platformTransferCode: platformTransferResult.data.transfer_code,
        providerTransferCode: providerTransferResult.data.transfer_code
      }
    });

  } catch (error) {
    console.error('Release payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to release payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/debug/check-provider-bank-account/:providerId', authenticateToken, async (req, res) => {
  try {
    const { providerId } = req.params;
    const { bookingId } = req.query;

    console.log('🔍 Debugging provider bank account setup:', {
      providerId,
      bookingId,
      currentUser: req.user.id,
      userType: req.user.userType
    });

    // Get provider
    const provider = await User.findById(providerId).select('name email paymentSettings userType');
    
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    console.log('👤 Provider found:', {
      name: provider.name,
      email: provider.email,
      userType: provider.userType,
      paymentSettings: provider.paymentSettings
    });

    // Get booking details if provided
    let booking = null;
    if (bookingId) {
      booking = await Booking.findById(bookingId);
      console.log('📋 Booking found:', {
        bookingId: booking?._id,
        status: booking?.status,
        payment: booking?.payment
      });
    }

    // Check multiple aspects of the payment settings
    const paymentSettingsAnalysis = {
      hasPaymentSettings: !!provider.paymentSettings,
      paymentSettingsKeys: provider.paymentSettings ? Object.keys(provider.paymentSettings) : [],
      hasPaystackRecipientCode: !!provider.paymentSettings?.paystackRecipientCode,
      paystackRecipientCode: provider.paymentSettings?.paystackRecipientCode,
      hasBankAccount: !!provider.paymentSettings?.bankAccount,
      bankAccountDetails: provider.paymentSettings?.bankAccount,
      isProviderUserType: provider.userType.includes('provider') || provider.userType === 'both',
      canReceivePayments: provider.userType.includes('provider') || provider.userType === 'both'
    };

    console.log('💰 Payment Settings Analysis:', paymentSettingsAnalysis);

    // Test Paystack recipient code if it exists
    let paystackValidation = null;
    if (provider.paymentSettings?.paystackRecipientCode) {
      try {
        if (paymentProcessors?.paystack) {
          // Try to fetch recipient details from Paystack
          const recipientResponse = await paymentProcessors.paystack.recipient.list({
            perPage: 1
          });
          
          console.log('🔗 Paystack recipient check:', {
            canListRecipients: !!recipientResponse.data?.data,
            totalRecipients: recipientResponse.data?.data?.length
          });

          // Check if our recipient code exists
          const recipients = recipientResponse.data?.data || [];
          const matchingRecipient = recipients.find(r => 
            r.recipient_code === provider.paymentSettings.paystackRecipientCode
          );

          paystackValidation = {
            canConnectToPaystack: true,
            recipientCodeExists: !!matchingRecipient,
            recipientDetails: matchingRecipient,
            isValid: matchingRecipient?.active === true
          };
        } else {
          paystackValidation = {
            canConnectToPaystack: false,
            error: 'Paystack not initialized'
          };
        }
      } catch (error) {
        console.error('❌ Paystack validation error:', error);
        paystackValidation = {
          canConnectToPaystack: false,
          error: error.message
        };
      }
    }

    res.json({
      success: true,
      data: {
        provider: {
          id: provider._id,
          name: provider.name,
          email: provider.email,
          userType: provider.userType
        },
        paymentSettings: provider.paymentSettings,
        paymentSettingsAnalysis,
        paystackValidation,
        booking: booking ? {
          id: booking._id,
          status: booking.status,
          paymentStatus: booking.payment?.status,
          customerId: booking.customerId,
          providerId: booking.providerId
        } : null,
        recommendations: !provider.paymentSettings?.paystackRecipientCode ? [
          'Provider needs to add bank account via /api/providers/bank-account endpoint',
          'Make sure provider userType includes "provider" or is "both"',
          'Bank account verification might have failed'
        ] : [
          'Provider has bank account set up',
          'Check if Paystack recipient code is valid',
          'Verify that the provider userType allows receiving payments'
        ]
      }
    });

  } catch (error) {
    console.error('❌ Debug provider bank account error:', error);
    res.status(500).json({
      success: false,
      message: 'Debug failed',
      error: error.message
    });
  }
});

app.post('/api/debug/check-provider-bank-account/:providerId', authenticateToken, async (req, res) => {
  try {
    const { providerId } = req.params;
    const { bookingId } = req.query;

    console.log('🔍 Debugging provider bank account setup:', {
      providerId,
      bookingId,
      currentUser: req.user.id,
      userType: req.user.userType
    });

    // Get provider
    const provider = await User.findById(providerId).select('name email paymentSettings userType');
    
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    console.log('👤 Provider found:', {
      name: provider.name,
      email: provider.email,
      userType: provider.userType,
      paymentSettings: provider.paymentSettings
    });

    // Get booking details if provided
    let booking = null;
    if (bookingId) {
      booking = await Booking.findById(bookingId);
      console.log('📋 Booking found:', {
        bookingId: booking?._id,
        status: booking?.status,
        payment: booking?.payment
      });
    }

    // Check multiple aspects of the payment settings
    const paymentSettingsAnalysis = {
      hasPaymentSettings: !!provider.paymentSettings,
      paymentSettingsKeys: provider.paymentSettings ? Object.keys(provider.paymentSettings) : [],
      hasPaystackRecipientCode: !!provider.paymentSettings?.paystackRecipientCode,
      paystackRecipientCode: provider.paymentSettings?.paystackRecipientCode,
      hasBankAccount: !!provider.paymentSettings?.bankAccount,
      bankAccountDetails: provider.paymentSettings?.bankAccount,
      isProviderUserType: provider.userType.includes('provider') || provider.userType === 'both',
      canReceivePayments: provider.userType.includes('provider') || provider.userType === 'both'
    };

    console.log('💰 Payment Settings Analysis:', paymentSettingsAnalysis);

    // Test Paystack recipient code if it exists
    let paystackValidation = null;
    if (provider.paymentSettings?.paystackRecipientCode) {
      try {
        if (paymentProcessors?.paystack) {
          // Try to fetch recipient details from Paystack
          const recipientResponse = await paymentProcessors.paystack.recipient.list({
            perPage: 1
          });
          
          console.log('🔗 Paystack recipient check:', {
            canListRecipients: !!recipientResponse.data?.data,
            totalRecipients: recipientResponse.data?.data?.length
          });

          // Check if our recipient code exists
          const recipients = recipientResponse.data?.data || [];
          const matchingRecipient = recipients.find(r => 
            r.recipient_code === provider.paymentSettings.paystackRecipientCode
          );

          paystackValidation = {
            canConnectToPaystack: true,
            recipientCodeExists: !!matchingRecipient,
            recipientDetails: matchingRecipient,
            isValid: matchingRecipient?.active === true
          };
        } else {
          paystackValidation = {
            canConnectToPaystack: false,
            error: 'Paystack not initialized'
          };
        }
      } catch (error) {
        console.error('❌ Paystack validation error:', error);
        paystackValidation = {
          canConnectToPaystack: false,
          error: error.message
        };
      }
    }

    res.json({
      success: true,
      data: {
        provider: {
          id: provider._id,
          name: provider.name,
          email: provider.email,
          userType: provider.userType
        },
        paymentSettings: provider.paymentSettings,
        paymentSettingsAnalysis,
        paystackValidation,
        booking: booking ? {
          id: booking._id,
          status: booking.status,
          paymentStatus: booking.payment?.status,
          customerId: booking.customerId,
          providerId: booking.providerId
        } : null,
        recommendations: !provider.paymentSettings?.paystackRecipientCode ? [
          'Provider needs to add bank account via /api/providers/bank-account endpoint',
          'Make sure provider userType includes "provider" or is "both"',
          'Bank account verification might have failed'
        ] : [
          'Provider has bank account set up',
          'Check if Paystack recipient code is valid',
          'Verify that the provider userType allows receiving payments'
        ]
      }
    });

  } catch (error) {
    console.error('❌ Debug provider bank account error:', error);
    res.status(500).json({
      success: false,
      message: 'Debug failed',
      error: error.message
    });
  }
});

app.post('/api/providers/force-reverify-bank-account', authenticateToken, async (req, res) => {
  try {
    const { providerId } = req.body;
    
    console.log('🔄 Force re-verifying provider bank account:', providerId);

    // Check if current user is admin or the provider themselves
    const currentUser = await User.findById(req.user.id);
    if (currentUser.userType !== 'admin' && req.user.id !== providerId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to force re-verification'
      });
    }

    const provider = await User.findById(providerId);
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    if (!provider.paymentSettings?.bankAccount) {
      return res.status(400).json({
        success: false,
        message: 'Provider has no bank account to re-verify'
      });
    }

    // Extract bank account details
    const bankAccount = provider.paymentSettings.bankAccount;
    
    // Re-create Paystack recipient
    let paystackRecipientCode;
    try {
      const recipientResponse = await paymentProcessors.paystack.recipient.create({
        type: 'nuban',
        name: bankAccount.accountName,
        account_number: bankAccount.fullAccountNumber || bankAccount.accountNumber,
        bank_code: bankAccount.bankCode,
        currency: 'NGN'
      });

      if (recipientResponse.data.status) {
        paystackRecipientCode = recipientResponse.data.data.recipient_code;
      } else {
        throw new Error(recipientResponse.data.message || 'Failed to create Paystack recipient');
      }
    } catch (paystackError) {
      console.error('❌ Paystack recipient recreation failed:', paystackError);
      return res.status(400).json({
        success: false,
        message: 'Failed to re-verify bank account with Paystack',
        error: paystackError.response?.data?.message || paystackError.message
      });
    }

    // Update provider with new recipient code
    provider.paymentSettings.paystackRecipientCode = paystackRecipientCode;
    provider.paymentSettings.verifiedAt = new Date();
    
    await provider.save();

    console.log('✅ Provider bank account re-verified successfully:', {
      providerId: provider._id,
      newRecipientCode: paystackRecipientCode
    });

    res.json({
      success: true,
      message: 'Bank account re-verified successfully',
      data: {
        providerId: provider._id,
        bankAccount: provider.paymentSettings.bankAccount,
        paystackRecipientCode,
        isVerified: true
      }
    });

  } catch (error) {
    console.error('❌ Force re-verify bank account error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to re-verify bank account',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/payments/auto-release-pending', authenticateToken, async (req, res) => {
  try {
    const provider = await User.findById(req.user.id);
    
    if (!provider.paymentSettings?.paystackRecipientCode) {
      return res.json({
        success: false,
        message: 'No bank account added yet'
      });
    }

    // Find all completed bookings with held payments for this provider
    const pendingPayments = await Booking.find({
      providerId: req.user.id,
      'payment.status': 'held',
      status: 'completed'
    }).populate('customerId', 'name email');

    console.log(`Found ${pendingPayments.length} pending payments to release`);

    const releasedPayments = [];
    const failedPayments = [];

    for (const booking of pendingPayments) {
      try {
        const totalAmount = booking.payment.amount;
        const platformFee = totalAmount * 0.15;
        const providerAmount = totalAmount * 0.85;

        // Transfer 15% to platform
        const platformTransfer = await paymentProcessors.paystack.transfer.create({
          source: 'balance',
          amount: Math.round(platformFee * 100),
          recipient: COMPANY_ACCOUNT.paystackRecipientCode,
          reason: `Home Heroes Platform Fee - Booking ${booking._id}`
        });

        // Transfer 85% to provider
        const providerTransfer = await paymentProcessors.paystack.transfer.create({
          source: 'balance',
          amount: Math.round(providerAmount * 100),
          recipient: provider.paymentSettings.paystackRecipientCode,
          reason: `Payment for ${booking.serviceType} service - Booking ${booking._id}`
        });

        // Update provider earnings
        provider.providerFinancials = provider.providerFinancials || {};
        provider.providerFinancials.totalEarnings = (provider.providerFinancials.totalEarnings || 0) + providerAmount;
        provider.providerFinancials.availableBalance = (provider.providerFinancials.availableBalance || 0) + providerAmount;

        // Update booking
        booking.payment.status = 'released';
        booking.payment.releasedAt = new Date();
        booking.payment.platformFee = platformFee;
        booking.payment.providerAmount = providerAmount;
        booking.payment.platformTransferCode = platformTransfer.data.transfer_code;
        booking.payment.providerTransferCode = providerTransfer.data.transfer_code;
        booking.paymentReleased = true;
        booking.paymentReleasedAt = new Date();

        await booking.save();

        releasedPayments.push({
          bookingId: booking._id,
          amount: providerAmount,
          transferCode: providerTransfer.data.transfer_code
        });

        // Send notification
        await Notification.createNotification({
          userId: provider._id,
          type: 'payment_released',
          title: 'Payment Released!',
          message: `Payment of ${booking.payment.currency}${providerAmount} has been automatically released to your bank account.`,
          relatedId: booking._id,
          relatedType: 'booking',
          priority: 'high'
        });

      } catch (error) {
        console.error(`Failed to release payment for booking ${booking._id}:`, error);
        failedPayments.push({
          bookingId: booking._id,
          error: error.message
        });
      }
    }

    await provider.save();

    res.json({
      success: true,
      message: `Auto-released ${releasedPayments.length} payments. ${failedPayments.length} failed.`,
      data: {
        released: releasedPayments,
        failed: failedPayments
      }
    });

  } catch (error) {
    console.error('Auto-release error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to auto-release payments'
    });
  }
});


app.post('/api/service-requests/:jobId/request-refund', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { reason } = req.body;

    console.log('🔄 Service request refund request:', { jobId, reason });

    const serviceRequest = await ServiceRequest.findById(jobId).populate('customerId', 'name email');
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check if user owns the service request
    if (serviceRequest.customerId._id.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to request refund for this service request'
      });
    }

    // Check if proposal has been accepted
    if (serviceRequest.status === 'accepted' || serviceRequest.acceptedProposalId) {
      return res.status(400).json({
        success: false,
        message: 'Cannot refund after proposal has been accepted'
      });
    }

    // Check if payment exists and is held
    if (!serviceRequest.payment || serviceRequest.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'No payment found or payment is not in held status'
      });
    }

    // Process refund based on payment processor
    let refundResult;

    if (serviceRequest.payment.processor === 'paystack') {
      try {
        const refundResponse = await paymentProcessors.paystack.refund.create({
          transaction: serviceRequest.payment.paymentIntentId,
          amount: Math.round(serviceRequest.payment.amount * 100)
        });

        if (refundResponse.data.status) {
          refundResult = {
            success: true,
            processor: 'paystack',
            refundId: refundResponse.data.data.id
          };
        } else {
          throw new Error(refundResponse.data.message);
        }
      } catch (paystackError) {
        console.error('❌ Paystack refund failed:', paystackError);
        throw new Error(`Paystack refund failed: ${paystackError.message}`);
      }
    } else if (serviceRequest.payment.processor === 'stripe') {
      try {
        const refund = await paymentProcessors.stripe.refunds.create({
          payment_intent: serviceRequest.payment.paymentIntentId
        });

        refundResult = {
          success: true,
          processor: 'stripe',
          refundId: refund.id
        };
      } catch (stripeError) {
        console.error('❌ Stripe refund failed:', stripeError);
        throw new Error(`Stripe refund failed: ${stripeError.message}`);
      }
    }

    // Update service request status
    serviceRequest.status = 'cancelled';
    serviceRequest.payment.status = 'refunded';
    serviceRequest.payment.refundedAt = new Date();
    serviceRequest.refundRequested = true;
    serviceRequest.refundReason = reason;
    serviceRequest.cancelledAt = new Date();

    await serviceRequest.save();

    console.log('✅ Service request refund processed successfully');

    // Notify customer
    await Notification.createNotification({
      userId: serviceRequest.customerId._id,
      type: 'payment_refunded',
      title: 'Payment Refunded',
      message: `Your payment of ${serviceRequest.payment.currency}${serviceRequest.payment.amount} has been refunded.`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'medium'
    });

    res.json({
      success: true,
      message: 'Refund processed successfully',
      data: {
        refund: refundResult,
        serviceRequest: {
          id: serviceRequest._id,
          status: serviceRequest.status,
          payment: serviceRequest.payment
        }
      }
    });

  } catch (error) {
    console.error('❌ Service request refund error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process refund',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/payments/webhooks/paystack', async (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    
    // Get the raw body properly - always ensure it's a string
    let body;
    if (req.rawBody) {
      body = req.rawBody.toString();
    } else if (typeof req.body === 'string') {
      body = req.body;
    } else if (req.body) {
      body = JSON.stringify(req.body);
    } else {
      body = '';
    }
    
    console.log('🔔 Paystack Webhook Received:', {
      signature: signature ? 'Present' : 'Missing',
      body: body.substring(0, Math.min(body.length, 200)) + (body.length > 200 ? '...' : '')
    });

    // Verify signature (recommended for production)
    if (process.env.NODE_ENV === 'production' && signature) {
      // Use Node.js crypto module directly
      const crypto = await import('crypto');
      const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                        .update(body)
                        .digest('hex');
      
      if (hash !== signature) {
        console.error('❌ Invalid webhook signature');
        return res.status(400).json({ success: false, message: 'Invalid signature' });
      }
    }

    // Parse the event data
    const event = typeof body === 'string' ? JSON.parse(body) : body;
    console.log('📨 Webhook Event:', event.event);

    // Handle different webhook events
    if (event.event === 'charge.success') {
      const { reference, amount, customer, metadata } = event.data;
      
      console.log('✅ Payment Successful:', {
        reference,
        amount: amount / 100,
        customerEmail: customer.email,
        metadata: metadata || 'No metadata'
      });

      // Find booking by Paystack reference
      const booking = await Booking.findOne({
        'payment.paymentIntentId': reference
      });

      if (booking) {
        console.log('🔍 Found booking:', {
          bookingId: booking._id,
          currentStatus: booking.status,
          currentPaymentStatus: booking.payment?.status
        });

        // Check if booking is already confirmed to avoid duplicate processing
        if (booking.payment?.status === 'held' || booking.status === 'confirmed') {
          console.log('ℹ️ Booking already processed, skipping update');
          return res.json({ success: true, message: 'Already processed' });
        }

        // Update booking payment status to HELD
        booking.payment.status = 'held';
        booking.payment.heldAt = new Date();
        booking.payment.verifiedAt = new Date();
        booking.status = 'confirmed'; // Change from pending to confirmed
        
        // Set auto-refund timer (4 hours from now)
        booking.autoRefundAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
        
        await booking.save();

        console.log('✅ Booking updated:', {
          bookingId: booking._id,
          newStatus: booking.status,
          newPaymentStatus: booking.payment.status,
          autoRefundAt: booking.autoRefundAt
        });

        // Send notification to provider
        try {
          await Notification.createNotification({
            userId: booking.providerId,
            type: 'payment_received',
            title: 'Payment Received!',
            message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your ${booking.serviceType} service. Please confirm the booking.`,
            relatedId: booking._id,
            relatedType: 'booking',
            priority: 'high'
          });
        } catch (notifError) {
          console.error('❌ Failed to send provider notification:', notifError);
        }

        // Send notification to customer
        try {
          await Notification.createNotification({
            userId: booking.customerId,
            type: 'payment_confirmed',
            title: 'Payment Confirmed!',
            message: `Your payment of ${booking.payment.currency}${booking.payment.amount} has been confirmed and is now held in escrow.`,
            relatedId: booking._id,
            relatedType: 'booking',
            priority: 'high'
          });
        } catch (notifError) {
          console.error('❌ Failed to send customer notification:', notifError);
        }

        console.log('✅ Notifications sent');
      } else {
        console.error('❌ Booking not found for reference:', reference);
        
        // Optional: Try alternative search methods
        if (metadata && metadata.bookingId) {
          console.log('🔍 Trying to find booking by metadata.bookingId:', metadata.bookingId);
          const bookingById = await Booking.findById(metadata.bookingId);
          if (bookingById) {
            console.log('✅ Found booking by ID, updating payment reference...');
            bookingById.payment.paymentIntentId = reference;
            await bookingById.save();
          }
        }
      }
    } else if (event.event === 'transfer.success') {
      console.log('✅ Transfer successful:', {
        reference: event.data.reference,
        amount: event.data.amount / 100,
        recipient: event.data.recipient.name || event.data.recipient.email
      });
      
      // Handle successful transfer to provider/company
      
    } else if (event.event === 'refund.processed') {
      console.log('✅ Refund processed:', {
        reference: event.data.reference,
        amount: event.data.amount / 100,
        status: event.data.status
      });
      
      // Handle refunds - find and update booking
      const { reference } = event.data;
      const booking = await Booking.findOne({
        'payment.paymentIntentId': reference
      });
      
      if (booking) {
        booking.payment.status = 'refunded';
        booking.status = 'cancelled';
        await booking.save();
        console.log('✅ Booking refund status updated:', booking._id);
      }
      
    } else {
      console.log('ℹ️ Unhandled webhook event:', event.event);
    }

    res.json({ success: true, message: 'Webhook processed' });
  } catch (error) {
    console.error('❌ Webhook processing error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message
    });
  }
});

app.get('/api/debug/booking/:bookingId', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId)
      .populate('customerId', 'name email')
      .populate('providerId', 'name email paymentSettings');

    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check Paystack verification
    let paystackStatus = null;
    if (booking.payment?.processor === 'paystack' && booking.payment?.paymentIntentId) {
      try {
        const verification = await paymentProcessors.paystack.transaction.verify(
          booking.payment.paymentIntentId
        );
        paystackStatus = verification.data;
      } catch (error) {
        console.error('Paystack verification error:', error);
      }
    }

    res.json({
      success: true,
      data: {
        booking: {
          id: booking._id,
          status: booking.status,
          payment: booking.payment,
          providerArrived: booking.providerArrived,
          showHeroHereButton: booking.showHeroHereButton,
          heroHereConfirmed: booking.heroHereConfirmed,
          autoRefundAt: booking.autoRefundAt,
          timeRemaining: booking.autoRefundAt 
            ? Math.max(0, new Date(booking.autoRefundAt).getTime() - Date.now()) 
            : null
        },
        paystackStatus: paystackStatus,
        escrow: {
          amount: booking.payment?.amount,
          status: booking.payment?.status,
          shouldBeHeld: booking.payment?.status === 'held',
          split: booking.payment?.amount ? {
            platformFee: booking.payment.amount * 0.15,
            providerAmount: booking.payment.amount * 0.85
          } : null
        }
      }
    });

  } catch (error) {
    console.error('Debug booking error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


app.get('/api/payments/held-payments', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // For providers: get their held payments
    if (user.userType.includes('provider') || user.userType === 'both') {
      const heldBookings = await Booking.find({
        providerId: req.user.id,
        'payment.status': 'held',
        status: 'completed'
      }).select('_id serviceType payment.amount payment.currency createdAt');

      const heldServiceRequests = await ServiceRequest.find({
        providerId: req.user.id,
        'payment.status': 'held',
        status: 'completed'
      }).select('_id serviceType payment.amount payment.currency createdAt');

      res.json({
        success: true,
        data: {
          hasBankAccount: !!user.paymentSettings?.paystackRecipientCode,
          heldBookings,
          heldServiceRequests,
          totalHeldAmount: [
            ...heldBookings.map(b => b.payment.amount),
            ...heldServiceRequests.map(s => s.payment.amount)
          ].reduce((sum, amount) => sum + amount, 0)
        }
      });
    } else {
      res.status(403).json({
        success: false,
        message: 'Only providers can access held payments'
      });
    }
  } catch (error) {
    console.error('Get held payments error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch held payments'
    });
  }
});

app.post('/api/service-requests/payment-verify', async (req, res) => {
  try {
    const { reference, jobId, processor } = req.query;

    console.log('🔍 Verifying service request payment:', { reference, jobId, processor });

    if (!reference || !jobId || !processor) {
      return res.redirect(`${process.env.FRONTEND_URL}/service-requests/${jobId}?payment=error&message=missing_parameters`);
    }

    let paymentVerified = false;
    let serviceRequest;

    if (processor === 'paystack') {
      // Verify Paystack payment
      const verification = await paymentProcessors.paystack.transaction.verify(reference);
      
      console.log('📊 Paystack verification response:', {
        status: verification.data.status,
        message: verification.data.message,
        data: verification.data.data
      });

      if (verification.data.status === 'success') {
        paymentVerified = true;
        serviceRequest = await ServiceRequest.findById(jobId)
          .populate('customerId', 'name email')
          .populate('providerId', 'name email paymentSettings');
        
        if (serviceRequest) {
          // Update payment status to HELD in escrow
          serviceRequest.payment.status = 'held';
          serviceRequest.payment.heldAt = new Date();
          serviceRequest.payment.verificationReference = reference;
          serviceRequest.payment.verifiedAt = new Date();
          serviceRequest.status = 'pending'; // Service request is now live with payment held
          
          // Set auto-refund time (customer can request refund before accepting proposal)
          serviceRequest.autoRefundAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
          serviceRequest.canRefund = true; // Allow refunds before proposal acceptance
          
          await serviceRequest.save();

          console.log('✅ Service request payment verified and held in escrow:', {
            serviceRequestId: serviceRequest._id,
            amount: serviceRequest.payment.amount,
            status: serviceRequest.payment.status
          });

          // If provider is already assigned (accepted proposal), check if payment can be released
          if (serviceRequest.providerId && serviceRequest.status === 'accepted') {
            await checkAndReleaseServiceRequestPayment(serviceRequest._id);
          }
        }
      }
    } else if (processor === 'stripe') {
      // For Stripe, verify payment intent
      if (!paymentProcessors.stripe) {
        console.log('❌ Stripe processor not available');
        return res.redirect(`${process.env.FRONTEND_URL}/service-requests/${jobId}?payment=error&message=stripe_not_configured`);
      }

      try {
        const paymentIntent = await paymentProcessors.stripe.paymentIntents.retrieve(reference);
        
        if (paymentIntent.status === 'succeeded') {
          paymentVerified = true;
          serviceRequest = await ServiceRequest.findById(jobId)
            .populate('customerId', 'name email')
            .populate('providerId', 'name email paymentSettings');
          
          if (serviceRequest) {
            serviceRequest.payment.status = 'held';
            serviceRequest.payment.heldAt = new Date();
            serviceRequest.payment.verificationReference = reference;
            serviceRequest.payment.verifiedAt = new Date();
            serviceRequest.status = 'pending';
            serviceRequest.autoRefundAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
            serviceRequest.canRefund = true;
            
            await serviceRequest.save();

            console.log('✅ Stripe payment verified and held for service request');

            if (serviceRequest.providerId && serviceRequest.status === 'accepted') {
              await checkAndReleaseServiceRequestPayment(serviceRequest._id);
            }
          }
        }
      } catch (stripeError) {
        console.error('❌ Stripe verification error:', stripeError);
        return res.redirect(`${process.env.FRONTEND_URL}/service-requests/${jobId}?payment=error&message=stripe_verification_failed`);
      }
    }

    if (paymentVerified && serviceRequest) {
      console.log('✅ Service request payment verified, job is now live with payment held');
      
      // Send notification to customer
      await Notification.createNotification({
        userId: serviceRequest.customerId._id,
        type: 'payment_held',
        title: 'Payment Secured!',
        message: `Your payment of ${serviceRequest.payment.currency}${serviceRequest.payment.amount} has been secured in escrow. Your job is now live for providers to apply.`,
        relatedId: serviceRequest._id,
        relatedType: 'service_request',
        priority: 'high'
      });

      // Redirect to service request page
      return res.redirect(`${process.env.FRONTEND_URL}/service-requests/${jobId}?payment=success&status=held`);
    } else {
      console.log('❌ Service request payment verification failed');
      return res.redirect(`${process.env.FRONTEND_URL}/service-requests/${jobId}?payment=failed&status=verification_failed`);
    }

  } catch (error) {
    console.error('❌ Service request payment verification error:', error);
    return res.redirect(`${process.env.FRONTEND_URL}/service-requests?payment=error&message=verification_error`);
  }
});

// Function to check and release service request payment (15%/85% split)
async function checkAndReleaseServiceRequestPayment(serviceRequestId) {
  try {
    const serviceRequest = await ServiceRequest.findById(serviceRequestId)
      .populate('providerId')
      .populate('customerId');
    
    if (!serviceRequest || !serviceRequest.payment || serviceRequest.payment.status !== 'held') {
      console.log(`⚠️ Service request ${serviceRequestId} not found or payment not held`);
      return;
    }

    // Check if service is completed
    if (serviceRequest.status !== 'completed') {
      console.log(`⚠️ Service request ${serviceRequestId} not completed yet`);
      return;
    }

    const provider = serviceRequest.providerId;
    
    // Check if provider has bank account set up
    if (!provider.paymentSettings?.paystackRecipientCode) {
      console.log(`⏳ Payment held for service request ${serviceRequestId} - provider needs to add bank account`);
      
      // Notify provider to add bank account
      await Notification.createNotification({
        userId: provider._id,
        type: 'bank_account_required',
        title: 'Add Bank Account to Receive Payment',
        message: 'Please add your bank account details to receive payment for completed services.',
        relatedId: serviceRequest._id,
        relatedType: 'service_request',
        priority: 'high'
      });
      
      return;
    }

    // Calculate 15% platform fee and 85% to provider
    const totalAmount = serviceRequest.payment.amount;
    const platformFee = totalAmount * 0.15;
    const providerAmount = totalAmount * 0.85;

    console.log('💰 Service Request Payment Split:', {
      serviceRequestId,
      totalAmount,
      platformFee,
      providerAmount,
      provider: provider.name
    });

    // Process transfers (15% to platform, 85% to provider)
    let platformTransferResult, providerTransferResult;

    try {
      // Transfer 15% to platform account
      platformTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(platformFee * 100), // Convert to kobo
        recipient: COMPANY_ACCOUNT.paystackRecipientCode,
        reason: `Home Heroes Platform Fee - Service Request ${serviceRequestId}`
      });

      if (!platformTransferResult.status) {
        throw new Error(`Platform transfer failed: ${platformTransferResult.message}`);
      }

      console.log('✅ Platform fee transfer initiated:', platformTransferResult.data.transfer_code);

    } catch (platformTransferError) {
      console.error('❌ Platform transfer failed:', platformTransferError);
      throw new Error(`Platform transfer failed: ${platformTransferError.message}`);
    }

    try {
      // Transfer 85% to provider account
      providerTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(providerAmount * 100), // Convert to kobo
        recipient: provider.paymentSettings.paystackRecipientCode,
        reason: `Payment for ${serviceRequest.serviceType} service - Service Request ${serviceRequestId}`
      });

      if (!providerTransferResult.status) {
        throw new Error(`Provider transfer failed: ${providerTransferResult.message}`);
      }

      console.log('✅ Provider transfer initiated:', providerTransferResult.data.transfer_code);

    } catch (providerTransferError) {
      console.error('❌ Provider transfer failed:', providerTransferError);
      
      // If provider transfer fails, try to reverse the platform transfer
      try {
        if (platformTransferResult?.data?.transfer_code) {
          await paymentProcessors.paystack.transfer.reverse({
            transfer_code: platformTransferResult.data.transfer_code
          });
          console.log('✅ Reversed platform transfer due to provider transfer failure');
        }
      } catch (reverseError) {
        console.error('❌ Failed to reverse platform transfer:', reverseError);
      }

      throw new Error(`Provider transfer failed: ${providerTransferError.message}`);
    }

    // Update provider earnings (only their 85% portion)
    provider.providerFinancials = provider.providerFinancials || {};
    provider.providerFinancials.totalEarnings = (provider.providerFinancials.totalEarnings || 0) + providerAmount;
    provider.providerFinancials.availableBalance = (provider.providerFinancials.availableBalance || 0) + providerAmount;
    await provider.save();

    // Update service request payment status
    serviceRequest.payment.status = 'released';
    serviceRequest.payment.releasedAt = new Date();
    serviceRequest.payment.platformFee = platformFee;
    serviceRequest.payment.providerAmount = providerAmount;
    serviceRequest.payment.platformTransferCode = platformTransferResult.data.transfer_code;
    serviceRequest.payment.providerTransferCode = providerTransferResult.data.transfer_code;
    serviceRequest.paymentReleased = true;
    serviceRequest.paymentReleasedAt = new Date();
    
    await serviceRequest.save();

    // Send notification to provider
    await Notification.createNotification({
      userId: provider._id,
      type: 'payment_released',
      title: 'Payment Released!',
      message: `Payment of ${serviceRequest.payment.currency}${providerAmount} has been released to your bank account (85% of total). Platform fee: ${serviceRequest.payment.currency}${platformFee}`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'high'
    });

    // Send notification to customer
    await Notification.createNotification({
      userId: serviceRequest.customerId._id,
      type: 'payment_completed',
      title: 'Payment Completed',
      message: `Payment has been released to ${provider.name} for the completed service.`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'medium'
    });

    console.log(`✅ Payment released for service request ${serviceRequestId}`);

    return {
      success: true,
      totalAmount,
      platformFee,
      providerAmount,
      platformTransferCode: platformTransferResult.data.transfer_code,
      providerTransferCode: providerTransferResult.data.transfer_code
    };

  } catch (error) {
    console.error(`❌ Failed to release payment for service request ${serviceRequestId}:`, error);
    
    // Notify admin of payment release failure
    await Notification.createNotification({
      userId: 'admin', // You'll need to implement admin user lookup
      type: 'payment_release_failed',
      title: 'Payment Release Failed',
      message: `Failed to release payment for service request ${serviceRequestId}: ${error.message}`,
      relatedId: serviceRequestId,
      relatedType: 'service_request',
      priority: 'critical'
    });
    
    throw error;
  }
}

app.post('/api/service-requests/:id/release-payment', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const serviceRequest = await ServiceRequest.findById(id)
      .populate('customerId', 'name email')
      .populate('providerId', 'name email paymentSettings');

    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Verify authorization (customer or admin)
    if (serviceRequest.customerId._id.toString() !== req.user.id && req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to release this payment'
      });
    }

    // Check if service is completed
    if (serviceRequest.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Service must be completed before releasing payment'
      });
    }

    // Check if payment is held
    if (serviceRequest.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Check if provider has bank account
    if (!serviceRequest.providerId.paymentSettings?.paystackRecipientCode) {
      return res.status(400).json({
        success: false,
        message: 'Provider has not added bank account. Payment will be held until provider adds account.'
      });
    }

    // Release payment with 15%/85% split
    const releaseResult = await checkAndReleaseServiceRequestPayment(id);

    res.json({
      success: true,
      message: 'Payment released successfully - 15% platform fee, 85% to provider',
      data: releaseResult
    });

  } catch (error) {
    console.error('❌ Manual payment release error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to release payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/service-requests/auto-release-on-account-add', authenticateToken, async (req, res) => {
  try {
    const provider = await User.findById(req.user.id);
    
    if (!provider.paymentSettings?.paystackRecipientCode) {
      return res.status(400).json({
        success: false,
        message: 'No bank account added yet'
      });
    }

    // Find all completed service requests with held payments for this provider
    const heldServiceRequests = await ServiceRequest.find({
      providerId: req.user.id,
      'payment.status': 'held',
      status: 'completed'
    });

    console.log(`Found ${heldServiceRequests.length} held service request payments to release`);

    const releasedPayments = [];
    const failedPayments = [];

    for (const serviceRequest of heldServiceRequests) {
      try {
        const releaseResult = await checkAndReleaseServiceRequestPayment(serviceRequest._id);
        releasedPayments.push({
          serviceRequestId: serviceRequest._id,
          amount: releaseResult.providerAmount,
          transferCode: releaseResult.providerTransferCode
        });
      } catch (error) {
        console.error(`Failed to release payment for service request ${serviceRequest._id}:`, error);
        failedPayments.push({
          serviceRequestId: serviceRequest._id,
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Auto-released ${releasedPayments.length} service request payments. ${failedPayments.length} failed.`,
      data: {
        released: releasedPayments,
        failed: failedPayments
      }
    });

  } catch (error) {
    console.error('❌ Auto-release on account add error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to auto-release payments'
    });
  }
});

app.post('/api/webhooks/service-request-payment', async (req, res) => {
  try {
    const event = req.body;
    console.log('🔔 Service request payment webhook received:', event.type);

    if (event.type === 'payment_intent.succeeded' || event.type === 'charge.succeeded') {
      const paymentIntentId = event.data.object.id || event.data.object.reference;
      
      // Find service request with this payment intent
      const serviceRequest = await ServiceRequest.findOne({
        'payment.paymentIntentId': paymentIntentId
      });

      if (serviceRequest) {
        // Update payment status to held
        serviceRequest.payment.status = 'held';
        serviceRequest.payment.heldAt = new Date();
        serviceRequest.payment.verificationReference = paymentIntentId;
        serviceRequest.payment.verifiedAt = new Date();
        
        await serviceRequest.save();

        console.log(`✅ Service request ${serviceRequest._id} payment verified via webhook`);

        // If service is completed, check if payment can be released
        if (serviceRequest.status === 'completed') {
          await checkAndReleaseServiceRequestPayment(serviceRequest._id);
        }
      }
    }

    res.sendStatus(200);
  } catch (error) {
    console.error('❌ Service request payment webhook error:', error);
    res.status(500).send('Webhook error');
  }
});

// Cron job to auto-release payments for providers who added bank accounts
cron.schedule('0 */6 * * *', async () => {
  try {
    console.log('🔄 Running service request payment auto-release check...');
    
    // Find all completed service requests with held payments
    const heldServiceRequests = await ServiceRequest.find({
      'payment.status': 'held',
      status: 'completed'
    }).populate('providerId', 'paymentSettings');

    for (const serviceRequest of heldServiceRequests) {
      if (serviceRequest.providerId?.paymentSettings?.paystackRecipientCode) {
        try {
          await checkAndReleaseServiceRequestPayment(serviceRequest._id);
          console.log(`✅ Auto-released payment for service request ${serviceRequest._id}`);
        } catch (error) {
          console.error(`❌ Failed to auto-release payment for service request ${serviceRequest._id}:`, error);
        }
      }
    }
  } catch (error) {
    console.error('❌ Service request payment auto-release cron error:', error);
  }
});



app.get('/api/payments/transfer-status/:transferCode', authenticateToken, async (req, res) => {
  try {
    const { transferCode } = req.params;

    const transfer = await paymentProcessors.paystack.transfer.fetch(transferCode);

    res.json({
      success: true,
      data: {
        status: transfer.data.status,
        amount: transfer.data.amount / 100, // Convert from kobo
        recipient: transfer.data.recipient,
        createdAt: transfer.data.createdAt,
        updatedAt: transfer.data.updatedAt
      }
    });
  } catch (error) {
    console.error('Check transfer status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check transfer status'
    });
  }
});

const COMPANY_ACCOUNT = {
  kudaAccountNumber: '2045836972',
  accountName: 'Peter Adeol Okusanya',
  bankName: 'Kuda',
  bankCode: '50211',
  paystackRecipientCode: null
};


async function initializeCompanyAccount() {
  try {
    console.log('🔧 Starting company account initialization...');
    
    if (!paymentProcessors?.paystack) {
      console.log('❌ Paystack not initialized');
      return;
    }

    console.log('🏢 Creating Paystack recipient for company account...');
    
    const response = await paymentProcessors.paystack.recipient.create({
      type: 'nuban',
      name: COMPANY_ACCOUNT.accountName,
      account_number: COMPANY_ACCOUNT.kudaAccountNumber,
      bank_code: COMPANY_ACCOUNT.bankCode,
      currency: 'NGN'
    });

    if (response.data.status === true) {
      COMPANY_ACCOUNT.paystackRecipientCode = response.data.data.recipient_code;
      console.log('✅ Company Paystack recipient created:', COMPANY_ACCOUNT.paystackRecipientCode);
    } else {
      console.error('❌ Failed to create company recipient:', response.data.message);
    }

  } catch (error) {
    console.error('❌ Company account initialization failed:', error.message);
    if (error.response) {
      console.error('Paystack API error response:', error.response.data);
    }
  }
}

// Call this when your server starts
initializeCompanyAccount();

app.get('/api/debug/paystack-structure', (req, res) => {
  if (!paymentProcessors?.paystack) {
    return res.json({ success: false, message: 'Paystack not initialized' });
  }

  const structure = {
    type: typeof paymentProcessors.paystack,
    isFunction: typeof paymentProcessors.paystack === 'function',
    methods: Object.keys(paymentProcessors.paystack).filter(key => typeof paymentProcessors.paystack[key] === 'function'),
    objects: Object.keys(paymentProcessors.paystack).filter(key => typeof paymentProcessors.paystack[key] === 'object'),
    fullStructure: {}
  };

  // Get detailed structure of objects
  structure.objects.forEach(objKey => {
    structure.fullStructure[objKey] = {
      methods: Object.keys(paymentProcessors.paystack[objKey]).filter(key => typeof paymentProcessors.paystack[objKey][key] === 'function'),
      properties: Object.keys(paymentProcessors.paystack[objKey]).filter(key => typeof paymentProcessors.paystack[objKey][key] !== 'function')
    };
  });

  console.log('🔍 Paystack Structure:', JSON.stringify(structure, null, 2));
  
  res.json({
    success: true,
    data: structure
  });
});

// const createPaystackClient = async () => {
//   try {
//     const axiosModule = await import('axios');
//     const axios = axiosModule.default;
    
//     const baseURL = 'https://api.paystack.co';
//     const headers = {
//       'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
//       'Content-Type': 'application/json'
//     };

//     return {
//       transaction: {
//         initialize: (data) => axios.post(`${baseURL}/transaction/initialize`, data, { headers }),
//         verify: (reference) => axios.get(`${baseURL}/transaction/verify/${reference}`, { headers }),
//         list: (params) => axios.get(`${baseURL}/transaction`, { headers, params })
//       },
//       recipient: {
//         create: (data) => axios.post(`${baseURL}/transferrecipient`, data, { headers }),
//         list: (params) => axios.get(`${baseURL}/transferrecipient`, { headers, params })
//       },
//       transfer: {
//         create: (data) => axios.post(`${baseURL}/transfer`, data, { headers }),
//         finalize: (data) => axios.post(`${baseURL}/transfer/finalize_transfer`, data, { headers }),
//         reverse: (data) => axios.post(`${baseURL}/transfer/reverse`, data, { headers })
//       },
//       // ADD THIS REFUND SUPPORT
//       refund: {
//         create: (data) => axios.post(`${baseURL}/refund`, data, { headers }),
//         list: (params) => axios.get(`${baseURL}/refund`, { headers, params })
//       }
//     };
//   } catch (error) {
//     console.error('❌ Failed to create Paystack axios client:', error.message);
//     throw error;
//   }
// };

const createPaystackClient = async () => {
  try {
    console.log('🔧 Creating Paystack client...');
    
    // Check multiple possible environment variable names
    const paystackSecretKey = 
      process.env.PAYSTACK_SECRET_KEY || 
      process.env.PAYSTACK_SECRET || 
      process.env.PAYSTACK_KEY;

    if (!paystackSecretKey) {
      console.error('❌ No Paystack secret key found in environment variables');
      console.error('🔍 Available PAYSTACK_* variables:', {
        PAYSTACK_SECRET_KEY: !!process.env.PAYSTACK_SECRET_KEY,
        PAYSTACK_SECRET: !!process.env.PAYSTACK_SECRET,
        PAYSTACK_KEY: !!process.env.PAYSTACK_KEY,
        PAYSTACK_PUBLIC_KEY: !!process.env.PAYSTACK_PUBLIC_KEY
      });
      throw new Error('Paystack secret key not found in environment variables');
    }

    // Validate the secret key format
    if (!paystackSecretKey.startsWith('sk_')) {
      console.error('❌ Invalid Paystack secret key format:', paystackSecretKey.substring(0, 10) + '...');
      throw new Error('Paystack secret key must start with "sk_"');
    }

    const axiosModule = await import('axios');
    const axios = axiosModule.default;
    
    const baseURL = 'https://api.paystack.co';
    const headers = {
      'Authorization': `Bearer ${paystackSecretKey}`,
      'Content-Type': 'application/json',
      'User-Agent': `HomeHeroes-App/${process.env.NODE_ENV || 'development'}`
    };

    console.log('✅ Paystack client configuration:', {
      baseURL,
      headers: { ...headers, Authorization: 'Bearer ***' + paystackSecretKey.slice(-4) },
      environment: process.env.NODE_ENV
    });

    // Create a simple test function to verify connectivity
    const testConnection = async () => {
      try {
        const response = await axios.get(`${baseURL}/transaction`, { 
          headers, 
          params: { perPage: 1 } 
        });
        return {
          success: true,
          status: response.status,
          data: response.data
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          status: error.response?.status,
          data: error.response?.data
        };
      }
    };

    // Test connection in production only (to avoid rate limits in development)
    if (process.env.NODE_ENV === 'production') {
      console.log('🌐 Testing Paystack API connection in production...');
      const connectionTest = await testConnection();
      console.log('🔗 Paystack connection test:', connectionTest.success ? 'SUCCESS' : 'FAILED');
      
      if (!connectionTest.success) {
        console.error('❌ Paystack API connection failed:', connectionTest);
        throw new Error(`Paystack API connection failed: ${connectionTest.error}`);
      }
    }

    // Create the client object with enhanced error handling
    const createApiCall = (method, url) => async (data = {}, config = {}) => {
      try {
        const fullUrl = `${baseURL}${url}`;
        console.log(`📤 Paystack ${method.toUpperCase()} ${url}`, { 
          data: method === 'post' ? { ...data, amount: data.amount ? '***' : undefined } : data,
          environment: process.env.NODE_ENV 
        });

        const response = await axios({
          method,
          url: fullUrl,
          data: method === 'post' ? data : undefined,
          params: method === 'get' ? data : undefined,
          headers,
          timeout: 30000, // 30 second timeout
          ...config
        });

        console.log(`📥 Paystack ${method.toUpperCase()} ${url} response:`, {
          status: response.status,
          dataStatus: response.data?.status
        });

        return response;
      } catch (error) {
        console.error(`❌ Paystack ${method.toUpperCase()} ${url} failed:`, {
          error: error.message,
          status: error.response?.status,
          data: error.response?.data,
          environment: process.env.NODE_ENV
        });
        throw error;
      }
    };

    const client = {
      transaction: {
        initialize: createApiCall('post', '/transaction/initialize'),
        verify: (reference) => createApiCall('get', `/transaction/verify/${reference}`)(),
        list: (params) => createApiCall('get', '/transaction')(params)
      },
      recipient: {
        create: createApiCall('post', '/transferrecipient'),
        list: (params) => createApiCall('get', '/transferrecipient')(params)
      },
      transfer: {
        create: createApiCall('post', '/transfer'),
        finalize: createApiCall('post', '/transfer/finalize_transfer'),
        reverse: createApiCall('post', '/transfer/reverse')
      },
      refund: {
        create: createApiCall('post', '/refund'),
        list: (params) => createApiCall('get', '/refund')(params)
      },
      bank: {
        list: (params) => createApiCall('get', '/bank')(params)
      },
      verification: {
        resolveAccount: (data) => createApiCall('get', '/bank/resolve')({
          account_number: data.account_number,
          bank_code: data.bank_code
        })
      }
    };

    console.log('✅ Paystack client created successfully for environment:', process.env.NODE_ENV);
    return client;

  } catch (error) {
    console.error('❌ Failed to create Paystack client in environment:', process.env.NODE_ENV);
    console.error('Error details:', error.message);
    
    if (error.code === 'MODULE_NOT_FOUND') {
      console.error('❌ Required module not found. Make sure axios is installed.');
    }
    
    if (error.response) {
      console.error('❌ Paystack API error:', {
        status: error.response.status,
        data: error.response.data
      });
    }
    
    throw error;
  }
};


async function processAutoRefunds() {
  try {
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
    
    const expiredBookings = await Booking.find({
      status: 'pending',
      'payment.status': 'held',
      'payment.heldAt': { $lte: fourHoursAgo },
      'payment.refundedAt': { $exists: false },
      'customerSeenProvider': { $ne: true } // Only refund if customer hasn't seen provider
    });

    for (const booking of expiredBookings) {
      try {
        console.log(`🔄 Processing auto-refund for booking ${booking._id}`);
        
        // Initiate Paystack refund
        const refundResponse = await paymentProcessors.paystack.refund.create({
          transaction: booking.payment.paymentIntentId,
          amount: Math.round(booking.payment.amount * 100) // Convert to kobo
        });

        if (refundResponse.data.status === 'processed') {
          // Update booking status
          booking.payment.status = 'refunded';
          booking.payment.refundedAt = new Date();
          booking.status = 'cancelled';
          booking.cancellationReason = 'Auto-refund: Customer did not confirm seeing provider within 4 hours';
          await booking.save();

          // Notify customer
          await Notification.createNotification({
            userId: booking.customerId,
            type: 'payment_refunded',
            title: 'Payment Refunded',
            message: `Your payment has been refunded as you didn't confirm seeing the provider within 4 hours`,
            relatedId: booking._id,
            relatedType: 'booking',
            priority: 'medium'
          });

          // Notify provider
          await Notification.createNotification({
            userId: booking.providerId,
            type: 'booking_cancelled',
            title: 'Booking Cancelled - Auto Refund',
            message: `Booking was automatically cancelled and refunded as customer didn't confirm seeing you within 4 hours`,
            relatedId: booking._id,
            relatedType: 'booking',
            priority: 'medium'
          });

          console.log(`✅ Auto-refund processed for booking ${booking._id}`);
        }
      } catch (error) {
        console.error(`❌ Failed to auto-refund booking ${booking._id}:`, error);
      }
    }
  } catch (error) {
    console.error('Auto-refund processing error:', error);
  }
}

// Schedule auto-refund check every 15 minutes
cron.schedule('*/15 * * * *', processAutoRefunds);


app.post('/api/bookings/:id/provider-confirm', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm this booking'
      });
    }

    // Check if payment is held
    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Update booking status to confirmed by provider
    booking.status = 'confirmed';
    booking.providerConfirmed = true;
    booking.providerConfirmedAt = new Date();
    
    await booking.save();

    // Notify customer that provider accepted
    await Notification.createNotification({
      userId: booking.customerId,
      type: 'provider_accepted',
      title: 'Booking Confirmed!',
      message: `${booking.providerName} has accepted your booking request. Please confirm when you've seen the provider to stop the 4-hour refund timer.`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Booking confirmed successfully. Waiting for customer to confirm they have seen you.',
      data: booking
    });

  } catch (error) {
    console.error('Provider confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm booking'
    });
  }
});

app.post('/api/bookings/:id/customer-seen-provider', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm this action'
      });
    }

    // Check if provider has confirmed the booking first
    if (!booking.providerConfirmed) {
      return res.status(400).json({
        success: false,
        message: 'Provider has not confirmed this booking yet'
      });
    }

    // Check if payment is still held
    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Update booking with customer confirmation - THIS STOPS THE 4-HOUR TIMER
    booking.customerSeenProvider = true;
    booking.customerSeenProviderAt = new Date();
    booking.status = 'in_progress';
    
    // Calculate time remaining for logging
    const timeHeld = new Date() - new Date(booking.payment.heldAt);
    const timeRemaining = (4 * 60 * 60 * 1000) - timeHeld; // 4 hours in milliseconds
    
    console.log(`⏰ Customer confirmed seeing provider. Timer stopped with ${Math.round(timeRemaining / (60 * 1000))} minutes remaining`);

    await booking.save();

    // Notify provider that customer confirmed seeing them
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'customer_seen_provider',
      title: 'Customer Confirmed Your Arrival!',
      message: 'The customer has confirmed they have seen you. The 4-hour refund timer has been stopped. You can now proceed with the service.',
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Provider arrival confirmed successfully. 4-hour refund timer has been stopped.',
      data: {
        booking,
        timeRemaining: Math.round(timeRemaining / (60 * 1000)) // minutes remaining
      }
    });

  } catch (error) {
    console.error('Customer seen provider confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm provider arrival'
    });
  }
});

app.post('/api/bookings/:id/complete-job', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    const booking = await Booking.findById(bookingId).populate('providerId');
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to complete this job'
      });
    }

    // Check if customer has confirmed seeing provider
    if (!booking.customerSeenProvider) {
      return res.status(400).json({
        success: false,
        message: 'Customer has not confirmed seeing you yet'
      });
    }

    // Update booking status to completed by provider
    booking.status = 'provider_completed';
    booking.providerCompletedAt = new Date();
    
    await booking.save();

    // Notify customer to confirm completion
    await Notification.createNotification({
      userId: booking.customerId,
      type: 'job_completed_by_provider',
      title: 'Service Completed!',
      message: `${booking.providerName} has marked the service as completed. Please confirm the service is completed to release payment.`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Job marked as completed. Waiting for customer confirmation to release payment.',
      data: booking
    });

  } catch (error) {
    console.error('Provider job completion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete job'
    });
  }
});

app.post('/api/bookings/:id/customer-confirm-completion', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;

    console.log('🔍 [DEBUG START] Customer confirm completion for booking:', bookingId);
    
    // First, get the booking without populate to get provider ID
    const booking = await Booking.findById(bookingId);
    
    if (!booking) {
      console.log('❌ Booking not found:', bookingId);
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    console.log('🔍 Booking found:', {
      bookingId: booking._id,
      status: booking.status,
      providerId: booking.providerId,
      customerId: booking.customerId
    });

    // Check if user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      console.log('❌ Authorization failed:', {
        bookingCustomer: booking.customerId.toString(),
        currentUser: req.user.id
      });
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm completion'
      });
    }

    // 🚨 FIX: Get provider data directly from database (bypass Mongoose populate issues)
    const db = mongoose.connection.db;
    const providerDoc = await db.collection('users').findOne(
      { _id: new mongoose.Types.ObjectId(booking.providerId) },
      { projection: { paymentSettings: 1, name: 1, email: 1 } }
    );

    if (!providerDoc) {
      console.log('❌ Provider not found:', booking.providerId);
      return res.status(400).json({
        success: false,
        message: 'Provider information not found'
      });
    }

    console.log('🔍 [DIRECT DB] Provider data:', {
      providerId: providerDoc._id,
      providerName: providerDoc.name,
      hasPaymentSettings: !!providerDoc.paymentSettings,
      paymentSettingsType: typeof providerDoc.paymentSettings,
      paystackRecipientCode: providerDoc.paymentSettings?.paystackRecipientCode
    });

    // Check if paymentSettings exists and has recipient code
    if (!providerDoc.paymentSettings?.paystackRecipientCode) {
      console.error('❌ Provider missing Paystack recipient code:', {
        providerId: providerDoc._id,
        paymentSettings: providerDoc.paymentSettings,
        paymentSettingsKeys: providerDoc.paymentSettings ? Object.keys(providerDoc.paymentSettings) : []
      });
      
      return res.status(400).json({
        success: false,
        message: 'Provider needs to complete bank account setup with Paystack verification',
        debug: {
          providerId: providerDoc._id,
          hasPaymentSettings: !!providerDoc.paymentSettings,
          paymentSettingsKeys: providerDoc.paymentSettings ? Object.keys(providerDoc.paymentSettings) : [],
          paystackRecipientCodeExists: !!providerDoc.paymentSettings?.paystackRecipientCode
        }
      });
    }

    console.log('✅ [SUCCESS] Provider has valid Paystack recipient code:', providerDoc.paymentSettings.paystackRecipientCode);
    
    // Check booking status
    const validStatusesForCompletion = ['provider_completed', 'completed'];
    if (!validStatusesForCompletion.includes(booking.status)) {
      console.log('❌ Invalid booking status:', booking.status);
      return res.status(400).json({
        success: false,
        message: 'Service has not been marked as completed by the provider yet'
      });
    }

    // Check if customer has already confirmed completion
    if (booking.customerConfirmedCompletion) {
      console.log('❌ Already confirmed completion');
      return res.status(400).json({
        success: false,
        message: 'You have already confirmed completion for this service'
      });
    }

    // Check if payment is still held
    if (booking.payment.status !== 'held') {
      console.log('❌ Payment not held:', booking.payment.status);
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Calculate amounts (20% company, 80% provider)
    const totalAmount = booking.payment.amount;
    const companyAmount = totalAmount * 0.20;
    const providerAmount = totalAmount * 0.80;

    console.log('💰 Payment Split:', {
      totalAmount,
      companyAmount,
      providerAmount,
      providerRecipientCode: providerDoc.paymentSettings.paystackRecipientCode
    });

    // Process transfers
    let companyTransferResult, providerTransferResult;

    try {
      // Transfer 20% to company account
      companyTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(companyAmount * 100), // Convert to kobo
        recipient: COMPANY_ACCOUNT.paystackRecipientCode,
        reason: `Home Heroes Platform Fee - Booking ${bookingId}`
      });

      if (!companyTransferResult.status) {
        throw new Error(`Company transfer failed: ${companyTransferResult.message}`);
      }

      console.log('✅ Company fee transfer initiated:', companyTransferResult.data.transfer_code);

    } catch (companyTransferError) {
      console.error('❌ Company transfer failed:', companyTransferError);
      return res.status(500).json({
        success: false,
        message: 'Failed to transfer company fee: ' + companyTransferError.message,
        code: 'COMPANY_TRANSFER_FAILED'
      });
    }

    try {
      // Transfer 80% to provider account
      providerTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(providerAmount * 100), // Convert to kobo
        recipient: providerDoc.paymentSettings.paystackRecipientCode,
        reason: `Payment for ${booking.serviceType} service - Booking ${bookingId}`
      });

      if (!providerTransferResult.status) {
        throw new Error(`Provider transfer failed: ${providerTransferResult.message}`);
      }

      console.log('✅ Provider transfer initiated:', providerTransferResult.data.transfer_code);

    } catch (providerTransferError) {
      console.error('❌ Provider transfer failed:', providerTransferError);
      
      // Try to reverse the company transfer
      try {
        if (companyTransferResult?.data?.transfer_code) {
          await paymentProcessors.paystack.transfer.reverse({
            transfer_code: companyTransferResult.data.transfer_code
          });
          console.log('✅ Reversed company transfer due to provider transfer failure');
        }
      } catch (reverseError) {
        console.error('❌ Failed to reverse company transfer:', reverseError);
      }

      return res.status(500).json({
        success: false,
        message: 'Failed to transfer payment to provider: ' + providerTransferError.message,
        code: 'PROVIDER_TRANSFER_FAILED'
      });
    }

    // Update provider earnings via direct database
    await db.collection('users').updateOne(
      { _id: new mongoose.Types.ObjectId(booking.providerId) },
      { 
        $inc: { 
          'providerFinancials.totalEarnings': providerAmount,
          'providerFinancials.availableBalance': providerAmount
        },
        $setOnInsert: {
          'providerFinancials': {
            totalEarnings: providerAmount,
            availableBalance: providerAmount,
            pendingBalance: 0,
            totalWithdrawn: 0
          }
        }
      }
    );

    // Update booking status
    booking.customerConfirmedCompletion = true;
    booking.customerConfirmedAt = new Date();
    booking.payment.status = 'released';
    booking.payment.releasedAt = new Date();
    booking.payment.companyAmount = companyAmount;
    booking.payment.providerAmount = providerAmount;
    booking.payment.companyTransferCode = companyTransferResult.data.transfer_code;
    booking.payment.providerTransferCode = providerTransferResult.data.transfer_code;
    booking.paymentReleased = true;
    booking.paymentReleasedAt = new Date();
    booking.status = 'completed';
    
    await booking.save();

    // Send notifications
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'payment_released',
      title: 'Payment Released!',
      message: `Payment of ${booking.payment.currency}${providerAmount} has been released to your bank account (80% of total). Company fee: ${booking.payment.currency}${companyAmount}`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    await Notification.createNotification({
      userId: booking.customerId,
      type: 'payment_completed',
      title: 'Payment Completed',
      message: `Payment has been released to ${providerDoc.name} for the completed service.`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'medium'
    });

    res.json({
      success: true,
      message: 'Payment released successfully - 20% company fee, 80% to provider',
      data: {
        totalAmount,
        companyAmount,
        providerAmount,
        companyTransferCode: companyTransferResult.data.transfer_code,
        providerTransferCode: providerTransferResult.data.transfer_code,
        providerRecipientCode: providerDoc.paymentSettings.paystackRecipientCode
      }
    });

  } catch (error) {
    console.error('❌ Customer completion confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm service completion',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/debug/provider-payments', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Method 1: Direct database query
    const db = mongoose.connection.db;
    const directDoc = await db.collection('users').findOne(
      { _id: new mongoose.Types.ObjectId(userId) },
      { projection: { paymentSettings: 1 } }
    );
    
    // Method 2: Mongoose find with select
    const mongooseDoc = await User.findById(userId).select('paymentSettings');
    
    // Method 3: Mongoose find without select
    const mongooseFull = await User.findById(userId);
    
    // Method 4: Check User schema
    const userSchema = User.schema;
    const paymentSettingsPath = userSchema.path('paymentSettings');
    
    res.json({
      success: true,
      data: {
        directDatabase: {
          paymentSettings: directDoc?.paymentSettings,
          hasPaystackCode: !!directDoc?.paymentSettings?.paystackRecipientCode,
          paystackCode: directDoc?.paymentSettings?.paystackRecipientCode
        },
        mongooseWithSelect: {
          paymentSettings: mongooseDoc?.paymentSettings,
          hasPaystackCode: !!mongooseDoc?.paymentSettings?.paystackRecipientCode,
          paystackCode: mongooseDoc?.paymentSettings?.paystackRecipientCode
        },
        mongooseWithoutSelect: {
          paymentSettings: mongooseFull?.paymentSettings,
          hasPaystackCode: !!mongooseFull?.paymentSettings?.paystackRecipientCode,
          paystackCode: mongooseFull?.paymentSettings?.paystackRecipientCode
        },
        schemaInfo: {
          hasPaymentSettingsPath: !!paymentSettingsPath,
          instanceType: paymentSettingsPath?.instance,
          isMixed: paymentSettingsPath?.instance === 'Mixed',
          schema: paymentSettingsPath?.schema?.tree
        }
      }
    });
  } catch (error) {
    console.error('Provider payments debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/payments/status', (req, res) => {
  res.json({
    success: true,
    data: {
      paystack: {
        configured: !!process.env.PAYSTACK_SECRET_KEY,
        initialized: !!paymentProcessors.paystack,
        companyAccount: !!COMPANY_ACCOUNT.paystackRecipientCode
      },
      stripe: {
        configured: !!process.env.STRIPE_SECRET_KEY,
        initialized: !!paymentProcessors.stripe
      }
    }
  });
});

app.get('/api/payments/transfer-status/:bookingId', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking || !booking.payment.platformTransferCode || !booking.payment.providerTransferCode) {
      return res.status(404).json({
        success: false,
        message: 'Booking or transfer codes not found'
      });
    }

    // Check both transfers
    const [platformTransfer, providerTransfer] = await Promise.all([
      paymentProcessors.paystack.transfer.fetch(booking.payment.platformTransferCode),
      paymentProcessors.paystack.transfer.fetch(booking.payment.providerTransferCode)
    ]);

    res.json({
      success: true,
      data: {
        platformTransfer: {
          status: platformTransfer.data.status,
          amount: platformTransfer.data.amount / 100,
          recipient: 'Home Heroes Platform',
          createdAt: platformTransfer.data.createdAt
        },
        providerTransfer: {
          status: providerTransfer.data.status,
          amount: providerTransfer.data.amount / 100,
          recipient: providerTransfer.data.recipient,
          createdAt: providerTransfer.data.createdAt
        }
      }
    });
  } catch (error) {
    console.error('Check transfer status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check transfer status'
    });
  }
});

app.get('/api/company/earnings', authenticateToken, async (req, res) => {
  try {
    // Only admin can access company earnings
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const timeRange = req.query.range || 'month'; // day, week, month, year

    // Calculate date range
    const now = new Date();
    let startDate;
    switch (timeRange) {
      case 'day':
        startDate = new Date(now.setDate(now.getDate() - 1));
        break;
      case 'week':
        startDate = new Date(now.setDate(now.getDate() - 7));
        break;
      case 'month':
        startDate = new Date(now.setMonth(now.getMonth() - 1));
        break;
      case 'year':
        startDate = new Date(now.setFullYear(now.getFullYear() - 1));
        break;
      default:
        startDate = new Date(now.setMonth(now.getMonth() - 1));
    }

    // Get all completed bookings with company commissions
    const completedBookings = await Booking.find({
      status: 'completed',
      paymentReleased: true,
      paymentReleasedAt: { $gte: startDate }
    });

    const totalEarnings = completedBookings.reduce((sum, booking) => {
      return sum + (booking.payment.companyAmount || 0);
    }, 0);

    const totalBookings = completedBookings.length;

    // Monthly breakdown for chart
    const monthlyBreakdown = await Booking.aggregate([
      {
        $match: {
          status: 'completed',
          paymentReleased: true,
          paymentReleasedAt: { $gte: new Date(now.getFullYear(), 0, 1) } // Current year
        }
      },
      {
        $group: {
          _id: { $month: '$paymentReleasedAt' },
          totalCommission: { $sum: '$payment.companyAmount' },
          bookingCount: { $sum: 1 }
        }
      },
      { $sort: { '_id': 1 } }
    ]);

    res.json({
      success: true,
      data: {
        totalEarnings,
        totalBookings,
        monthlyBreakdown,
        timeRange
      }
    });
  } catch (error) {
    console.error('Get company earnings error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch company earnings'
    });
  }
});

app.post('/api/providers/bank-account', authenticateToken, async (req, res) => {
  try {
    const { bankName, accountNumber, accountName, bankCode } = req.body;
    
    console.log('🔍 [BANK ACCOUNT] Starting bank account setup:', {
      bankName, 
      accountNumber, 
      accountName, 
      bankCode,
      userId: req.user.id
    });

    // Validate user is a provider
    const user = await User.findById(req.user.id);
    if (!user.userType.includes('provider') && user.userType !== 'both') {
      return res.status(403).json({
        success: false,
        message: 'Only providers can add bank accounts to receive payments'
      });
    }

    // Validate required fields
    if (!bankName || !accountNumber || !accountName || !bankCode) {
      return res.status(400).json({
        success: false,
        message: 'All bank account details are required'
      });
    }

    // Validate account number (10 digits for Nigerian banks)
    const cleanAccountNumber = accountNumber.replace(/\D/g, '');
    if (cleanAccountNumber.length !== 10) {
      return res.status(400).json({
        success: false,
        message: 'Account number must be 10 digits'
      });
    }

    // Create Paystack recipient
    console.log('📤 Creating Paystack recipient...');
    let paystackRecipientCode;
    try {
      const recipientResponse = await paymentProcessors.paystack.recipient.create({
        type: 'nuban',
        name: accountName,
        account_number: cleanAccountNumber,
        bank_code: bankCode,
        currency: 'NGN'
      });

      console.log('📥 Paystack response:', {
        status: recipientResponse.status,
        dataStatus: recipientResponse.data?.status,
        message: recipientResponse.data?.message
      });

      if (recipientResponse.data?.status === true) {
        paystackRecipientCode = recipientResponse.data.data.recipient_code;
        console.log('✅ Paystack recipient code created:', paystackRecipientCode);
      } else {
        throw new Error(recipientResponse.data?.message || 'Failed to create Paystack recipient');
      }
    } catch (paystackError) {
      console.error('❌ Paystack recipient creation failed:', {
        error: paystackError.message,
        response: paystackError.response?.data
      });
      
      return res.status(400).json({
        success: false,
        message: 'Failed to verify bank account with Paystack',
        error: paystackError.response?.data?.message || paystackError.message
      });
    }

    // 🚨 FIX: Create a proper JavaScript object (not string)
    console.log('💾 Creating payment settings object...');

    const paymentSettings = {
      paystackRecipientCode: paystackRecipientCode,
      bankAccount: {
        bankName: bankName,
        accountNumber: cleanAccountNumber.slice(-4),
        accountName: accountName,
        bankCode: bankCode,
        fullAccountNumber: cleanAccountNumber,
        bankNameFull: bankName
      },
      preferredPayoutMethod: 'paystack',
      currency: 'NGN',
      verifiedAt: new Date(),
      lastUpdated: new Date(),
      taxInformation: {
        taxFormSubmitted: false,
        taxId: null,
        taxFormUrl: null
      },
      payoutSchedule: 'weekly'
    };

    console.log('📝 Payment settings object (type):', typeof paymentSettings);
    console.log('📝 Payment settings value:', JSON.stringify(paymentSettings));

    // 🚨 FIX: Use Mongoose's findOneAndUpdate properly
    console.log('💾 Saving with Mongoose...');
    
    const updateResult = await User.findOneAndUpdate(
      { _id: req.user.id },
      { 
        $set: { 
          paymentSettings: paymentSettings // This should be an object, not string
        } 
      },
      { 
        new: true, // Return updated document
        runValidators: false // Skip validation to avoid issues
      }
    );

    console.log('✅ Update result:', {
      success: !!updateResult,
      hasPaymentSettings: !!updateResult?.paymentSettings,
      paymentSettingsType: typeof updateResult?.paymentSettings,
      paystackRecipientCode: updateResult?.paymentSettings?.paystackRecipientCode
    });

    // 🚨 FIX: If Mongoose fails, try direct update with proper object
    if (!updateResult?.paymentSettings?.paystackRecipientCode) {
      console.log('🔄 Trying direct database update with proper object...');
      
      const db = mongoose.connection.db;
      
      // Make sure we're passing an object, not a string
      const directUpdate = await db.collection('users').updateOne(
        { _id: new mongoose.Types.ObjectId(req.user.id) },
        { 
          $set: { 
            'paymentSettings': paymentSettings // Object, not JSON string
          } 
        }
      );

      console.log('🔍 Direct update result:', directUpdate);
    }

    // 🚨 FIX: Fetch and verify with proper parsing
    console.log('🔍 Final verification...');
    
    const db = mongoose.connection.db;
    const finalUser = await db.collection('users').findOne(
      { _id: new mongoose.Types.ObjectId(req.user.id) },
      { projection: { paymentSettings: 1 } }
    );

    // Check if paymentSettings is a string and parse it
    let finalPaymentSettings = finalUser?.paymentSettings;
    if (typeof finalPaymentSettings === 'string') {
      console.log('⚠️ paymentSettings is stored as string, parsing...');
      try {
        finalPaymentSettings = JSON.parse(finalPaymentSettings);
      } catch (parseError) {
        console.error('❌ Failed to parse paymentSettings:', parseError);
      }
    }

    console.log('✅ Final check:', {
      paymentSettingsType: typeof finalPaymentSettings,
      paystackRecipientCode: finalPaymentSettings?.paystackRecipientCode,
      isObject: finalPaymentSettings && typeof finalPaymentSettings === 'object'
    });

    res.json({
      success: true,
      message: 'Bank account added successfully and verified with Paystack',
      data: {
        bankAccount: finalPaymentSettings?.bankAccount || paymentSettings.bankAccount,
        isVerified: true,
        recipientCode: finalPaymentSettings?.paystackRecipientCode || paystackRecipientCode,
        currency: 'NGN',
        verifiedAt: finalPaymentSettings?.verifiedAt || paymentSettings.verifiedAt,
        storedCorrectly: finalPaymentSettings && typeof finalPaymentSettings === 'object'
      }
    });

  } catch (error) {
    console.error('❌ Add bank account error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add bank account',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/debug/db-check', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get mongoose connection
    const db = mongoose.connection.db;
    
    // Check user document directly
    const userDoc = await db.collection('users').findOne(
      { _id: new mongoose.Types.ObjectId(userId) },
      { projection: { paymentSettings: 1, userType: 1, name: 1 } }
    );
    
    // Also check via Mongoose
    const mongooseUser = await User.findById(userId).lean();
    
    res.json({
      success: true,
      data: {
        directDatabase: {
          exists: !!userDoc,
          paymentSettings: userDoc?.paymentSettings,
          paymentSettingsType: typeof userDoc?.paymentSettings
        },
        viaMongoose: {
          exists: !!mongooseUser,
          paymentSettings: mongooseUser?.paymentSettings,
          paymentSettingsType: typeof mongooseUser?.paymentSettings
        },
        comparison: {
          sameRecipientCode: userDoc?.paymentSettings?.paystackRecipientCode === mongooseUser?.paymentSettings?.paystackRecipientCode,
          sameBankAccount: JSON.stringify(userDoc?.paymentSettings?.bankAccount) === JSON.stringify(mongooseUser?.paymentSettings?.bankAccount)
        }
      }
    });
  } catch (error) {
    console.error('DB check error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/providers/force-bank-account', authenticateToken, async (req, res) => {
  try {
    const { bankName, accountNumber, accountName, bankCode } = req.body;
    
    console.log('⚡ Force setting bank account...');
    
    const cleanAccountNumber = accountNumber.replace(/\D/g, '');
    
    // 1. Create Paystack recipient
    const recipientResponse = await paymentProcessors.paystack.recipient.create({
      type: 'nuban',
      name: accountName,
      account_number: cleanAccountNumber,
      bank_code: bankCode,
      currency: 'NGN'
    });
    
    const paystackRecipientCode = recipientResponse.data.data.recipient_code;
    
    // 2. Create minimal payment settings
    const paymentSettings = {
      paystackRecipientCode: paystackRecipientCode,
      bankAccount: {
        bankName: bankName,
        accountNumber: cleanAccountNumber.slice(-4),
        accountName: accountName,
        bankCode: bankCode,
        fullAccountNumber: cleanAccountNumber
      },
      verifiedAt: new Date()
    };
    
    // 3. Use mongoose's native update (bypasses schema validation)
    const result = await mongoose.connection.db.collection('users').updateOne(
      { _id: new mongoose.Types.ObjectId(req.user.id) },
      { 
        $set: { 
          'paymentSettings': paymentSettings
        } 
      }
    );
    
    console.log('⚡ Force update result:', result);
    
    res.json({
      success: true,
      message: 'Bank account forcefully set via direct database operation',
      data: {
        recipientCode: paystackRecipientCode,
        bankAccount: paymentSettings.bankAccount,
        updateStatus: {
          matched: result.matchedCount > 0,
          modified: result.modifiedCount > 0
        }
      }
    });
    
  } catch (error) {
    console.error('Force bank account error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/debug/user-schema', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    // Check schema definition
    const schema = User.schema;
    const paymentSettingsPath = schema.path('paymentSettings');
    
    res.json({
      success: true,
      data: {
        userPaymentSettings: user.paymentSettings,
        schemaDefinition: {
          hasPaymentSettingsPath: !!paymentSettingsPath,
          paymentSettingsType: paymentSettingsPath?.instance,
          paymentSettingsSchema: paymentSettingsPath?.schema?.tree
        },
        userModel: 'User model loaded correctly'
      }
    });
  } catch (error) {
    console.error('Schema debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get all supported banks from Paystack
app.get('/api/banks', authenticateToken, async (req, res) => {
  try {
    console.log('🏦 Fetching bank list from Paystack...');
    
    if (!paymentProcessors.paystack) {
      return res.status(503).json({
        success: false,
        message: 'Paystack service not available'
      });
    }

    // Use the correct Paystack API endpoint for listing banks
    const response = await paymentProcessors.paystack.bank.list({
      country: 'nigeria',
      currency: 'NGN',
      type: 'nuban'
    });

    if (response.data.status) {
      const banks = response.data.data.map(bank => ({
        id: bank.id,
        code: bank.code,
        name: bank.name
      })).sort((a, b) => a.name.localeCompare(b.name));

      console.log(`✅ Retrieved ${banks.length} banks from Paystack`);
      
      res.json({
        success: true,
        data: banks
      });
    } else {
      throw new Error(response.data.message || 'Failed to fetch banks');
    }
  } catch (error) {
    console.error('❌ Get banks error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bank list',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


// Verify account number with Paystack
app.post('/api/verify-account', authenticateToken, async (req, res) => {
  try {
    const { accountNumber, bankCode } = req.body;

    console.log('🔍 Verifying account details:', { accountNumber, bankCode });

    if (!accountNumber || !bankCode) {
      return res.status(400).json({
        success: false,
        message: 'Account number and bank code are required'
      });
    }

    if (!paymentProcessors.paystack) {
      return res.status(503).json({
        success: false,
        message: 'Paystack service not available'
      });
    }

    // Use Paystack's account verification endpoint
    const response = await paymentProcessors.paystack.verification.resolveAccount({
      account_number: accountNumber,
      bank_code: bankCode
    });

    if (response.data.status) {
      console.log('✅ Account verified successfully:', response.data.data.account_name);
      
      res.json({
        success: true,
        data: {
          accountName: response.data.data.account_name,
          accountNumber: response.data.data.account_number,
          bankCode: bankCode
        }
      });
    } else {
      throw new Error(response.data.message || 'Account verification failed');
    }
  } catch (error) {
    console.error('❌ Account verification error:', error);
    
    let errorMessage = 'Failed to verify account number';
    if (error.response?.data?.message) {
      errorMessage = error.response.data.message;
    } else if (error.message.includes('No account was found')) {
      errorMessage = 'Invalid account number or bank combination';
    }
    
    res.status(400).json({
      success: false,
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Updated bank account setup endpoint


app.get('/api/debug/user-payment-settings', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).lean();
    
    // Also check the raw database document
    const db = mongoose.connection.db;
    const rawUser = await db.collection('users').findOne(
      { _id: new mongoose.Types.ObjectId(req.user.id) },
      { projection: { paymentSettings: 1 } }
    );
    
    // Check User model schema
    const paymentSettingsSchema = User.schema.path('paymentSettings');
    
    res.json({
      success: true,
      data: {
        viaMongoose: {
          paymentSettings: user.paymentSettings,
          type: typeof user.paymentSettings,
          isObject: user.paymentSettings && typeof user.paymentSettings === 'object'
        },
        viaDirectDB: {
          paymentSettings: rawUser?.paymentSettings,
          type: typeof rawUser?.paymentSettings
        },
        schemaInfo: {
          exists: !!paymentSettingsSchema,
          instance: paymentSettingsSchema?.instance,
          isMixed: paymentSettingsSchema?.instance === 'Mixed',
          schemaTree: paymentSettingsSchema?.schema?.tree
        }
      }
    });
  } catch (error) {
    console.error('Payment settings debug error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});




// app.post('/api/providers/bank-account', authenticateToken, async (req, res) => {
//   try {
//     const { bankName, accountNumber, accountName, bankCode } = req.body;
    
//     // Validate required fields
//     if (!bankName || !accountNumber || !accountName || !bankCode) {
//       return res.status(400).json({
//         success: false,
//         message: 'All bank account details are required'
//       });
//     }

//     // Verify user is a provider
//     const user = await User.findById(req.user.id);
//     if (!user.userType.includes('provider')) {
//       return res.status(403).json({
//         success: false,
//         message: 'Only providers can add bank accounts'
//       });
//     }

//     // Create Paystack recipient (this is the crucial step)
//     let paystackRecipientCode;
//     try {
//       const recipientResponse = await paymentProcessors.paystack.recipient.create({
//         type: 'nuban',
//         name: accountName,
//         account_number: accountNumber,
//         bank_code: bankCode,
//         currency: 'NGN'
//       });

//       if (recipientResponse.status) {
//         paystackRecipientCode = recipientResponse.data.recipient_code;
//       } else {
//         throw new Error(recipientResponse.message || 'Failed to create Paystack recipient');
//       }
//     } catch (paystackError) {
//       console.error('Paystack recipient creation failed:', paystackError);
//       return res.status(400).json({
//         success: false,
//         message: 'Failed to verify bank account with Paystack: ' + paystackError.message
//       });
//     }

//     // Update user with bank account and recipient code
//     user.paymentSettings = {
//       paystackRecipientCode: paystackRecipientCode,
//       bankAccount: {
//         bankName,
//         accountNumber: accountNumber.slice(-4), // Store only last 4 digits for security
//         accountName,
//         bankCode
//       },
//       preferredPayoutMethod: 'paystack'
//     };

//     await user.save();

//     res.json({
//       success: true,
//       message: 'Bank account added successfully and verified with Paystack',
//       data: {
//         bankAccount: user.paymentSettings.bankAccount,
//         isVerified: true
//       }
//     });

//   } catch (error) {
//     console.error('Add bank account error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to add bank account',
//       error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
//     });
//   }
// });

// app.get('/api/providers/bank-account', authenticateToken, async (req, res) => {
//   try {
//     const user = await User.findById(req.user.id);
    
//     if (!user.paymentSettings || !user.paymentSettings.bankAccount) {
//       return res.json({
//         success: true,
//         data: null
//       });
//     }

//     res.json({
//       success: true,
//       data: user.paymentSettings
//     });
//   } catch (error) {
//     console.error('Get bank account error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to fetch bank account details'
//     });
//   }
// });

app.get('/api/providers/bank-account', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user.userType.includes('provider')) {
      return res.status(403).json({
        success: false,
        message: 'Only providers can add bank accounts'
      });
    }

    if (!user.paymentSettings || !user.paymentSettings.bankAccount) {
      return res.json({
        success: true,
        data: null,
        message: 'No bank account configured'
      });
    }

    // Check if bank account setup is complete
    const hasPaystackRecipientCode = !!user.paymentSettings.paystackRecipientCode;
    const hasFullAccountNumber = !!user.paymentSettings.bankAccount.fullAccountNumber;
    const hasBankCode = !!user.paymentSettings.bankAccount.bankCode;
    const hasAccountName = !!user.paymentSettings.bankAccount.accountName;

    const isComplete = hasPaystackRecipientCode && hasFullAccountNumber && hasBankCode && hasAccountName;

    res.json({
      success: true,
      data: {
        bankAccount: user.paymentSettings.bankAccount,
        isVerified: user.paymentSettings.verifiedAt !== null,
        verifiedAt: user.paymentSettings.verifiedAt,
        setupComplete: isComplete,
        missingFields: {
          paystackRecipientCode: !hasPaystackRecipientCode,
          fullAccountNumber: !hasFullAccountNumber,
          bankCode: !hasBankCode,
          accountName: !hasAccountName
        },
        needsReconfiguration: !hasPaystackRecipientCode
      }
    });

  } catch (error) {
    console.error('Fetch bank account error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bank account',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/payments/create-intent', authenticateToken, async (req, res) => {
  try {
    const { bookingId, amount, currency, customerCountry } = req.body;

    // Validate booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Determine payment processor based on customer country
    const isNigeria = customerCountry === 'NG' || customerCountry === 'Nigeria';
    const isUK = customerCountry === 'GB' || customerCountry === 'UK';

    if (isNigeria) {
      // Use Paystack for Nigeria
      const paystackResponse = await paystack.transaction.initialize({
        amount: amount * 100, // Convert to kobo
        email: req.user.email,
        currency: 'NGN',
        metadata: {
          bookingId: bookingId,
          customerId: req.user.id,
          paymentType: 'escrow'
        },
        callback_url: `${process.env.FRONTEND_URL}/payment-verify`
      });

      // Store payment intent in booking
      booking.payment = {
        processor: 'paystack',
        paymentIntentId: paystackResponse.data.reference,
        amount: amount,
        currency: 'NGN',
        status: 'requires_payment_method',
        autoRefundAt: new Date(Date.now() + 4 * 60 * 60 * 1000) // 4 hours from now
      };

      await booking.save();

      res.json({
        success: true,
        processor: 'paystack',
        authorizationUrl: paystackResponse.data.authorization_url,
        reference: paystackResponse.data.reference
      });

    } else {
      // Use Stripe for UK and other countries
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100), // Convert to cents/pence
        currency: isUK ? 'gbp' : 'usd',
        capture_method: 'manual', // This holds the payment until manually captured
        metadata: {
          bookingId: bookingId,
          customerId: req.user.id,
          paymentType: 'escrow'
        }
      });

      // Store payment intent in booking
      booking.payment = {
        processor: 'stripe',
        paymentIntentId: paymentIntent.id,
        amount: amount,
        currency: isUK ? 'GBP' : 'USD',
        status: 'requires_payment_method',
        autoRefundAt: new Date(Date.now() + 4 * 60 * 60 * 1000) // 4 hours from now
      };

      await booking.save();

      res.json({
        success: true,
        processor: 'stripe',
        clientSecret: paymentIntent.client_secret,
        paymentIntentId: paymentIntent.id
      });
    }

  } catch (error) {
    console.error('Create payment intent error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment intent'
    });
  }
});

app.post('/api/payments/verify-paystack', authenticateToken, async (req, res) => {
  try {
    const { reference, bookingId } = req.body;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify payment with Paystack
    const verification = await paystack.transaction.verify(reference);

    if (verification.data.status === 'success') {
      // Update booking payment status
      booking.payment.status = 'held';
      booking.payment.heldAt = new Date();
      await booking.save();

      // Send notification to provider
      await Notification.createNotification({
        userId: booking.providerId,
        type: 'payment_received',
        title: 'Payment Received',
        message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your service`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'high'
      });

      res.json({
        success: true,
        message: 'Payment verified successfully',
        paymentStatus: 'held'
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Payment verification failed'
      });
    }

  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify payment'
    });
  }
});


app.post('/api/payments/confirm-stripe', authenticateToken, async (req, res) => {
  try {
    const { paymentIntentId, bookingId } = req.body;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // For Stripe, payment is automatically held when created with capture_method: 'manual'
    booking.payment.status = 'held';
    booking.payment.heldAt = new Date();
    await booking.save();

    // Send notification to provider
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'payment_received',
      title: 'Payment Received',
      message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your service`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Payment confirmed successfully',
      paymentStatus: 'held'
    });

  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm payment'
    });
  }
});

app.post('/api/payments/release', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.body;

    const booking = await Booking.findById(bookingId).populate('providerId');
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify user is authorized to release payment
    if (booking.customerId.toString() !== req.user.id && req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to release this payment'
      });
    }

    if (booking.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    if (booking.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Booking must be completed before releasing payment'
      });
    }

    const provider = booking.providerId;

    if (booking.payment.processor === 'stripe') {
      // Capture the held Stripe payment
      await stripe.paymentIntents.capture(booking.payment.paymentIntentId);

      // Calculate platform commission (20%)
      const commission = booking.payment.amount * 0.20;
      const providerAmount = booking.payment.amount * 0.80;

      // Update provider earnings
      provider.totalEarnings = (provider.totalEarnings || 0) + providerAmount;
      await provider.save();

      // Update payment status
      booking.payment.status = 'released';
      booking.payment.commission = commission;
      booking.payment.providerAmount = providerAmount;
      booking.payment.releasedAt = new Date();

    } else if (booking.payment.processor === 'paystack') {
      // For Paystack, you would initiate a transfer to the provider's bank account
      // This requires the provider to have set up their bank account details
      
      if (!provider.paystackRecipientCode) {
        return res.status(400).json({
          success: false,
          message: 'Provider has not set up their bank account for payments'
        });
      }

      // Calculate amounts
      const commission = booking.payment.amount * 0.20;
      const providerAmount = booking.payment.amount * 0.80;

      // Initiate transfer to provider (you need to implement this based on your Paystack setup)
      const transfer = await paystack.transfer.create({
        source: 'balance',
        amount: Math.round(providerAmount * 100), // Convert to kobo
        recipient: provider.paystackRecipientCode,
        reason: `Payment for ${booking.serviceType} service`
      });

      // Update provider earnings
      provider.totalEarnings = (provider.totalEarnings || 0) + providerAmount;
      await provider.save();

      // Update payment status
      booking.payment.status = 'released';
      booking.payment.commission = commission;
      booking.payment.providerAmount = providerAmount;
      booking.payment.releasedAt = new Date();
    }

    await booking.save();

    // Notify provider
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'payment_released',
      title: 'Payment Released',
      message: `Payment of ${booking.payment.currency}${booking.payment.providerAmount} has been released to your account`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Payment released to provider successfully',
      data: {
        providerAmount: booking.payment.providerAmount,
        commission: booking.payment.commission
      }
    });

  } catch (error) {
    console.error('Release payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to release payment'
    });
  }
});


app.post('/api/payments/auto-refund-expired', async (req, res) => {
  try {
    // This would typically be called by a cron job
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
    
    const expiredBookings = await Booking.find({
      status: 'pending',
      'payment.status': 'held',
      'payment.autoRefundAt': { $lte: new Date() }
    });

    for (const booking of expiredBookings) {
      try {
        if (booking.payment.processor === 'stripe') {
          // Refund the Stripe payment
          await stripe.refunds.create({
            payment_intent: booking.payment.paymentIntentId
          });
        } else if (booking.payment.processor === 'paystack') {
          // For Paystack, you might need to implement refund logic
          // This depends on your Paystack integration
          console.log(`Would refund Paystack payment: ${booking.payment.paymentIntentId}`);
        }

        // Update booking status
        booking.payment.status = 'refunded';
        booking.payment.refundedAt = new Date();
        booking.status = 'cancelled';
        await booking.save();

        // Notify customer
        await Notification.createNotification({
          userId: booking.customerId,
          type: 'payment_refunded',
          title: 'Payment Refunded',
          message: `Your payment has been refunded as the provider didn't accept the booking within 4 hours`,
          relatedId: booking._id,
          relatedType: 'booking',
          priority: 'medium'
        });

      } catch (error) {
        console.error(`Failed to refund booking ${booking._id}:`, error);
      }
    }

    res.json({
      success: true,
      message: `Processed ${expiredBookings.length} expired bookings`
    });

  } catch (error) {
    console.error('Auto refund error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process auto refunds'
    });
  }
});


app.post('/api/payments/confirm-service-completion', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.body;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm service completion'
      });
    }

    // Mark service as confirmed by customer
    booking.serviceConfirmedByCustomer = true;
    booking.serviceConfirmedAt = new Date();
    
    // If payment is held, automatically release it
    if (booking.payment.status === 'held') {
      // You can either auto-release here or require manual release
      // For now, we'll auto-release when customer confirms service completion
      booking.payment.status = 'released';
      booking.payment.releasedAt = new Date();
    }

    await booking.save();

    res.json({
      success: true,
      message: 'Service completion confirmed successfully'
    });

  } catch (error) {
    console.error('Confirm service completion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm service completion'
    });
  }
});

cron.schedule('0 * * * *', async () => {
  try {
    console.log('🔄 Running auto-refund check...');
    
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
    
    const expiredBookings = await Booking.find({
      status: 'pending',
      'payment.status': 'held',
      'payment.autoRefundAt': { $lte: new Date() }
    });

    for (const booking of expiredBookings) {
      try {
        console.log(`🔄 Auto-refunding booking ${booking._id}`);
        
        if (booking.payment.processor === 'stripe') {
          await stripe.refunds.create({
            payment_intent: booking.payment.paymentIntentId
          });
        }
        // Add Paystack refund logic here

        booking.payment.status = 'refunded';
        booking.payment.refundedAt = new Date();
        booking.status = 'cancelled';
        await booking.save();

        console.log(`✅ Auto-refunded booking ${booking._id}`);
        
      } catch (error) {
        console.error(`❌ Failed to auto-refund booking ${booking._id}:`, error);
      }
    }
    
    console.log(`✅ Auto-refund check completed. Processed ${expiredBookings.length} bookings.`);
  } catch (error) {
    console.error('❌ Auto-refund job error:', error);
  }
});

const determinePaymentProcessor = (customerCountry, providerCountry) => {
  const isNigeria = customerCountry === 'NG' || providerCountry === 'NG';
  const isUK = customerCountry === 'GB' || providerCountry === 'GB';
  
  // Check available processors
  const hasStripe = !!paymentProcessors.stripe;
  const hasPaystack = !!paymentProcessors.paystack;
  
  console.log('🔍 Payment Processor Availability:', { hasStripe, hasPaystack, isNigeria, isUK });

  if (isNigeria && hasPaystack) {
    return 'paystack';
  }
  if ((isUK || !isNigeria) && hasStripe) {
    return 'stripe';
  }
  
  // Fallback logic
  if (hasPaystack) return 'paystack';
  if (hasStripe) return 'stripe';
  
  // No processors configured
  
};


// app.post('/api/bookings/:bookingId/create-payment', authenticateToken, async (req, res) => {
//   try {
//     const { bookingId } = req.params;
//     const { amount, customerCountry = 'NIGERIA' } = req.body;

//     console.log('🔍 Payment Creation Debug:', {
//       bookingId,
//       amount,
//       customerCountry,
//       user: req.user.id,
//       body: req.body
//     });

//     // Input validation
//     if (!bookingId || !mongoose.Types.ObjectId.isValid(bookingId)) {
//       console.log('❌ Invalid booking ID:', bookingId);
//       return res.status(400).json({
//         success: false,
//         message: 'Valid booking ID is required',
//         code: 'INVALID_BOOKING_ID'
//       });
//     }

//     if (!amount || isNaN(amount) || amount <= 0) {
//       console.log('❌ Invalid amount:', amount);
//       return res.status(400).json({
//         success: false,
//         message: 'Valid payment amount is required',
//         code: 'INVALID_AMOUNT'
//       });
//     }

//     // Find booking with better error handling
//     const booking = await Booking.findById(bookingId).populate('customerId', 'email');
//     if (!booking) {
//       console.log('❌ Booking not found:', bookingId);
//       return res.status(404).json({
//         success: false,
//         message: 'Booking not found',
//         code: 'BOOKING_NOT_FOUND'
//       });
//     }

//     console.log('✅ Booking found:', {
//       bookingId: booking._id,
//       customerId: booking.customerId?._id,
//       currentUserId: req.user.id,
//       bookingStatus: booking.status,
//       existingPayment: booking.payment
//     });

//     // Check authorization
//     if (booking.customerId._id.toString() !== req.user.id) {
//       console.log('❌ Authorization failed:', {
//         bookingCustomer: booking.customerId._id.toString(),
//         currentUser: req.user.id
//       });
//       return res.status(403).json({
//         success: false,
//         message: 'Not authorized to pay for this booking',
//         code: 'UNAUTHORIZED_PAYMENT'
//       });
//     }

//     console.log('✅ Authorization passed, proceeding with payment...');

//     // Check if booking already has an active payment
//     // Check if booking already has an active payment
// if (booking.payment && booking.payment.status === 'requires_payment_method') {
//   console.log('⚠️ Payment already initiated for booking:', {
//     paymentIntentId: booking.payment.paymentIntentId,
//     processor: booking.payment.processor,
//     status: booking.payment.status,
//     initiatedAt: booking.payment.initiatedAt,
//     timeSinceInitiation: booking.payment.initiatedAt ? 
//       Date.now() - new Date(booking.payment.initiatedAt).getTime() : 'unknown'
//   });

//   // CRITICAL FIX: For requires_payment_method status, treat as retry and create NEW reference
//   console.log('🔄 Payment requires new attempt - creating new reference...');
  
//   // Don't return here - continue to create a new payment with fresh reference
//   // We'll update the existing payment record with new reference below
// }

//     const paymentAmount = parseFloat(amount);
//     const bookingAmount = booking.price || booking.amount;
    
//     // Validate payment amount against booking amount with tolerance
//     if (bookingAmount && Math.abs(paymentAmount - bookingAmount) > 0.01) {
//       console.log('⚠️ Payment amount differs from booking amount:', {
//         paymentAmount,
//         bookingAmount,
//         difference: Math.abs(paymentAmount - bookingAmount)
//       });
//     }

//     // Convert country name to code
//     const getCountryCode = (country) => {
//       if (!country) return 'NG';
      
//       const countryMap = {
//         'nigeria': 'NG',
//         'ng': 'NG',
//         'united kingdom': 'GB',
//         'uk': 'GB',
//         'gb': 'GB',
//         'united states': 'US',
//         'usa': 'US',
//         'us': 'US'
//       };
      
//       return countryMap[country.toLowerCase()] || 'NG';
//     };

//     const countryCode = getCountryCode(customerCountry);
    
//     console.log('🌍 Country processing:', {
//       received: customerCountry,
//       processed: countryCode
//     });

//     // Now use countryCode instead of customerCountry in payment logic
//     const isNigeria = countryCode === 'NG';
//     const isUK = countryCode === 'GB';
    
//     console.log('💰 Processing payment:', {
//       paymentAmount,
//       originalCountry: customerCountry,
//       processedCountryCode: countryCode,
//       isNigeria,
//       isUK,
//       userEmail: req.user.email
//     });

//     let paymentResult;

//     if (isNigeria) {
//       // PAYSTACK PAYMENT (Nigeria)
//       console.log('🌍 Using Paystack for Nigerian customer');
      
//       if (!paymentProcessors.paystack) {
//         console.log('❌ Paystack processor not configured');
//         return res.status(503).json({
//           success: false,
//           message: 'Paystack payment processor is not configured',
//           code: 'PAYMENT_PROCESSOR_UNAVAILABLE'
//         });
//       }

//       try {
// const paystackPayload = {
//   amount: Math.round(paymentAmount * 100),
//   email: req.user.email || booking.customerId.email,
//   currency: 'NGN',
//   metadata: {
//     bookingId: bookingId,
//     customerId: req.user.id,
//     paymentType: 'escrow'
//   },
//   callback_url: `${process.env.FRONTEND_URL}/customer/payment-status?bookingId=${bookingId}&processor=paystack`
// };

//         console.log('📤 Paystack request payload:', paystackPayload);

//         const paystackResponse = await paymentProcessors.paystack.transaction.initialize(paystackPayload);

//         console.log('📥 Paystack response:', {
//           status: paystackResponse.status,
//           reference: paystackResponse.data?.reference,
//           authorizationUrl: paystackResponse.data?.authorization_url ? 'present' : 'missing'
//         });

//         if (!paystackResponse.status) {
//           throw new Error(paystackResponse.message || 'Paystack initialization failed');
//         }

//         paymentResult = {
//           success: true,
//           processor: 'paystack',
//           paymentIntentId: paystackResponse.data.reference,
//           authorizationUrl: paystackResponse.data.authorization_url,
//           accessCode: paystackResponse.data.access_code,
//           amount: paymentAmount,
//           currency: 'NGN',
//           status: 'requires_payment_method',
//           existingPayment: false
//         };

//         console.log('✅ Paystack payment initialized successfully:', paystackResponse.data.reference);

//       } catch (paystackError) {
//         console.error('❌ Paystack payment creation failed:', {
//           error: paystackError.message,
//           stack: paystackError.stack,
//           response: paystackError.response?.data
//         });
//         return res.status(502).json({
//           success: false,
//           message: 'Paystack payment service unavailable',
//           error: process.env.NODE_ENV === 'development' ? paystackError.message : undefined,
//           code: 'PAYSTACK_SERVICE_ERROR'
//         });
//       }

//     } else {
//       // STRIPE PAYMENT (International)
//       console.log('🌍 Using Stripe for international customer:', { 
//         originalCountry: customerCountry,
//         countryCode,
//         isUK 
//       });
      
//       if (!paymentProcessors.stripe) {
//         console.log('❌ Stripe processor not configured');
//         return res.status(503).json({
//           success: false,
//           message: 'Stripe payment processor is not configured',
//           code: 'PAYMENT_PROCESSOR_UNAVAILABLE'
//         });
//       }

//       const currency = isUK ? 'gbp' : 'usd';
      
//       try {
//         const stripePayload = {
//           amount: Math.round(paymentAmount * 100), // Convert to cents/pence
//           currency: currency,
//           capture_method: 'manual', // Hold payment until service completion
//           metadata: {
//             bookingId: bookingId,
//             customerId: req.user.id,
//             paymentType: 'escrow',
//             originalCountry: customerCountry,
//             processedCountryCode: countryCode,
//             timestamp: new Date().toISOString()
//           },
//           automatic_payment_methods: {
//             enabled: true,
//           },
//           description: `Payment for booking ${bookingId}`,
//         };

//         console.log('📤 Stripe request payload:', stripePayload);

//         const paymentIntent = await paymentProcessors.stripe.paymentIntents.create(stripePayload);

//         console.log('📥 Stripe response:', {
//           id: paymentIntent.id,
//           status: paymentIntent.status,
//           clientSecret: paymentIntent.client_secret ? 'present' : 'missing'
//         });

//         paymentResult = {
//           success: true,
//           processor: 'stripe',
//           paymentIntentId: paymentIntent.id,
//           clientSecret: paymentIntent.client_secret,
//           amount: paymentAmount,
//           currency: currency.toUpperCase(),
//           status: paymentIntent.status,
//           existingPayment: false
//         };

//         console.log('✅ Stripe payment intent created successfully:', paymentIntent.id);

//       } catch (stripeError) {
//         console.error('❌ Stripe payment creation failed:', {
//           error: stripeError.message,
//           stack: stripeError.stack,
//           type: stripeError.type,
//           code: stripeError.code
//         });
//         return res.status(502).json({
//           success: false,
//           message: 'Stripe payment service unavailable',
//           error: process.env.NODE_ENV === 'development' ? stripeError.message : undefined,
//           code: 'STRIPE_SERVICE_ERROR'
//         });
//       }
//     }

//     // Update booking with payment info
//     console.log('💾 Updating booking with payment information...');
    
//     booking.payment = {
//       processor: isNigeria ? 'paystack' : 'stripe',
//       paymentIntentId: paymentResult.paymentIntentId,
//       amount: paymentResult.amount,
//       currency: paymentResult.currency,
//       status: paymentResult.status,
//       initiatedAt: new Date(),
//       autoRefundAt: new Date(Date.now() + 4 * 60 * 60 * 1000), // 4 hours from now
//       originalCountry: customerCountry,
//       processedCountryCode: countryCode,
//       authorizationUrl: paymentResult.authorizationUrl,
//       clientSecret: paymentResult.clientSecret
//     };

//     // Add payment history entry
//     booking.paymentHistory = booking.paymentHistory || [];
//     booking.paymentHistory.push({
//       action: 'payment_initiated',
//       processor: booking.payment.processor,
//       paymentIntentId: paymentResult.paymentIntentId,
//       amount: paymentResult.amount,
//       currency: paymentResult.currency,
//       status: paymentResult.status,
//       originalCountry: customerCountry,
//       processedCountryCode: countryCode,
//       timestamp: new Date()
//     });

//     await booking.save();

//     console.log('✅ Booking updated successfully with payment info:', {
//       bookingId: booking._id,
//       paymentIntentId: paymentResult.paymentIntentId,
//       processor: booking.payment.processor,
//       countryCode: countryCode
//     });

//     res.json({
//       success: true,
//       message: 'Payment intent created successfully',
//       data: paymentResult
//     });

//   } catch (error) {
//     console.error('❌ Create payment error details:', {
//       error: error.message,
//       stack: error.stack,
//       bookingId: req.params.bookingId,
//       user: req.user.id,
//       timestamp: new Date().toISOString()
//     });
    
//     // Handle specific error types
//     if (error.name === 'CastError') {
//       return res.status(400).json({
//         success: false,
//         message: 'Invalid booking ID format',
//         code: 'INVALID_BOOKING_ID'
//       });
//     }

//     if (error.name === 'ValidationError') {
//       return res.status(400).json({
//         success: false,
//         message: 'Validation error',
//         error: process.env.NODE_ENV === 'development' ? error.message : undefined,
//         code: 'VALIDATION_ERROR'
//       });
//     }

//     res.status(500).json({
//       success: false,
//       message: 'Failed to create payment intent',
//       error: process.env.NODE_ENV === 'development' ? error.message : undefined,
//       code: 'PAYMENT_CREATION_FAILED'
//     });
//   }
// });

app.get('/api/bookings/:bookingId/payment-url', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this payment'
      });
    }

    if (!booking.payment) {
      return res.status(404).json({
        success: false,
        message: 'No payment found for this booking'
      });
    }

    // For Paystack, use the correct URL format
    if (booking.payment.processor === 'paystack' && booking.payment.paymentIntentId) {
      // If we stored the authorization URL, use it
      if (booking.payment.authorizationUrl) {
        return res.json({
          success: true,
          data: {
            authorizationUrl: booking.payment.authorizationUrl,
            paymentIntentId: booking.payment.paymentIntentId,
            amount: booking.payment.amount,
            currency: booking.payment.currency,
            status: booking.payment.status
          }
        });
      }
      
      // Otherwise, construct the correct Paystack URL
      const authorizationUrl = `https://checkout.paystack.com/${paymentResult.data.access_code}`;

      if (!authorizationUrl.includes('checkout.paystack.com')) {
  console.error('Invalid Paystack URL:', authorizationUrl);
  alert('Invalid payment URL. Please try again.');
  return;
}
      
      console.log('🔗 Constructed Paystack URL:', authorizationUrl);
      
      return res.json({
        success: true,
        data: {
          authorizationUrl: authorizationUrl,
          paymentIntentId: booking.payment.paymentIntentId,
          amount: booking.payment.amount,
          currency: booking.payment.currency,
          status: booking.payment.status
        }
      });
    }

    res.status(400).json({
      success: false,
      message: 'Unable to generate payment URL'
    });

  } catch (error) {
    console.error('Get payment URL error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment URL'
    });
  }
});

app.post('/api/debug/test-paystack-direct', async (req, res) => {
  try {
    const { amount, email } = req.body;
    
    if (!paymentProcessors.paystack) {
      return res.status(400).json({
        success: false,
        message: 'Paystack not initialized'
      });
    }

    const testPayload = {
      amount: Math.round((amount || 10000)), // 100 NGN
      email: email || 'test@example.com',
      currency: 'NGN',
      callback_url: `${process.env.FRONTEND_URL}/payment-verify`
    };

    console.log('🧪 Testing Paystack directly with:', testPayload);

    const response = await paymentProcessors.paystack.transaction.initialize(testPayload);

    console.log('🔍 FULL PAYSTACK RESPONSE:', JSON.stringify(response, null, 2));

    res.json({
      success: true,
      data: {
        status: response.status,
        message: response.message,
        authorization_url: response.data?.authorization_url,
        reference: response.data?.reference,
        access_code: response.data?.access_code,
        full_response: response
      }
    });

  } catch (error) {
    console.error('❌ Direct Paystack test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      response: error.response?.data
    });
  }
});

// Add this debug endpoint to reset payment
app.delete('/api/debug/bookings/:bookingId/reset-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Reset payment
    booking.payment = undefined;
    await booking.save();

    res.json({
      success: true,
      message: 'Payment reset successfully'
    });

  } catch (error) {
    console.error('Reset payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset payment'
    });
  }
});

app.post('/api/service-requests/:id/provider-arrived', authenticateToken, async (req, res) => {
  try {
    const serviceRequestId = req.params.id;

    const serviceRequest = await ServiceRequest.findById(serviceRequestId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check if user is the provider for this service request
    if (serviceRequest.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm arrival for this service request'
      });
    }

    // Check if service request is in correct status
    if (serviceRequest.status !== 'accepted') {
      return res.status(400).json({
        success: false,
        message: 'Service request is not in accepted status'
      });
    }

    // Check if provider already confirmed arrival
    if (serviceRequest.providerArrived) {
      return res.status(400).json({
        success: false,
        message: 'Arrival already confirmed'
      });
    }

    // Update service request with provider arrival confirmation
    serviceRequest.providerArrived = true;
    serviceRequest.providerArrivedAt = new Date();
    serviceRequest.status = 'awaiting_hero';
    serviceRequest.showHeroHereButton = true;
    
    await serviceRequest.save();

    // Notify customer that provider has arrived
    await Notification.createNotification({
      userId: serviceRequest.customerId,
      type: 'provider_arrived',
      title: 'Your Hero Has Arrived!',
      message: `${serviceRequest.providerId.name} has arrived at your location. Please confirm they are here to start the service.`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Arrival confirmed successfully. Customer can now confirm you are here.',
      data: {
        providerArrived: true,
        providerArrivedAt: serviceRequest.providerArrivedAt,
        showHeroHereButton: true
      }
    });

  } catch (error) {
    console.error('Provider arrived confirmation error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm arrival'
    });
  }
});

app.post('/api/service-requests/:id/confirm-hero-here', authenticateToken, async (req, res) => {
  try {
    const serviceRequestId = req.params.id;

    const serviceRequest = await ServiceRequest.findById(serviceRequestId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check if user is the customer for this service request
    if (serviceRequest.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm service for this service request'
      });
    }

    // Check if provider has confirmed arrival first
    if (!serviceRequest.providerArrived) {
      return res.status(400).json({
        success: false,
        message: 'Provider has not confirmed arrival yet'
      });
    }

    // Check if "Hero Here" button should be visible
    if (!serviceRequest.showHeroHereButton) {
      return res.status(400).json({
        success: false,
        message: 'Cannot confirm hero here at this time'
      });
    }

    // Update service request with customer confirmation
    serviceRequest.customerSeenProvider = true;
    serviceRequest.customerSeenProviderAt = new Date();
    serviceRequest.heroHereConfirmed = true;
    serviceRequest.status = 'in_progress';
    serviceRequest.startedAt = new Date();
    
    // Set auto-refund timer (4 hours from now)
    serviceRequest.autoRefundAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
    
    await serviceRequest.save();

    // Notify provider that customer confirmed their arrival
    await Notification.createNotification({
      userId: serviceRequest.providerId,
      type: 'hero_here_confirmed',
      title: 'Customer Confirmed Your Arrival!',
      message: 'The customer has confirmed you are at the location. Service can begin.',
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Hero here confirmed successfully. Service has started.',
      data: {
        autoRefundAt: serviceRequest.autoRefundAt,
        heroHereConfirmed: true,
        startedAt: serviceRequest.startedAt
      }
    });

  } catch (error) {
    console.error('Confirm hero here error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm hero here'
    });
  }
});

app.post('/api/service-requests/:id/provider-complete', authenticateToken, async (req, res) => {
  try {
    const serviceRequestId = req.params.id;

    const serviceRequest = await ServiceRequest.findById(serviceRequestId).populate('providerId');
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check if user is the provider for this service request
    if (serviceRequest.providerId._id.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to complete this job'
      });
    }

    // Check if customer has confirmed seeing provider
    if (!serviceRequest.customerSeenProvider) {
      return res.status(400).json({
        success: false,
        message: 'Customer has not confirmed seeing you yet'
      });
    }

    // Check if payment is still held
    if (serviceRequest.payment.status !== 'held') {
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Update service request status to completed by provider
    serviceRequest.status = 'provider_completed';
    serviceRequest.providerCompletedJob = true;
    serviceRequest.providerCompletedAt = new Date();
    
    await serviceRequest.save();

    // Notify customer to confirm completion
    await Notification.createNotification({
      userId: serviceRequest.customerId,
      type: 'job_completed_by_provider',
      title: 'Service Completed!',
      message: `${serviceRequest.providerId.name} has marked the service as completed. Please confirm the service is completed to release payment.`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Job marked as completed. Waiting for customer confirmation to release payment.',
      data: serviceRequest
    });

  } catch (error) {
    console.error('Provider job completion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete job'
    });
  }
});

app.post('/api/service-requests/:id/customer-confirm-completion', authenticateToken, async (req, res) => {
  try {
    const serviceRequestId = req.params.id;

    console.log('🔍 Customer confirm completion for service request:', serviceRequestId);
    
    // Get service request
    const serviceRequest = await ServiceRequest.findById(serviceRequestId);
    
    if (!serviceRequest) {
      console.log('❌ Service request not found:', serviceRequestId);
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    console.log('🔍 Service request found:', {
      serviceRequestId: serviceRequest._id,
      status: serviceRequest.status,
      providerId: serviceRequest.providerId,
      customerId: serviceRequest.customerId
    });

    // Check if user is the customer for this service request
    if (serviceRequest.customerId.toString() !== req.user.id) {
      console.log('❌ Authorization failed:', {
        serviceRequestCustomer: serviceRequest.customerId.toString(),
        currentUser: req.user.id
      });
      return res.status(403).json({
        success: false,
        message: 'Not authorized to confirm completion'
      });
    }

    // Get provider data directly from database
    const db = mongoose.connection.db;
    const providerDoc = await db.collection('users').findOne(
      { _id: new mongoose.Types.ObjectId(serviceRequest.providerId) },
      { projection: { paymentSettings: 1, name: 1, email: 1 } }
    );

    if (!providerDoc) {
      console.log('❌ Provider not found:', serviceRequest.providerId);
      return res.status(400).json({
        success: false,
        message: 'Provider information not found'
      });
    }

    console.log('🔍 [DIRECT DB] Provider data:', {
      providerId: providerDoc._id,
      providerName: providerDoc.name,
      hasPaymentSettings: !!providerDoc.paymentSettings,
      paystackRecipientCode: providerDoc.paymentSettings?.paystackRecipientCode
    });

    // Check if provider has Paystack recipient code
    if (!providerDoc.paymentSettings?.paystackRecipientCode) {
      console.error('❌ Provider missing Paystack recipient code');
      
      return res.status(400).json({
        success: false,
        message: 'Provider needs to complete bank account setup with Paystack verification'
      });
    }

    console.log('✅ [SUCCESS] Provider has valid Paystack recipient code:', providerDoc.paymentSettings.paystackRecipientCode);
    
    // Check service request status
    const validStatusesForCompletion = ['provider_completed', 'completed'];
    if (!validStatusesForCompletion.includes(serviceRequest.status)) {
      console.log('❌ Invalid service request status:', serviceRequest.status);
      return res.status(400).json({
        success: false,
        message: 'Service has not been marked as completed by the provider yet'
      });
    }

    // Check if customer has already confirmed completion
    if (serviceRequest.customerConfirmedCompletion) {
      console.log('❌ Already confirmed completion');
      return res.status(400).json({
        success: false,
        message: 'You have already confirmed completion for this service'
      });
    }

    // Check if payment is still held
    if (serviceRequest.payment.status !== 'held') {
      console.log('❌ Payment not held:', serviceRequest.payment.status);
      return res.status(400).json({
        success: false,
        message: 'Payment is not in held status'
      });
    }

    // Calculate amounts (15% company, 85% provider)
    const totalAmount = serviceRequest.payment.amount;
    const companyAmount = totalAmount * 0.15;
    const providerAmount = totalAmount * 0.85;

    console.log('💰 Payment Split (15%/85%):', {
      totalAmount,
      companyAmount,
      providerAmount,
      providerRecipientCode: providerDoc.paymentSettings.paystackRecipientCode
    });

    // Process transfers (15% to company, 85% to provider)
    let companyTransferResult, providerTransferResult;

    try {
      // Transfer 15% to company account
      companyTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(companyAmount * 100), // Convert to kobo
        recipient: COMPANY_ACCOUNT.paystackRecipientCode,
        reason: `Home Heroes Platform Fee - Service Request ${serviceRequestId}`
      });

      if (!companyTransferResult.status) {
        throw new Error(`Company transfer failed: ${companyTransferResult.message}`);
      }

      console.log('✅ Company fee transfer initiated:', companyTransferResult.data.transfer_code);

    } catch (companyTransferError) {
      console.error('❌ Company transfer failed:', companyTransferError);
      return res.status(500).json({
        success: false,
        message: 'Failed to transfer company fee: ' + companyTransferError.message,
        code: 'COMPANY_TRANSFER_FAILED'
      });
    }

    try {
      // Transfer 85% to provider account
      providerTransferResult = await paymentProcessors.paystack.transfer.create({
        source: 'balance',
        amount: Math.round(providerAmount * 100), // Convert to kobo
        recipient: providerDoc.paymentSettings.paystackRecipientCode,
        reason: `Payment for ${serviceRequest.serviceType} service - Service Request ${serviceRequestId}`
      });

      if (!providerTransferResult.status) {
        throw new Error(`Provider transfer failed: ${providerTransferResult.message}`);
      }

      console.log('✅ Provider transfer initiated:', providerTransferResult.data.transfer_code);

    } catch (providerTransferError) {
      console.error('❌ Provider transfer failed:', providerTransferError);
      
      // Try to reverse the company transfer
      try {
        if (companyTransferResult?.data?.transfer_code) {
          await paymentProcessors.paystack.transfer.reverse({
            transfer_code: companyTransferResult.data.transfer_code
          });
          console.log('✅ Reversed company transfer due to provider transfer failure');
        }
      } catch (reverseError) {
        console.error('❌ Failed to reverse company transfer:', reverseError);
      }

      return res.status(500).json({
        success: false,
        message: 'Failed to transfer payment to provider: ' + providerTransferError.message,
        code: 'PROVIDER_TRANSFER_FAILED'
      });
    }

    // Update provider earnings (only their 85% portion)
    await db.collection('users').updateOne(
      { _id: new mongoose.Types.ObjectId(serviceRequest.providerId) },
      { 
        $inc: { 
          'providerFinancials.totalEarnings': providerAmount,
          'providerFinancials.availableBalance': providerAmount
        },
        $setOnInsert: {
          'providerFinancials': {
            totalEarnings: providerAmount,
            availableBalance: providerAmount,
            pendingBalance: 0,
            totalWithdrawn: 0
          }
        }
      }
    );

    // Update service request with completion confirmation and payment details
    serviceRequest.customerConfirmedCompletion = true;
    serviceRequest.customerConfirmedAt = new Date();
    serviceRequest.status = 'completed';
    serviceRequest.completedAt = new Date();
    
    // Update payment details
    serviceRequest.payment.status = 'released';
    serviceRequest.payment.releasedAt = new Date();
    serviceRequest.payment.companyAmount = companyAmount;
    serviceRequest.payment.providerAmount = providerAmount;
    serviceRequest.payment.companyTransferCode = companyTransferResult.data.transfer_code;
    serviceRequest.payment.providerTransferCode = providerTransferResult.data.transfer_code;
    serviceRequest.payment.paymentReleased = true;
    serviceRequest.payment.paymentReleasedAt = new Date();
    
    await serviceRequest.save();

    // Send notifications
    await Notification.createNotification({
      userId: serviceRequest.providerId,
      type: 'payment_released',
      title: 'Payment Released!',
      message: `Payment of ${serviceRequest.payment.currency}${providerAmount} has been released to your bank account (85% of total). Company fee: ${serviceRequest.payment.currency}${companyAmount}`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'high'
    });

    await Notification.createNotification({
      userId: serviceRequest.customerId,
      type: 'payment_completed',
      title: 'Payment Completed',
      message: `Payment has been released to ${providerDoc.name} for the completed service.`,
      relatedId: serviceRequest._id,
      relatedType: 'service_request',
      priority: 'medium'
    });

    res.json({
      success: true,
      message: 'Payment released successfully - 15% company fee, 85% to provider',
      data: {
        totalAmount,
        companyAmount,
        providerAmount,
        companyTransferCode: companyTransferResult.data.transfer_code,
        providerTransferCode: providerTransferResult.data.transfer_code,
        providerRecipientCode: providerDoc.paymentSettings.paystackRecipientCode
      }
    });

  } catch (error) {
    console.error('❌ Service request completion confirmation error:', error);
    
    // Check if it's the Paystack Starter Business error
    if (error.response?.data?.code === 'transfer_unavailable') {
      return res.status(400).json({
        success: false,
        message: 'Paystack account needs to be upgraded to Registered Business for transfers',
        error: error.response.data.message,
        suggestion: 'Upgrade your Paystack account to enable automatic transfers'
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to confirm service completion',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


async function processServiceRequestAutoRefunds() {
  try {
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
    
    const expiredServiceRequests = await ServiceRequest.find({
      status: 'awaiting_hero',
      'payment.status': 'held',
      'payment.heldAt': { $lte: fourHoursAgo },
      'payment.refundedAt': { $exists: false },
      'customerSeenProvider': { $ne: true }
    });

    for (const serviceRequest of expiredServiceRequests) {
      try {
        console.log(`🔄 Processing auto-refund for service request ${serviceRequest._id}`);
        
        // Initiate Paystack refund
        const refundResponse = await paymentProcessors.paystack.refund.create({
          transaction: serviceRequest.payment.paymentIntentId,
          amount: Math.round(serviceRequest.payment.amount * 100)
        });

        if (refundResponse.data.status === 'processed') {
          // Update service request status
          serviceRequest.payment.status = 'refunded';
          serviceRequest.payment.refundedAt = new Date();
          serviceRequest.status = 'cancelled';
          serviceRequest.cancellationReason = 'Auto-refund: Customer did not confirm seeing provider within 4 hours';
          await serviceRequest.save();

          // Notify customer
          await Notification.createNotification({
            userId: serviceRequest.customerId,
            type: 'payment_refunded',
            title: 'Payment Refunded',
            message: `Your payment has been refunded as you didn't confirm seeing the provider within 4 hours`,
            relatedId: serviceRequest._id,
            relatedType: 'service_request',
            priority: 'medium'
          });

          // Notify provider
          await Notification.createNotification({
            userId: serviceRequest.providerId,
            type: 'service_request_cancelled',
            title: 'Service Request Cancelled - Auto Refund',
            message: `Service request was automatically cancelled and refunded as customer didn't confirm seeing you within 4 hours`,
            relatedId: serviceRequest._id,
            relatedType: 'service_request',
            priority: 'medium'
          });

          console.log(`✅ Auto-refund processed for service request ${serviceRequest._id}`);
        }
      } catch (error) {
        console.error(`❌ Failed to auto-refund service request ${serviceRequest._id}:`, error);
      }
    }
  } catch (error) {
    console.error('Service request auto-refund processing error:', error);
  }
}

// Add to your existing cron schedule
cron.schedule('*/15 * * * *', () => {
  processAutoRefunds(); // For bookings
  processServiceRequestAutoRefunds(); // For service requests
});




app.get('/api/bookings/:bookingId/payment-details', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check authorization
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this payment'
      });
    }

    if (!booking.payment) {
      return res.status(404).json({
        success: false,
        message: 'No payment found for this booking'
      });
    }

    // For Stripe, get updated payment intent details
    if (booking.payment.processor === 'stripe' && booking.payment.paymentIntentId) {
      try {
        const paymentIntent = await paymentProcessors.stripe.paymentIntents.retrieve(
          booking.payment.paymentIntentId
        );
        
        // Update booking payment status if needed
        if (paymentIntent.status !== booking.payment.status) {
          booking.payment.status = paymentIntent.status;
          await booking.save();
        }

        res.json({
          success: true,
          data: {
            ...booking.payment.toObject(),
            clientSecret: paymentIntent.client_secret,
            status: paymentIntent.status
          }
        });
        return;
      } catch (stripeError) {
        console.error('Stripe retrieval error:', stripeError);
      }
    }

    // For Paystack or if Stripe retrieval fails, return existing payment data
    res.json({
      success: true,
      data: booking.payment
    });

  } catch (error) {
    console.error('Get payment details error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment details'
    });
  }
});

app.post('/api/bookings/:bookingId/confirm-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { paymentMethodId, processor = 'stripe' } = req.body;

    console.log('💰 Confirming payment for booking:', { 
      bookingId, 
      paymentMethodId,
      processor 
    });

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    if (!booking.payment) {
      return res.status(400).json({
        success: false,
        message: 'No payment found for this booking'
      });
    }

    let paymentResult;

    if (processor === 'stripe' && paymentProcessors.stripe && paymentMethodId) {
      try {
        console.log('🔐 Confirming Stripe payment with payment method:', paymentMethodId);
        
        // Confirm the payment intent with the payment method
        const paymentIntent = await paymentProcessors.stripe.paymentIntents.confirm(
          booking.payment.paymentIntentId,
          {
            payment_method: paymentMethodId,
            return_url: `${process.env.FRONTEND_URL}/payment-success?bookingId=${bookingId}`
          }
        );

        console.log('✅ Stripe payment intent status:', paymentIntent.status);

        if (paymentIntent.status === 'requires_capture' || paymentIntent.status === 'succeeded') {
          // Payment is held successfully
          booking.payment.status = 'held';
          booking.payment.heldAt = new Date();
          booking.status = 'confirmed';
          await booking.save();

          paymentResult = {
            success: true,
            paymentStatus: 'held',
            clientSecret: paymentIntent.client_secret,
            requiresAction: paymentIntent.status === 'requires_action',
            nextAction: paymentIntent.next_action
          };

          console.log('✅ Stripe payment confirmed and held');

        } else if (paymentIntent.status === 'requires_action') {
          // 3D Secure required
          paymentResult = {
            success: true,
            paymentStatus: 'requires_action',
            clientSecret: paymentIntent.client_secret,
            requiresAction: true,
            nextAction: paymentIntent.next_action
          };

          console.log('⚠️ Stripe payment requires 3D Secure');
        } else {
          throw new Error(`Unexpected payment status: ${paymentIntent.status}`);
        }

      } catch (stripeError) {
        console.error('❌ Stripe confirmation error:', stripeError);
        throw new Error(`Stripe payment failed: ${stripeError.message}`);
      }

    } else if (processor === 'paystack') {
      // For Paystack, payment is confirmed via webhook/callback
      // The webhook will update the status
      paymentResult = {
        success: true,
        paymentStatus: 'pending_verification',
        message: 'Payment pending verification via webhook'
      };

      console.log('✅ Paystack payment confirmation initiated');

    } else {
      throw new Error('Invalid payment processor or missing payment method');
    }

    // Send notification to provider
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'payment_received',
      title: 'Payment Received!',
      message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your ${booking.serviceType} service`,
      relatedId: booking._id,
      relatedType: 'booking',
      priority: 'high'
    });

    res.json({
      success: true,
      message: 'Payment confirmed successfully',
      data: {
        booking: booking,
        ...paymentResult
      }
    });

  } catch (error) {
    console.error('❌ Confirm payment error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Failed to confirm payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
      code: 'PAYMENT_CONFIRMATION_FAILED'
    });
  }
});

// app.post('/api/payments/paystack-webhook', async (req, res) => {
//   try {
//     const signature = req.headers['x-paystack-signature'];
    
//     if (!signature) {
//       return res.status(400).send('No signature');
//     }

//     // Verify webhook signature
//     const crypto = require('crypto');
//     const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
//                       .update(JSON.stringify(req.body))
//                       .digest('hex');
    
//     if (hash !== signature) {
//       return res.status(400).send('Invalid signature');
//     }

//     const event = req.body;
//     console.log('🔔 Paystack webhook received:', event.event);

//     if (event.event === 'charge.success') {
//       const { reference, amount, customer } = event.data;
      
//       // Find booking by Paystack reference
//       const booking = await Booking.findOne({
//         'payment.paymentIntentId': reference
//       });

//       if (booking) {
//         // Update booking payment status
//         booking.payment.status = 'held';
//         booking.payment.heldAt = new Date();
//         booking.status = 'confirmed';
//         await booking.save();

//         // Send notification to provider
//         await Notification.createNotification({
//           userId: booking.providerId,
//           type: 'payment_received',
//           title: 'Payment Received!',
//           message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your ${booking.serviceType} service`,
//           relatedId: booking._id,
//           relatedType: 'booking',
//           priority: 'high'
//         });

//         console.log('✅ Paystack payment verified and booking updated');
//       }
//     }

//     res.sendStatus(200);
//   } catch (error) {
//     console.error('❌ Paystack webhook error:', error);
//     res.status(500).send('Webhook error');
//   }
// });

app.post('/api/payments/paystack-webhook', async (req, res) => {
  try {
    const signature = req.headers['x-paystack-signature'];
    
    // Get the raw body properly
    let body;
    if (req.rawBody) {
      body = req.rawBody.toString();
    } else if (typeof req.body === 'string') {
      body = req.body;
    } else if (req.body) {
      body = JSON.stringify(req.body);
    } else {
      body = '';
    }
    
    console.log('🔔 Paystack Webhook Received for:', req.body?.event);

    // Verify signature (for production)
    if (process.env.NODE_ENV === 'production' && signature) {
      const crypto = await import('crypto');
      const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
                        .update(body)
                        .digest('hex');
      
      if (hash !== signature) {
        console.error('❌ Invalid webhook signature');
        return res.status(400).json({ success: false, message: 'Invalid signature' });
      }
    }

    const event = typeof body === 'string' ? JSON.parse(body) : body;

    if (event.event === 'charge.success') {
      const { reference, amount, customer, metadata } = event.data;
      
      console.log('✅ Payment Successful:', {
        reference,
        amount: amount / 100,
        customerEmail: customer.email,
        metadata: metadata || 'No metadata'
      });

      // Check if it's a booking
      const booking = await Booking.findOne({
        'payment.paymentIntentId': reference
      });

      if (booking) {
        // Handle booking payment (existing code)
        // ...
      }

      // Check if it's a service request
      const serviceRequest = await ServiceRequest.findOne({
        'payment.paymentIntentId': reference
      });

      if (serviceRequest) {
        console.log('🔍 Found service request:', {
          serviceRequestId: serviceRequest._id,
          currentStatus: serviceRequest.status,
          currentPaymentStatus: serviceRequest.payment?.status
        });

        // Check if already processed
        if (serviceRequest.payment?.status === 'held' || serviceRequest.status === 'accepted') {
          console.log('ℹ️ Service request already processed, skipping update');
          return res.json({ success: true, message: 'Already processed' });
        }

        // Update service request payment status to HELD
        serviceRequest.payment.status = 'held';
        serviceRequest.payment.heldAt = new Date();
        serviceRequest.payment.verifiedAt = new Date();
        serviceRequest.status = 'accepted'; // Payment successful, now accepted
        
        // Set auto-refund timer (4 hours from now)
        serviceRequest.autoRefundAt = new Date(Date.now() + 4 * 60 * 60 * 1000);
        
        await serviceRequest.save();

        console.log('✅ Service request updated:', {
          serviceRequestId: serviceRequest._id,
          newStatus: serviceRequest.status,
          newPaymentStatus: serviceRequest.payment.status,
          autoRefundAt: serviceRequest.autoRefundAt
        });

        // Send notification to provider
        try {
          await Notification.createNotification({
            userId: serviceRequest.providerId,
            type: 'payment_received',
            title: 'Payment Received!',
            message: `A customer has made a payment of ${serviceRequest.payment.currency}${serviceRequest.payment.amount} for your ${serviceRequest.serviceType} service.`,
            relatedId: serviceRequest._id,
            relatedType: 'service_request',
            priority: 'high'
          });
        } catch (notifError) {
          console.error('❌ Failed to send provider notification:', notifError);
        }

        // Send notification to customer
        try {
          await Notification.createNotification({
            userId: serviceRequest.customerId,
            type: 'payment_confirmed',
            title: 'Payment Confirmed!',
            message: `Your payment of ${serviceRequest.payment.currency}${serviceRequest.payment.amount} has been confirmed and is now held in escrow.`,
            relatedId: serviceRequest._id,
            relatedType: 'service_request',
            priority: 'high'
          });
        } catch (notifError) {
          console.error('❌ Failed to send customer notification:', notifError);
        }
      }
    }

    res.json({ success: true, message: 'Webhook processed' });
  } catch (error) {
    console.error('❌ Webhook processing error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message
    });
  }
});

app.post('/api/bookings/:bookingId/paystack-payment', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { amount, email } = req.body;

    console.log('🇳🇬 Initializing Paystack payment for booking:', bookingId);

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(400).json({
        success: false,
        message: 'Paystack is not configured'
      });
    }

    const Paystack = require('paystack')(process.env.PAYSTACK_SECRET_KEY);
    
    const paystackResponse = await Paystack.transaction.initialize({
      amount: Math.round(amount * 100), // Convert to kobo
      email: email,
      currency: 'NGN',
      metadata: {
        bookingId: bookingId,
        customerId: req.user.id,
        paymentType: 'escrow'
      },
      callback_url: `${process.env.FRONTEND_URL}/payment-verify?bookingId=${bookingId}`
    });

    if (!paystackResponse.status) {
      throw new Error('Paystack initialization failed');
    }

    // Update booking with Paystack reference
    booking.payment = {
      processor: 'paystack',
      paymentIntentId: paystackResponse.data.reference,
      amount: amount,
      currency: 'NGN',
      status: 'requires_payment_method',
      autoRefundAt: new Date(Date.now() + 4 * 60 * 60 * 1000)
    };
    await booking.save();

    console.log('✅ Paystack payment initialized');

    res.json({
      success: true,
      message: 'Paystack payment initialized',
      data: {
        authorizationUrl: paystackResponse.data.authorization_url,
        reference: paystackResponse.data.reference
      }
    });

  } catch (error) {
    console.error('❌ Paystack payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to initialize Paystack payment',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


app.get('/api/bookings/:bookingId/payment-status', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user has access to this booking
    if (booking.customerId.toString() !== req.user.id && booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view this booking payment'
      });
    }

    res.json({
      success: true,
      data: {
        payment: booking.payment,
        timeUntilAutoRefund: booking.payment?.autoRefundAt ? 
          booking.payment.autoRefundAt - new Date() : null
      }
    });

  } catch (error) {
    console.error('Get payment status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get payment status'
    });
  }
});

app.get('/api/payments/verify-paystack', async (req, res) => {
  try {
    const { reference, trxref, bookingId, isRetry } = req.query;
    
    console.log('🔍 Verifying Paystack payment:', { reference, trxref, bookingId, isRetry });

    const paymentReference = reference || trxref;
    
    if (!paymentReference) {
      return res.redirect(`${process.env.FRONTEND_URL}/customer/payment-status?status=failed&error=missing_reference`);
    }

    if (!paymentProcessors.paystack) {
      console.log('❌ Paystack not configured');
      return res.redirect(`${process.env.FRONTEND_URL}/customer/payment-status?status=failed&error=paystack_not_configured`);
    }

    const verification = await paymentProcessors.paystack.transaction.verify(paymentReference);

    if (verification.data.status === 'success') {
      // Find booking by payment reference
      const booking = await Booking.findOne({
        'payment.paymentIntentId': paymentReference
      });

      if (booking) {
        // ✅ CRITICAL: Update both payment status AND booking status
        booking.payment.status = 'held';
        booking.payment.heldAt = new Date();
        booking.status = 'confirmed'; // Change from 'awaiting_payment' to 'confirmed'
        
        // If this was a retry, mark it as such
        if (isRetry) {
          booking.payment.lastSuccessfulRetryAt = new Date();
        }
        
        await booking.save();

        // Send notification to provider
        await Notification.createNotification({
          userId: booking.providerId,
          type: 'payment_received',
          title: 'Payment Received!',
          message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your ${booking.serviceType} service`,
          relatedId: booking._id,
          relatedType: 'booking',
          priority: 'high'
        });

        console.log('✅ Paystack payment verified and booking updated');
      }

      // ✅ REDIRECT TO /customer AFTER SUCCESSFUL PAYMENT
      res.redirect(`${process.env.FRONTEND_URL}/customer?payment=success&bookingId=${booking?._id}&reference=${paymentReference}`);
    } else {
      console.log('❌ Paystack payment verification failed');
      res.redirect(`${process.env.FRONTEND_URL}/customer/payment-status?status=failed&error=verification_failed&reference=${paymentReference}`);
    }

  } catch (error) {
    console.error('Paystack verification error:', error);
    res.redirect(`${process.env.FRONTEND_URL}/customer/payment-status?status=failed&error=verification_error`);
  }
});






const handlePaymentSuccess = async (bookingId) => {
  console.log('💰 Processing payment for booking:', bookingId);
  
  try {
    const token = localStorage.getItem('authToken');
    if (!token) {
      throw new Error('Authentication required');
    }

    // Get user data to determine country
    const userData = JSON.parse(localStorage.getItem('userData') || '{}');
    const userCountry = userData.country || 'NG';

    // Get booking to determine provider country (you might need to fetch this)
    const bookingResponse = await fetch(`${API_BASE_URL}/api/bookings/${bookingId}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    
    const bookingData = await bookingResponse.json();
    const providerCountry = bookingData.data?.providerCountry || 'NG';

    // Show payment modal with country information
    setSelectedBookingForPayment(bookingData.data);
    setShowPaymentModal(true);

  } catch (error) {
    console.error('❌ Payment initialization error:', error);
    alert('Failed to initialize payment: ' + error.message);
  }
};


app.post('/api/payments/create-payment-intent', authenticateToken, async (req, res) => {
  try {
    const { amount, currency = 'usd', bookingId, customerId } = req.body;

    if (!amount || !bookingId) {
      return res.status(400).json({
        success: false,
        message: 'Amount and booking ID are required'
      });
    }

    // Validate booking exists and user has permission
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to pay for this booking'
      });
    }

    // Create Stripe payment intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100), // Convert to cents
      currency: currency.toLowerCase(),
      metadata: {
        bookingId: bookingId,
        customerId: req.user.id,
        paymentType: 'escrow'
      },
      automatic_payment_methods: {
        enabled: true,
      },
    });

    // Update booking with payment info
    booking.payment = {
      processor: 'stripe',
      paymentIntentId: paymentIntent.id,
      amount: amount,
      currency: currency.toUpperCase(),
      status: 'requires_payment_method'
    };

    await booking.save();

    res.json({
      success: true,
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    });

  } catch (error) {
    console.error('Create payment intent error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment intent'
    });
  }
});

app.post('/api/payments/confirm-stripe-payment', authenticateToken, async (req, res) => {
  try {
    const { paymentIntentId, bookingId } = req.body;

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify payment intent
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status === 'succeeded') {
      // Payment successful - update booking
      booking.payment.status = 'held';
      booking.payment.heldAt = new Date();
      booking.status = 'confirmed';
      
      await booking.save();

      // Send notification to provider
      await Notification.createNotification({
        userId: booking.providerId,
        type: 'payment_received',
        title: 'Payment Received!',
        message: `A customer has made a payment of ${booking.payment.currency}${booking.payment.amount} for your service`,
        relatedId: booking._id,
        relatedType: 'booking',
        priority: 'high'
      });

      res.json({
        success: true,
        message: 'Payment confirmed successfully',
        data: {
          booking: booking,
          paymentStatus: 'held'
        }
      });
    } else {
      res.status(400).json({
        success: false,
        message: `Payment not completed. Status: ${paymentIntent.status}`
      });
    }

  } catch (error) {
    console.error('Confirm payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to confirm payment'
    });
  }
});


app.get('/api/service-requests/:jobId/proposals', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('📨 Fetching proposals for ServiceRequest:', jobId);
    
    // Validate jobId
    if (!jobId || jobId === 'undefined' || !mongoose.Types.ObjectId.isValid(jobId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid job ID is required'
      });
    }

    const serviceRequest = await ServiceRequest.findById(jobId)
      .populate('proposals.providerId', 'name email profileImage rating reviewCount completedJobs')
      .populate('customerId', 'name email');

    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check authorization
    const canView = serviceRequest.customerId._id.toString() === req.user.id || 
                   req.user.userType.includes('provider');
    
    if (!canView) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to view these proposals'
      });
    }

    console.log('✅ Proposals found:', serviceRequest.proposals?.length);

    res.json({
      success: true,
      data: {
        proposals: serviceRequest.proposals || [],
        jobTitle: serviceRequest.serviceType,
        jobStatus: serviceRequest.status,
        isCustomer: serviceRequest.customerId._id.toString() === req.user.id
      }
    });

  } catch (error) {
    console.error('❌ Get proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch proposals',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});



app.post('/api/admin/init-proposals-array/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔄 Initializing proposals array for job:', jobId);
    
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const serviceRequest = await ServiceRequest.findById(jobId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'ServiceRequest not found'
      });
    }

    console.log('🔍 Before initialization:', {
      hasProposals: !!serviceRequest.proposals,
      isArray: Array.isArray(serviceRequest.proposals),
      proposals: serviceRequest.proposals
    });

    // Initialize proposals array if it doesn't exist or isn't an array
    if (!serviceRequest.proposals || !Array.isArray(serviceRequest.proposals)) {
      serviceRequest.proposals = [];
      await serviceRequest.save();
      console.log('✅ Proposals array initialized');
    } else {
      console.log('ℹ️ Proposals array already exists');
    }

    console.log('🔍 After initialization:', {
      hasProposals: !!serviceRequest.proposals,
      isArray: Array.isArray(serviceRequest.proposals),
      proposalsCount: serviceRequest.proposals.length
    });

    res.json({
      success: true,
      message: 'Proposals array initialized',
      data: {
        jobId: jobId,
        proposalsCount: serviceRequest.proposals.length,
        wasInitialized: !serviceRequest.proposals || !Array.isArray(serviceRequest.proposals)
      }
    });

  } catch (error) {
    console.error('❌ Init proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to initialize proposals',
      error: error.message
    });
  }
});

app.post('/api/admin/add-test-proposal/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const { providerId = '6921db643a14cec399ce928a' } = req.body;
    
    console.log('🧪 Adding test proposal to job:', jobId);
    
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const serviceRequest = await ServiceRequest.findById(jobId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'ServiceRequest not found'
      });
    }

    // Ensure proposals array exists
    if (!serviceRequest.proposals || !Array.isArray(serviceRequest.proposals)) {
      serviceRequest.proposals = [];
    }

    // Add test proposal
    const testProposal = {
      providerId: providerId,
      proposalText: 'Test proposal - I can help with this service!',
      proposedAmount: 5000,
      estimatedDuration: '2-3 hours',
      status: 'pending',
      submittedAt: new Date(),
      createdAt: new Date()
    };

    serviceRequest.proposals.push(testProposal);
    await serviceRequest.save();

    console.log('✅ Test proposal added:', testProposal._id);

    res.json({
      success: true,
      message: 'Test proposal added successfully',
      data: {
        jobId: jobId,
        proposalId: testProposal._id,
        proposalsCount: serviceRequest.proposals.length
      }
    });

  } catch (error) {
    console.error('❌ Add test proposal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add test proposal',
      error: error.message
    });
  }
});



app.get('/api/jobs/:jobId/proposals', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('📨 Unified fetching proposals for:', jobId);
    
    // Validate jobId
    if (!jobId || jobId === 'undefined' || !mongoose.Types.ObjectId.isValid(jobId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid job ID is required'
      });
    }

    // Try ServiceRequest first
    let serviceRequest = await ServiceRequest.findById(jobId)
      .populate('proposals.providerId', 'name email profileImage rating reviewCount completedJobs')
      .populate('customerId', 'name email');

    if (serviceRequest) {
      console.log('✅ Found in ServiceRequest, proposals:', serviceRequest.proposals?.length);
      
      // Check if user can view these proposals
      const canView = serviceRequest.customerId._id.toString() === req.user.id || 
                     req.user.userType.includes('provider');
      
      if (!canView) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view these proposals'
        });
      }

      return res.json({
        success: true,
        data: {
          proposals: serviceRequest.proposals || [],
          jobTitle: serviceRequest.serviceType,
          jobStatus: serviceRequest.status,
          isCustomer: serviceRequest.customerId._id.toString() === req.user.id
        }
      });
    }

    // Try Job collection as fallback
    const job = await Job.findById(jobId)
      .populate('applications.providerId', 'name email profileImage rating reviewCount')
      .populate('customerId', 'name email');

    if (job) {
      console.log('✅ Found in Job collection, applications:', job.applications?.length);
      
      const canView = job.customerId._id.toString() === req.user.id || 
                     req.user.userType.includes('provider');
      
      if (!canView) {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to view these applications'
        });
      }

      // Transform applications to proposals format
      const proposals = (job.applications || []).map(app => ({
        _id: app._id,
        providerId: app.providerId,
        proposalText: app.message || app.proposalText || 'No message provided',
        proposedAmount: app.proposedBudget || app.budget,
        estimatedDuration: app.timeline || app.estimatedDuration,
        status: app.status || 'pending',
        submittedAt: app.createdAt || app.submittedAt,
        createdAt: app.createdAt
      }));

      return res.json({
        success: true,
        data: {
          proposals: proposals,
          jobTitle: job.title || job.serviceType,
          jobStatus: job.status,
          isCustomer: job.customerId._id.toString() === req.user.id
        }
      });
    }

    console.log('❌ Job not found in any collection:', jobId);
    return res.status(404).json({
      success: false,
      message: 'Job not found'
    });

  } catch (error) {
    console.error('❌ Unified get proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch proposals',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});



app.post('/api/admin/migrate-jobs-to-service-requests', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    console.log('🔄 Starting job migration from Job to ServiceRequest collection...');

    // Find all jobs that don't have corresponding ServiceRequest
    const allJobs = await Job.find({});
    let migratedCount = 0;
    let errors = [];

    for (const job of allJobs) {
      try {
        // Check if ServiceRequest already exists
        const existingServiceRequest = await ServiceRequest.findById(job._id);
        if (existingServiceRequest) {
          console.log(`ℹ️ ServiceRequest already exists for job: ${job._id}`);
          continue;
        }

        // Create new ServiceRequest from Job data
        const serviceRequest = new ServiceRequest({
          _id: job._id,
          serviceType: job.title || job.serviceType || 'General Service',
          description: job.description || 'No description provided',
          location: job.location || 'Location not specified',
          budget: job.budget || 'Not specified',
          budgetAmount: job.budget ? parseInt(job.budget.replace(/\D/g, '')) || 0 : 0,
          customerId: job.customerId,
          status: job.status || 'pending',
          createdAt: job.createdAt,
          proposals: []
        });

        // Copy applications from Job to proposals in ServiceRequest
        if (job.applications && job.applications.length > 0) {
          serviceRequest.proposals = job.applications.map(app => ({
            providerId: app.providerId,
            proposalText: app.message || 'No message provided',
            proposedAmount: app.proposedBudget,
            estimatedDuration: app.timeline,
            status: app.status || 'pending',
            submittedAt: app.createdAt,
            createdAt: app.createdAt
          }));
        }

        await serviceRequest.save();
        migratedCount++;
        console.log(`✅ Migrated job: ${job._id} with ${serviceRequest.proposals.length} proposals`);

      } catch (error) {
        errors.push({
          jobId: job._id,
          error: error.message
        });
        console.error(`❌ Failed to migrate job: ${job._id}`, error.message);
      }
    }

    console.log(`🎉 Migration completed: ${migratedCount} jobs migrated, ${errors.length} errors`);

    res.json({
      success: true,
      message: `Migrated ${migratedCount} jobs to ServiceRequest collection`,
      data: {
        migratedCount,
        errorCount: errors.length,
        errors: errors
      }
    });

  } catch (error) {
    console.error('❌ Migration error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to migrate jobs',
      error: error.message
    });
  }
});

app.post('/api/admin/sync-proposals/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔄 Syncing proposals for job:', jobId);
    
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Find job in Job collection
    const job = await Job.findById(jobId)
      .populate('applications.providerId');

    if (!job) {
      return res.status(404).json({
        success: false,
        message: 'Job not found in Job collection'
      });
    }

    // Find or create corresponding ServiceRequest
    let serviceRequest = await ServiceRequest.findById(jobId);
    
    if (!serviceRequest) {
      // Create a ServiceRequest from the Job data
      serviceRequest = new ServiceRequest({
        _id: jobId,
        serviceType: job.serviceType || job.title,
        description: job.description,
        location: job.location,
        budget: job.budget,
        customerId: job.customerId,
        status: job.status,
        createdAt: job.createdAt,
        proposals: []
      });
    }

    // Sync applications from Job to proposals in ServiceRequest
    if (job.applications && job.applications.length > 0) {
      serviceRequest.proposals = job.applications.map(app => ({
        providerId: app.providerId._id,
        proposalText: app.message || 'No message provided',
        proposedAmount: app.proposedBudget,
        estimatedDuration: app.timeline,
        status: app.status || 'pending',
        submittedAt: app.createdAt,
        createdAt: app.createdAt
      }));
    }

    await serviceRequest.save();

    console.log('✅ Synced proposals:', serviceRequest.proposals.length);

    res.json({
      success: true,
      message: `Synced ${serviceRequest.proposals.length} proposals from Job to ServiceRequest`,
      data: {
        jobId: jobId,
        proposalsCount: serviceRequest.proposals.length
      }
    });

  } catch (error) {
    console.error('❌ Sync proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to sync proposals'
    });
  }
});

app.get('/api/debug/job-proposals-check/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔍 Checking proposals in both systems for job:', jobId);
    
    // Check ServiceRequest
    const serviceRequest = await ServiceRequest.findById(jobId)
      .populate('proposals.providerId', 'name email');
    
    // Check Job
    const job = await Job.findById(jobId)
      .populate('applications.providerId', 'name email');

    const result = {
      serviceRequest: {
        exists: !!serviceRequest,
        proposalsCount: serviceRequest?.proposals?.length || 0,
        proposals: serviceRequest?.proposals || []
      },
      job: {
        exists: !!job,
        applicationsCount: job?.applications?.length || 0,
        applications: job?.applications || []
      }
    };

    console.log('🔍 Debug result:', result);

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    console.error('❌ Debug check error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check proposals'
    });
  }
});

app.get('/api/debug/job-proposals-detailed/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔍 DETAILED DEBUG: Checking job:', jobId);
    
    // Check ServiceRequest collection
    const serviceRequest = await ServiceRequest.findById(jobId);
    console.log('🔍 ServiceRequest found:', !!serviceRequest);
    if (serviceRequest) {
      console.log('🔍 ServiceRequest data:', {
        id: serviceRequest._id,
        serviceType: serviceRequest.serviceType,
        proposalsCount: serviceRequest.proposals?.length,
        proposals: serviceRequest.proposals
      });
    }

    // Check Job collection
    const job = await Job.findById(jobId);
    console.log('🔍 Job found:', !!job);
    if (job) {
      console.log('🔍 Job data:', {
        id: job._id,
        title: job.title,
        applicationsCount: job.applications?.length,
        applications: job.applications
      });
    }

    // Check if jobId exists in both collections
    const serviceRequestExists = !!serviceRequest;
    const jobExists = !!job;

    res.json({
      success: true,
      data: {
        jobId: jobId,
        collections: {
          serviceRequest: {
            exists: serviceRequestExists,
            data: serviceRequest ? {
              serviceType: serviceRequest.serviceType,
              proposalsCount: serviceRequest.proposals?.length,
              proposals: serviceRequest.proposals
            } : null
          },
          job: {
            exists: jobExists,
            data: job ? {
              title: job.title,
              applicationsCount: job.applications?.length,
              applications: job.applications
            } : null
          }
        },
        summary: {
          jobFoundInServiceRequest: serviceRequestExists,
          jobFoundInJobCollection: jobExists,
          totalProposals: (serviceRequest?.proposals?.length || 0) + (job?.applications?.length || 0)
        }
      }
    });

  } catch (error) {
    console.error('❌ Detailed debug error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to debug job',
      error: error.message
    });
  }
});

app.post('/api/jobs/:jobId/apply', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const {
      proposedBudget,
      timeline,
      message,
      proposedSchedule
    } = req.body;

    console.log('📨 New job application:', {
      jobId,
      providerId: req.user.id,
      proposedBudget,
      timeline
    });

    // Validate jobId
    if (!jobId || !mongoose.Types.ObjectId.isValid(jobId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid job ID is required'
      });
    }

    // Validate user is a provider
    const user = await User.findById(req.user.id);
    if (!user.userType.includes('provider') && user.userType !== 'both') {
      return res.status(403).json({
        success: false,
        message: 'Only providers can submit proposals'
      });
    }

    // Try ServiceRequest first
    let serviceRequest = await ServiceRequest.findById(jobId);
    if (serviceRequest) {
      console.log('✅ Applying to ServiceRequest');
      
      // Check if job is still open
      if (serviceRequest.status !== 'pending') {
        return res.status(400).json({
          success: false,
          message: 'This job is no longer accepting proposals'
        });
      }

      // Check if provider already submitted a proposal
      const existingProposal = serviceRequest.proposals.find(
        proposal => proposal.providerId.toString() === req.user.id
      );

      if (existingProposal) {
        return res.status(400).json({
          success: false,
          message: 'You have already submitted a proposal for this job'
        });
      }

      // Add new proposal
      const newProposal = {
        providerId: req.user.id,
        proposalText: message,
        proposedAmount: proposedBudget ? parseInt(proposedBudget.replace(/\D/g, '')) : 0,
        estimatedDuration: timeline,
        proposedSchedule: proposedSchedule,
        status: 'pending',
        submittedAt: new Date()
      };

      serviceRequest.proposals.push(newProposal);
      await serviceRequest.save();

      // Populate the new proposal for response
      await serviceRequest.populate('proposals.providerId', 'name profileImage rating reviewCount');

      const savedProposal = serviceRequest.proposals[serviceRequest.proposals.length - 1];

      console.log('✅ Proposal submitted to ServiceRequest successfully');

      // Notify customer
      await Notification.createNotification({
        userId: serviceRequest.customerId,
        type: 'new_proposal',
        title: 'New Proposal Received',
        message: `${user.name} has submitted a proposal for your ${serviceRequest.serviceType} job`,
        relatedId: serviceRequest._id,
        relatedType: 'job',
        priority: 'medium'
      });

      return res.json({
        success: true,
        message: 'Proposal submitted successfully',
        data: {
          proposal: savedProposal,
          jobId: serviceRequest._id
        }
      });
    }

    // Try Job collection as fallback
    const job = await Job.findById(jobId);
    if (job) {
      console.log('✅ Applying to Job collection');
      
      if (job.status !== 'pending') {
        return res.status(400).json({
          success: false,
          message: 'This job is no longer accepting applications'
        });
      }

      // Check if already applied
      const existingApplication = job.applications?.find(
        app => app.providerId.toString() === req.user.id
      );

      if (existingApplication) {
        return res.status(400).json({
          success: false,
          message: 'You have already applied for this job'
        });
      }

      // Add application
      const newApplication = {
        providerId: req.user.id,
        message: message,
        proposedBudget: proposedBudget,
        timeline: timeline,
        proposedSchedule: proposedSchedule,
        status: 'pending',
        createdAt: new Date()
      };

      if (!job.applications) {
        job.applications = [];
      }
      job.applications.push(newApplication);
      await job.save();

      console.log('✅ Application submitted to Job collection successfully');

      // Notify customer
      await Notification.createNotification({
        userId: job.customerId,
        type: 'new_application',
        title: 'New Application Received',
        message: `${user.name} has applied for your ${job.title} job`,
        relatedId: job._id,
        relatedType: 'job',
        priority: 'medium'
      });

      return res.json({
        success: true,
        message: 'Application submitted successfully',
        data: {
          application: job.applications[job.applications.length - 1],
          jobId: job._id
        }
      });
    }

    console.log('❌ Job not found in any collection:', jobId);
    return res.status(404).json({
      success: false,
      message: 'Job not found'
    });

  } catch (error) {
    console.error('❌ Proposal submission error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit proposal',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

async function sendProposalNotification(customerEmail, customerName, providerName, serviceType, jobId) {
  try {
    const emailSubject = `New Proposal Received for Your ${serviceType} Job`;
    const emailBody = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>Hello ${customerName},</h2>
        <p>Great news! You've received a new proposal from <strong>${providerName}</strong> for your ${serviceType} job.</p>
        
        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <h3>Next Steps:</h3>
          <ul>
            <li>Review the proposal details</li>
            <li>Check the provider's profile and reviews</li>
            <li>Respond to the proposal within 48 hours</li>
          </ul>
        </div>
        
        <a href="${process.env.CLIENT_URL}/jobs/${jobId}/proposals" 
           style="background-color: #007bff; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          View Proposal
        </a>
        
        <p style="margin-top: 30px; color: #666; font-size: 14px;">
          This is an automated notification. Please do not reply to this email.
        </p>
      </div>
    `;

    // Send email using your email service (Nodemailer, SendGrid, etc.)
    // Example with Nodemailer:
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: customerEmail,
      subject: emailSubject,
      html: emailBody
    });

    return true;
  } catch (error) {
    console.error('Error sending proposal notification email:', error);
    throw error;
  }
}



app.post('/api/admin/clear-proposals/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🧹 Clearing proposals for job:', jobId);
    
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    // Clear proposals from ServiceRequest
    const serviceRequest = await ServiceRequest.findById(jobId);
    if (serviceRequest) {
      const previousCount = serviceRequest.proposals?.length || 0;
      serviceRequest.proposals = [];
      await serviceRequest.save();
      console.log(`✅ Cleared ${previousCount} proposals from ServiceRequest`);
    }

    // Clear applications from Job
    const job = await Job.findById(jobId);
    if (job) {
      const previousCount = job.applications?.length || 0;
      job.applications = [];
      await job.save();
      console.log(`✅ Cleared ${previousCount} applications from Job`);
    }

    res.json({
      success: true,
      message: 'Proposals cleared successfully',
      data: {
        jobId: jobId,
        clearedFrom: {
          serviceRequest: !!serviceRequest,
          job: !!job
        }
      }
    });

  } catch (error) {
    console.error('❌ Clear proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to clear proposals',
      error: error.message
    });
  }
});

app.get('/api/debug/current-proposals/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔍 CHECKING CURRENT PROPOSALS FOR:', jobId);
    
    // Check ServiceRequest
    const serviceRequest = await ServiceRequest.findById(jobId)
      .populate('proposals.providerId', 'name email');
    
    // Check Job
    const job = await Job.findById(jobId)
      .populate('applications.providerId', 'name email');

    const currentState = {
      serviceRequest: {
        exists: !!serviceRequest,
        proposals: serviceRequest?.proposals || [],
        proposalsCount: serviceRequest?.proposals?.length || 0,
        proposalIds: serviceRequest?.proposals?.map(p => ({
          id: p._id,
          providerId: p.providerId?._id,
          providerName: p.providerId?.name
        })) || []
      },
      job: {
        exists: !!job,
        applications: job?.applications || [],
        applicationsCount: job?.applications?.length || 0,
        applicationIds: job?.applications?.map(a => ({
          id: a._id,
          providerId: a.providerId?._id,
          providerName: a.providerId?.name
        })) || []
      }
    };

    console.log('📊 CURRENT STATE:', currentState);

    res.json({
      success: true,
      data: currentState
    });

  } catch (error) {
    console.error('❌ Check current proposals error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check current proposals',
      error: error.message
    });
  }
});

app.get('/api/debug/notification-types', authenticateToken, async (req, res) => {
  try {
    // Check Notification model schema to see valid types
    const notificationTypes = [
      'booking_request',
      'booking_confirmed', 
      'booking_cancelled',
      'booking_reminder',
      'payment_received',
      'payment_failed',
      'rating_received',
      'message_received',
      'system_alert',
      'job_update',
      'verification_submitted',
      'verification_status_updated',
      'proposal_accepted'
      // Add any other types from your Notification model
    ];

    res.json({
      success: true,
      data: {
        validTypes: notificationTypes,
        currentModel: 'Check your Notification.js model for the exact enum values'
      }
    });
  } catch (error) {
    console.error('Debug notification types error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get notification types'
    });
  }
});

app.get('/api/debug/verify-proposal/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔍 Verifying proposal for job:', jobId);
    
    // Check ServiceRequest
    const serviceRequest = await ServiceRequest.findById(jobId)
      .populate('proposals.providerId', 'name email')
      .populate('customerId', 'name email');

    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'ServiceRequest not found'
      });
    }

    console.log('🔍 ServiceRequest proposals:', serviceRequest.proposals);

    res.json({
      success: true,
      data: {
        jobId: jobId,
        serviceRequest: {
          _id: serviceRequest._id,
          serviceType: serviceRequest.serviceType,
          customer: serviceRequest.customerId,
          proposalsCount: serviceRequest.proposals?.length || 0,
          proposals: serviceRequest.proposals || []
        },
        summary: `Found ${serviceRequest.proposals?.length || 0} proposals`
      }
    });

  } catch (error) {
    console.error('❌ Verify proposal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify proposal',
      error: error.message
    });
  }
});

app.get('/api/debug/service-request-proposals/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    
    console.log('🔍 DETAILED DEBUG: Checking ServiceRequest proposals for:', jobId);
    
    const serviceRequest = await ServiceRequest.findById(jobId)
      .populate('proposals.providerId', 'name email profileImage');

    if (!serviceRequest) {
      console.log('❌ ServiceRequest not found');
      return res.json({
        success: false,
        message: 'ServiceRequest not found'
      });
    }

    console.log('🔍 ServiceRequest details:', {
      _id: serviceRequest._id,
      serviceType: serviceRequest.serviceType,
      proposalsCount: serviceRequest.proposals?.length,
      proposalsRaw: serviceRequest.proposals
    });

    // Check if proposals array exists and has data
    if (serviceRequest.proposals && serviceRequest.proposals.length > 0) {
      console.log('✅ Proposals found, checking each one:');
      serviceRequest.proposals.forEach((proposal, index) => {
        console.log(`   Proposal ${index + 1}:`, {
          _id: proposal._id,
          providerId: proposal.providerId?._id,
          providerName: proposal.providerId?.name,
          proposalText: proposal.proposalText?.substring(0, 50) + '...',
          status: proposal.status
        });
      });
    } else {
      console.log('❌ No proposals array or empty array');
    }

    res.json({
      success: true,
      data: {
        serviceRequest: {
          _id: serviceRequest._id,
          serviceType: serviceRequest.serviceType,
          proposalsCount: serviceRequest.proposals?.length || 0,
          proposals: serviceRequest.proposals || []
        }
      }
    });

  } catch (error) {
    console.error('❌ Debug error:', error);
    res.status(500).json({
      success: false,
      message: 'Debug failed',
      error: error.message
    });
  }
});


//NIN
app.post('/api/auth/verify-identity', authenticateToken, upload.single('nepaBill'), async (req, res) => {
  try {
    const { nin } = req.body;
    const nepaBill = req.file;

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

    // Handle file upload for NEPA bill to GCS
    let nepaBillUrl = '';
    if (nepaBill) {
      console.log('Uploading NEPA bill to Google Cloud Storage...');
      const uploadResult = await uploadToGCS(nepaBill, 'verification');
      nepaBillUrl = uploadResult.url;
      console.log('✅ NEPA bill uploaded to GCS:', nepaBillUrl);
    }

    // Update user verification data
    const user = await User.findById(req.user.id);
    user.identityVerification = {
      nin: cleanNIN,
      nepaBillUrl: nepaBillUrl,
      isNinVerified: false,
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

app.get('/api/verification/status', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select('identityVerification hasSubmittedVerification verificationStatus userType');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const verificationData = user.identityVerification || {};
    
    // Determine verification status
    let verificationStatus = 'not_submitted';
    let isVerified = false;
    
    if (user.hasSubmittedVerification) {
      if (verificationData.verificationStatus === 'approved') {
        verificationStatus = 'verified';
        isVerified = true;
      } else if (verificationData.verificationStatus === 'rejected') {
        verificationStatus = 'rejected';
      } else if (verificationData.verificationStatus === 'pending') {
        verificationStatus = 'pending_review';
      } else {
        verificationStatus = 'submitted';
      }
    }

    res.json({
      success: true,
      data: {
        hasSubmittedVerification: user.hasSubmittedVerification,
        verificationStatus: verificationStatus,
        isVerified: isVerified,
        details: {
          ninVerified: verificationData.isNinVerified || false,
          nepaVerified: verificationData.isNepaVerified || false,
          selfieVerified: verificationData.isSelfieVerified || false,
          submittedAt: verificationData.verificationSubmittedAt,
          reviewedAt: verificationData.verificationReviewedAt,
          notes: verificationData.verificationNotes || ''
        }
      }
    });

  } catch (error) {
    console.error('Check verification status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check verification status'
    });
  }
});


// Save verification information to Google Storage and update user record
app.post('/api/verification/submit', authenticateToken, upload.fields([
  { name: 'selfie', maxCount: 1 },
  { name: 'nepaBill', maxCount: 1 }
]), async (req, res) => {
  try {
    console.log('🔐 Verification submit endpoint hit');
    
    const { nin, consent } = req.body;
    const files = req.files;
    
    console.log('📋 Received data:', {
      hasNin: !!nin,
      hasConsent: !!consent,
      hasSelfie: !!(files?.selfie?.[0]),
      hasNepaBill: !!(files?.nepaBill?.[0])
    });

    // Validate required fields
    if (!nin || !consent) {
      console.log('❌ Missing required fields:', { nin: !!nin, consent: !!consent });
      return res.status(400).json({
        success: false,
        message: 'NIN and consent are required'
      });
    }

    if (!files?.selfie?.[0]) {
      console.log('❌ No selfie file provided');
      return res.status(400).json({
        success: false,
        message: 'Selfie photo is required'
      });
    }

    // Validate NIN format
    const cleanNIN = nin.replace(/\D/g, '');
    if (cleanNIN.length !== 11) {
      console.log('❌ Invalid NIN length:', cleanNIN.length);
      return res.status(400).json({
        success: false,
        message: 'NIN must be exactly 11 digits'
      });
    }

    const userId = req.user.id;
    const user = await User.findById(userId);

    if (!user) {
      console.log('❌ User not found:', userId);
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Upload files to Google Cloud Storage with enhanced error handling
    let selfieUrl = '';
    let nepaBillUrl = '';

    try {
      console.log('📤 Uploading selfie to Google Cloud Storage...');
      const selfieFile = files.selfie[0];
      const selfieUploadResult = await uploadToGCS(selfieFile, 'verification/selfies');
      selfieUrl = selfieUploadResult.url;
      console.log('✅ Selfie uploaded to GCS:', selfieUrl);
    } catch (uploadError) {
      console.error('❌ Selfie upload failed:', uploadError);
      return res.status(500).json({
        success: false,
        message: 'Failed to upload selfie photo to cloud storage'
      });
    }

    if (files?.nepaBill?.[0]) {
      try {
        console.log('📤 Uploading utility bill to Google Cloud Storage...');
        const nepaBillFile = files.nepaBill[0];
        const nepaBillUploadResult = await uploadToGCS(nepaBillFile, 'verification/utility-bills');
        nepaBillUrl = nepaBillUploadResult.url;
        console.log('✅ Utility bill uploaded to GCS:', nepaBillUrl);
      } catch (uploadError) {
        console.error('❌ Utility bill upload failed:', uploadError);
        // Don't fail the entire verification if utility bill upload fails
        console.log('⚠️ Continuing without utility bill...');
      }
    }

    // Update user verification data
    user.identityVerification = {
      nin: cleanNIN,
      selfieUrl: selfieUrl,
      nepaBillUrl: nepaBillUrl || '',
      isNinVerified: false,
      isSelfieVerified: false,
      isNepaVerified: false,
      verificationStatus: 'pending',
      verificationSubmittedAt: new Date(),
      consentGiven: consent === 'true' || consent === true,
      lastVerifiedAt: null,
      verificationNotes: ''
    };

    user.hasSubmittedVerification = true;
    await user.save();

    console.log('✅ Verification submitted successfully for user:', userId);

    // Send notification to admin for review
    try {
      await Notification.createNotification({
        userId: userId,
        type: 'verification_submitted',
        title: 'Verification Submitted',
        message: 'Your identity verification has been submitted and is under review.',
        relatedId: user._id,
        relatedType: 'verification',
        priority: 'medium'
      });
    } catch (notificationError) {
      console.error('Notification error:', notificationError);
      // Continue even if notification fails
    }

    res.json({
      success: true,
      message: 'Verification information submitted successfully. Your documents will be reviewed by our team.',
      data: {
        verificationId: user.identityVerification._id,
        submittedAt: user.identityVerification.verificationSubmittedAt,
        documentsSubmitted: {
          nin: true,
          selfie: true,
          utilityBill: !!files?.nepaBill?.[0]
        },
        estimatedReviewTime: '24-48 hours'
      }
    });

  } catch (error) {
    console.error('❌ Submit verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit verification information',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


// Get all verification requests (Admin only)
app.get('/api/admin/verification-requests', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin OR has the specific email
    const isAdmin = req.user.userType === 'admin' || req.user.email === 'petervj2019@gmail.com';
    
    if (!isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const { status } = req.query;
    
    let query = { 
      'identityVerification.verificationStatus': { $exists: true },
      hasSubmittedVerification: true 
    };

    if (status && status !== 'all') {
      if (status === 'pending') {
        query['identityVerification.verificationStatus'] = 'pending';
      } else if (status === 'approved') {
        query['identityVerification.verificationStatus'] = 'approved';
      } else if (status === 'rejected') {
        query['identityVerification.verificationStatus'] = 'rejected';
      }
    }

    const users = await User.find(query)
      .select('name email phoneNumber userType createdAt identityVerification')
      .sort({ 'identityVerification.verificationSubmittedAt': -1 });

    const verificationRequests = users.map(user => ({
      _id: user._id.toString(),
      userId: user._id.toString(),
      user: {
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        userType: user.userType,
        createdAt: user.createdAt
      },
      verificationData: user.identityVerification
    }));

    res.json({
      success: true,
      data: verificationRequests
    });

  } catch (error) {
    console.error('Get verification requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch verification requests'
    });
  }
});



// Approve/Reject verification (Admin only)
app.post('/api/admin/verify-provider', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin OR has the specific email
    const isAdmin = req.user.userType === 'admin' || req.user.email === 'petervj2019@gmail.com';
    
    if (!isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const { userId, action, notes } = req.body;

    if (!userId || !action) {
      return res.status(400).json({
        success: false,
        message: 'User ID and action are required'
      });
    }

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
        message: 'User has not submitted verification documents'
      });
    }

    // Update verification status
    if (action === 'approve') {
      user.identityVerification.verificationStatus = 'approved';
      user.identityVerification.isNinVerified = true;
      user.identityVerification.isSelfieVerified = true;
      user.identityVerification.isNepaVerified = !!user.identityVerification.nepaBillUrl;
      user.identityVerification.verificationReviewedAt = new Date();
      user.identityVerification.verificationNotes = notes || 'Approved by admin';
    } else if (action === 'reject') {
      user.identityVerification.verificationStatus = 'rejected';
      user.identityVerification.verificationReviewedAt = new Date();
      user.identityVerification.verificationNotes = notes || 'Rejected by admin';
    }

    await user.save();

    // Send notification to provider (if you have notification system)
    try {
      await Notification.createNotification({
        userId: userId,
        type: 'verification_status_updated',
        title: `Verification ${action === 'approve' ? 'Approved' : 'Rejected'}`,
        message: `Your identity verification has been ${action === 'approve' ? 'approved' : 'rejected'}. ${notes ? `Notes: ${notes}` : ''}`,
        relatedId: user._id,
        relatedType: 'verification',
        priority: 'high'
      });
    } catch (notificationError) {
      console.error('Notification error:', notificationError);
      // Continue even if notification fails
    }

    res.json({
      success: true,
      message: `Verification ${action}ed successfully`,
      data: {
        userId: userId,
        verificationStatus: user.identityVerification.verificationStatus,
        reviewedAt: user.identityVerification.verificationReviewedAt
      }
    });

  } catch (error) {
    console.error('Verify provider error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update verification status'
    });
  }
});



// Save verification information to Google Storage and update user record
// app.post('/api/verification/submit', authenticateToken, upload.fields([
//   { name: 'selfie', maxCount: 1 },
//   { name: 'nepaBill', maxCount: 1 }
// ]), async (req, res) => {
//   try {
//     const { nin, consent } = req.body;
//     const files = req.files;
    
//     const selfieFile = files?.selfie?.[0];
//     const nepaBillFile = files?.nepaBill?.[0];

//     // Validate required fields
//     if (!nin || !consent) {
//       return res.status(400).json({
//         success: false,
//         message: 'NIN and consent are required'
//       });
//     }

//     if (!selfieFile) {
//       return res.status(400).json({
//         success: false,
//         message: 'Selfie photo is required'
//       });
//     }

//     // Validate NIN format
//     const cleanNIN = nin.replace(/\D/g, '');
//     if (cleanNIN.length !== 11) {
//       return res.status(400).json({
//         success: false,
//         message: 'NIN must be exactly 11 digits'
//       });
//     }

//     const userId = req.user.id;
//     const user = await User.findById(userId);

//     if (!user) {
//       return res.status(404).json({
//         success: false,
//         message: 'User not found'
//       });
//     }

//     // Upload files to Google Cloud Storage
//     let selfieUrl = '';
//     let nepaBillUrl = '';

//     try {
//       console.log('📤 Uploading selfie to Google Cloud Storage...');
//       const selfieUploadResult = await uploadToGCS(selfieFile, 'verification/selfies');
//       selfieUrl = selfieUploadResult.url;
//       console.log('✅ Selfie uploaded to GCS:', selfieUrl);
//     } catch (uploadError) {
//       console.error('❌ Selfie upload failed:', uploadError);
//       return res.status(500).json({
//         success: false,
//         message: 'Failed to upload selfie photo'
//       });
//     }

//     if (nepaBillFile) {
//       try {
//         console.log('📤 Uploading utility bill to Google Cloud Storage...');
//         const nepaBillUploadResult = await uploadToGCS(nepaBillFile, 'verification/utility-bills');
//         nepaBillUrl = nepaBillUploadResult.url;
//         console.log('✅ Utility bill uploaded to GCS:', nepaBillUrl);
//       } catch (uploadError) {
//         console.error('❌ Utility bill upload failed:', uploadError);
//         // Don't fail the entire verification if utility bill upload fails
//         console.log('⚠️ Continuing without utility bill...');
//       }
//     }

//     // Update user verification data
//     user.identityVerification = {
//       nin: cleanNIN,
//       selfieUrl: selfieUrl,
//       nepaBillUrl: nepaBillUrl || '',
//       isNinVerified: false, // Will be set to true after manual/admin verification
//       isSelfieVerified: false,
//       isNepaVerified: false,
//       verificationStatus: 'pending',
//       verificationSubmittedAt: new Date(),
//       consentGiven: consent === 'true',
//       lastVerifiedAt: null,
//       verificationNotes: ''
//     };

//     user.hasSubmittedVerification = true;
//     await user.save();

//     // In a real implementation, you might want to:
//     // 1. Trigger an admin notification for review
//     // 2. Integrate with external verification services
//     // 3. Send confirmation email to user

//     console.log('✅ Verification submitted for user:', userId);

//     res.json({
//       success: true,
//       message: 'Verification information submitted successfully. Your documents will be reviewed by our team.',
//       data: {
//         verificationId: user.identityVerification._id,
//         submittedAt: user.identityVerification.verificationSubmittedAt,
//         documentsSubmitted: {
//           nin: true,
//           selfie: true,
//           utilityBill: !!nepaBillFile
//         },
//         estimatedReviewTime: '24-48 hours'
//       }
//     });

//   } catch (error) {
//     console.error('Submit verification error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Failed to submit verification information',
//       error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
//     });
//   }
// });

app.patch('/api/admin/verification/:userId', authenticateToken, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.userType !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Admin access required'
      });
    }

    const { userId } = req.params;
    const { status, notes, ninVerified, selfieVerified, nepaVerified } = req.body;

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
        message: 'User has not submitted verification documents'
      });
    }

    // Update verification status
    user.identityVerification.verificationStatus = status;
    user.identityVerification.verificationReviewedAt = new Date();
    user.identityVerification.verificationNotes = notes || '';
    
    if (ninVerified !== undefined) {
      user.identityVerification.isNinVerified = ninVerified;
    }
    
    if (selfieVerified !== undefined) {
      user.identityVerification.isSelfieVerified = selfieVerified;
    }
    
    if (nepaVerified !== undefined) {
      user.identityVerification.isNepaVerified = nepaVerified;
    }

    await user.save();

    // Send notification to user about status change
    await Notification.createNotification({
      userId: userId,
      type: 'verification_status_updated',
      title: 'Verification Status Updated',
      message: `Your identity verification status has been updated to: ${status}`,
      relatedId: user._id,
      relatedType: 'verification',
      priority: 'medium'
    });

    res.json({
      success: true,
      message: 'Verification status updated successfully',
      data: {
        userId: userId,
        verificationStatus: status,
        reviewedAt: user.identityVerification.verificationReviewedAt
      }
    });

  } catch (error) {
    console.error('Admin verification update error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update verification status'
    });
  }
});

app.use('/api/ratings', (req, res, next) => {
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  }
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});


app.get('/api/providers/:id/rating', async (req, res) => {
  try {
    const providerId = req.params.id;
    
    const ratingStats = await Rating.getProviderAverageRating(providerId);
    
    res.json({
      success: true,
      data: ratingStats
    });
  } catch (error) {
    console.error('Get provider rating error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider rating'
    });
  }
});




app.delete('/api/gallery/:id', authenticateToken, async (req, res) => {
  try {
    const imageId = req.params.id;
    
    // Find the image first to get the file URL
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
    
    // Delete from Google Cloud Storage if it's a GCS URL
    if (image.imageUrl && image.imageUrl.includes('storage.googleapis.com')) {
      try {
        await deleteFromGCS(image.imageUrl);
      } catch (gcsError) {
        console.error('❌ GCS delete error (non-critical):', gcsError);
        // Continue with database deletion even if GCS delete fails
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

// Check and create upload directories with proper permissions
// const setupUploadDirectories = () => {
//   const uploadDirs = [
//     path.join(__dirname, 'uploads', 'gallery'),
//     path.join(__dirname, 'uploads', 'profiles')
//   ];
  
//   uploadDirs.forEach(uploadDir => {
//     try {
//       if (!fs.existsSync(uploadDir)) {
//         fs.mkdirSync(uploadDir, { 
//           recursive: true,
//           mode: 0o755 // Read/write/execute for owner, read/execute for group and others
//         });
//       }
      
//       // Test write permissions
//       const testFile = path.join(uploadDir, 'test.txt');
//       fs.writeFileSync(testFile, 'test');
//       fs.unlinkSync(testFile);
      
//       console.log(`✅ Upload directory is writable: ${uploadDir}`);
//     } catch (error) {
//       console.error(`❌ Upload directory error for ${uploadDir}:`, error);
//       console.error('Please check directory permissions for:', uploadDir);
//     }
//   });
// };

// Initialize upload directories
// setupUploadDirectories();

// Connect to MongoDB
const connectDB = async () => {
  try {
    console.log('🔗 Attempting MongoDB connection...');
    
    // Validate MONGODB_URI format
    const MONGODB_URI = process.env.MONGODB_URI;
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is not set');
    }
    
    // Check if URI starts with valid protocol
    if (!MONGODB_URI.startsWith('mongodb://') && !MONGODB_URI.startsWith('mongodb+srv://')) {
      throw new Error(`Invalid MongoDB URI format. Expected "mongodb://" or "mongodb+srv://", got: ${MONGODB_URI.substring(0, 20)}...`);
    }
    
    try {
    const MONGODB_URI = process.env.MONGODB_URI;
    
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined');
    }

    const conn = await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('Database connection error:', error.message);
    process.exit(1);
  }

    console.log('✅ MongoDB URI format is valid');
    
    const mongooseOptions = {
      maxPoolSize: 10,
      minPoolSize: 5,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      bufferCommands: true,
      retryWrites: true,
      retryReads: true,
      authSource: 'admin'
    };

    console.log('📋 MongoDB connection options:', mongooseOptions);

    const conn = await mongoose.connect(MONGODB_URI, mongooseOptions);
    
    console.log('✅ MongoDB connected successfully');
    console.log(`📊 Database: ${conn.connection.name}`);
    console.log(`🌐 Host: ${conn.connection.host}`);

  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    
    // More specific error handling
    if (error.message.includes('Invalid scheme')) {
      console.error('🔧 SOLUTION: Check your MONGODB_URI in Render.com environment variables');
      console.error('   - It should start with: mongodb+srv://... or mongodb://...');
      console.error('   - Current value starts with:', process.env.MONGODB_URI?.substring(0, 20) + '...');
    }
    
    // In production, try to reconnect but with better error info
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
      'https://backendhomeheroes.onrender.com',
      'http://localhost:5173',
    ]
  : [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://127.0.0.1:5173',
      'http://localhost:4173',
      'http://localhost:5174',
      'http://localhost:5175',
      'http://localhost:3001'
    ];


app.use('/api/providers/:id/favorite', (req, res, next) => {
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  }
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.NODE_ENV === 'production' 
      ? [
          'https://homeheroes.help',
          'https://www.homeheroes.help',
          'https://backendhomeheroes.onrender.com'
        ]
      : [
          'http://localhost:5173',
          'http://localhost:5174',
          'http://localhost:3000',
          'http://localhost:5175'
        ];
    
    if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('localhost')) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
}));

app.options('*', cors());



app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));


app.get('/api/debug/cors-test', (req, res) => {
  res.json({
    success: true,
    message: 'CORS is working!',
    allowedOrigins: [
      'https://homeheroes.help',
      'https://www.homeheroes.help',
      'http://localhost:5173',
      'http://localhost:5174'
    ],
    requestOrigin: req.headers.origin,
    timestamp: new Date().toISOString()
  });
});


app.set('trust proxy', 1); // Trust first proxy


app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV 
  });
});

app.use('/api/ratings', express.json({ limit: '10mb' }));
app.use('/api/ratings', express.urlencoded({ extended: true }));

app.use('/api/ratings', express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
    console.log('📦 Ratings Raw Body:', buf.toString('utf8').substring(0, 200));
  }
}));

app.use('/api/ratings', express.urlencoded({ 
  extended: true, 
  limit: '10mb' 
}));

// Debug middleware to log ALL ratings requests
app.use('/api/ratings', (req, res, next) => {
  console.log('🎯 Ratings Route Hit:', {
    method: req.method,
    url: req.originalUrl,
    path: req.path,
    body: req.body,
    contentType: req.headers['content-type'],
    hasBody: !!req.body,
    bodyKeys: req.body ? Object.keys(req.body) : 'No body'
  });
  next();
});

app.use('/api/ratings', ratingRoutes);


// app.use(cors({
//   origin: function (origin, callback) {
//     // Allow requests with no origin (like mobile apps or curl requests)
//     if (!origin) return callback(null, true);
    
//     if (allowedOrigins.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       console.log('CORS blocked origin:', origin);
//       callback(new Error('Not allowed by CORS'), false);
//     }
//   },
//   credentials: true,
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
//   allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
// }));

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

app.get('/api/debug/ratings', async (req, res) => {
  try {
    const ratings = await Rating.find({})
      .populate('providerId', 'name email')
      .populate('customerId', 'name email')
      .populate('bookingId', 'serviceType status');
    
    res.json({
      success: true,
      data: {
        totalRatings: ratings.length,
        ratings: ratings.map(r => ({
          id: r._id,
          bookingId: r.bookingId?._id,
          serviceType: r.bookingId?.serviceType,
          provider: r.providerId?.name,
          customer: r.customerId?.name,
          providerRating: r.providerRating,
          customerRating: r.customerRating,
          customerRated: r.customerRated,
          providerRated: r.providerRated
        }))
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
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
    'Pragma',
    'x-access-token'

  ]
}));

// Handle preflight requests
app.options('*', cors());

// Explicitly handle preflight requests for all routes
app.options('*', cors());


// Handle preflight requests
app.options('*', cors());
// Middleware

console.log('🔧 Checking route registration...');
console.log('Auth routes:', authRoutes ? 'Loaded' : 'NOT LOADED');
console.log('All routes registered successfully');

// Add this specific middleware for ratings routes
app.use('/api/ratings', express.json({ limit: '10mb' }));
app.use('/api/ratings', express.urlencoded({ extended: true }));

// Debug middleware to log request bodies
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, Cache-Control, Pragma');
  }
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});



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


app.use((req, res, next) => {
  console.log('🔍 Request:', req.method, req.url);
  next();
});

console.log('🔧 DEBUG: Starting route registration...');

try {
  console.log('🔧 DEBUG: Importing auth routes...');
  const authRoutes = await import('./routes/auth.routes.js');
  console.log('✅ DEBUG: Auth routes imported successfully');
} catch (error) {
  console.error('❌ DEBUG: Auth routes import failed:', error);
}

app.use('/api/auth', authRoutes);
app.use('/api/verification', verificationRoutes);
app.use('/api/jobs', jobRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/ratings', ratingRoutes);
app.use('/api/providers', providerRoutes);
app.use(cookieParser());

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt received:', {
      email: req.body.email,
      userType: req.body.userType,
      timestamp: new Date().toISOString()
    });

    const { email, password, userType } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email address before logging in',
        requiresVerification: true,
        email: user.email
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email, 
        userType: userType || user.userType,
        isEmailVerified: user.isEmailVerified
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Determine redirect path
    let redirectTo = '/dashboard';
    const finalUserType = userType || user.userType;
    if (finalUserType === 'provider' || user.userType === 'both') {
      redirectTo = '/provider/dashboard';
    } else {
      redirectTo = '/customer/dashboard';
    }

    console.log('✅ Login successful for:', user.email);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          userType: finalUserType,
          actualUserType: user.userType,
          country: user.country,
          isEmailVerified: user.isEmailVerified
        },
        token,
        redirectTo,
        canSwitchRoles: user.userType === 'both'
      }
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/auth/login', (req, res) => {
  res.json({
    success: true,
    message: 'Login endpoint is working! Use POST to login.',
    method: 'GET'
  });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('📝 Login request body:', req.body);
    
    // Simple response to confirm it's working
    res.json({
      success: true,
      message: 'Login endpoint is working!',
      received: req.body
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
});

app.post('/api/auth/login', (req, res) => {
  res.json({
    success: true,
    message: 'POST login endpoint is working!',
    method: 'POST',
    bodyReceived: req.body
  });
});

// Serve static files for uploaded images
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use((req, res, next) => {
  console.log('🔍 Incoming Request:', {
    method: req.method,
    url: req.url,
    path: req.path,
    originalUrl: req.originalUrl,
    origin: req.headers.origin,
    timestamp: new Date().toISOString()
  });
  next();
});

console.log('🔧 Registering routes...');


app.use('/api/auth', authRoutes);
console.log('✅ Auth routes registered at /api/auth');

app.use('/api/verification', verificationRoutes);
console.log('✅ Verification routes registered');

app.use('/api/jobs', jobRoutes);
console.log('✅ Job routes registered');
app.post('/api/test-login', (req, res) => {
  console.log('✅ Test login route hit via POST');
  res.json({
    success: true,
    message: 'Test login route is working!',
    method: 'POST'
  });
});

app.get('/api/test-login', (req, res) => {
  console.log('✅ Test login route hit via GET');
  res.json({
    success: true,
    message: 'Test login route is working!',
    method: 'GET'
  });
});
app.get('/api/debug/config', (req, res) => {
  res.json({
    environment: process.env.NODE_ENV,
    nodeEnv: process.env.NODE_ENV,
    port: process.env.PORT,
    frontendUrl: process.env.FRONTEND_URL,
    emailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
    database: process.env.MONGODB_URI ? 'Configured' : 'Not configured',
    jwtSecret: process.env.JWT_SECRET ? 'Set' : 'Not set',
    timestamp: new Date().toISOString()
  });
});


app.get('/api/debug/db-test', async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    const dbName = mongoose.connection.db.databaseName;
    
    res.json({
      success: true,
      data: {
        database: dbName,
        userCount: userCount,
        connection: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        connectionString: process.env.MONGODB_URI ? process.env.MONGODB_URI.substring(0, 50) + '...' : 'Not set'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

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

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
    
    try {
      const user = await User.findById(decoded.id).select('-password');
      if (!user) {
        console.error('User not found for ID:', decoded.id);
        return res.status(403).json({
          success: false,
          message: 'User not found'
        });
      }
      
      req.user = {
        id: user._id.toString(),
        userType: user.userType,
        email: user.email,
        name: user.name
      };
      
      next();
    } catch (error) {
      console.error('Error verifying user:', error);
      return res.status(500).json({
        success: false,
        message: 'Error verifying user'
      });
    }
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
app.get('/api/debug/database-info', async (req, res) => {
  try {
    const db = mongoose.connection.db;
    const dbName = db.databaseName;
    const collections = await db.listCollections().toArray();
    const userCount = await User.countDocuments();
    
    res.json({
      success: true,
      data: {
        database: dbName,
        userCount: userCount,
        collections: collections.map(c => c.name),
        connectionString: process.env.MONGODB_URI ? 
          process.env.MONGODB_URI.substring(0, 60) + '...' : 'Not set'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


app.get('/api/debug/check-user/:email', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email.toLowerCase() });
    
    if (!user) {
      return res.json({
        success: false,
        message: 'User not found in database'
      });
    }
    
    res.json({
      success: true,
      data: {
        id: user._id,
        email: user.email,
        name: user.name,
        userType: user.userType,
        isEmailVerified: user.isEmailVerified,
        isActive: user.isActive,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
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
    const providerId = req.params.id;
    
    console.log('👤 Fetching provider profile:', providerId);

    const provider = await User.findById(providerId)
      .select('name email services hourlyRate averageRating city state country profileImage isAvailableNow experience phoneNumber address reviewCount completedJobs isVerified isTopRated responseTime createdAt')
      .lean();

    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    // Calculate REAL completed jobs from bookings
    const completedJobsCount = await Booking.countDocuments({
      providerId: providerId,
      status: 'completed'
    });

    console.log('📊 Completed jobs count:', completedJobsCount);

    // Calculate REAL rating stats
    const ratingStats = await Rating.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          customerRated: true,
          providerRating: { $exists: true, $ne: null, $gte: 1, $lte: 5 }
        }
      },
      {
        $group: {
          _id: '$providerId',
          averageRating: { $avg: '$providerRating' },
          totalRatings: { $sum: 1 }
        }
      }
    ]);

    console.log('⭐ Rating stats:', ratingStats);

    const stats = ratingStats.length > 0 ? ratingStats[0] : {
      averageRating: 0,
      totalRatings: 0
    };

    // Get gallery count
    const galleryCount = await Gallery.countDocuments({ userId: providerId });

    // Format the response with REAL data
    const providerProfile = {
      ...provider,
      completedJobs: completedJobsCount, // Use REAL count from bookings
      averageRating: Math.round(stats.averageRating * 10) / 10 || 0,
      reviewCount: stats.totalRatings || 0,
      isAvailableNow: provider.isAvailableNow || false,
      isVerified: provider.isVerified || false,
      isTopRated: provider.isTopRated || false,
      responseTime: provider.responseTime || 'within 1 hour',
      joinedDate: provider.createdAt ? new Date(provider.createdAt).toLocaleDateString() : 'Recently',
      galleryCount: galleryCount
    };

    console.log('✅ Final provider profile:', {
      name: providerProfile.name,
      completedJobs: providerProfile.completedJobs,
      averageRating: providerProfile.averageRating,
      reviewCount: providerProfile.reviewCount,
      galleryCount: providerProfile.galleryCount
    });

    res.json({
      success: true,
      data: providerProfile
    });
  } catch (error) {
    console.error('❌ Get provider profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider profile'
    });
  }
});



app.get('/api/providers/:id/gallery', async (req, res) => {
  try {
    const providerId = req.params.id;
    const { page = 1, limit = 100 } = req.query;

    console.log('🖼️ Fetching gallery for provider:', providerId);

    // Try multiple gallery endpoints
    let galleryData = null;
    
    // First try the direct user-based gallery
    try {
      const gallery = await Gallery.find({ userId: providerId })
        .sort({ createdAt: -1 })
        .limit(parseInt(limit))
        .populate('userId', 'name profileImage')
        .lean();
      
      if (gallery && gallery.length > 0) {
        galleryData = gallery;
        console.log('✅ Found gallery via userId:', galleryData.length);
      }
    } catch (error) {
      console.log('❌ Gallery fetch via userId failed:', error.message);
    }

    // If no gallery found, try other endpoints
    if (!galleryData || galleryData.length === 0) {
      console.log('🔄 Trying alternative gallery endpoints...');
      
      // Try general gallery endpoint
      try {
        const response = await Gallery.find({})
          .sort({ createdAt: -1 })
          .limit(parseInt(limit))
          .populate('userId', 'name profileImage')
          .lean();
        
        if (response && response.length > 0) {
          galleryData = response;
          console.log('✅ Found gallery via general query:', galleryData.length);
        }
      } catch (error) {
        console.log('❌ General gallery fetch failed:', error.message);
      }
    }

    const galleryImages = galleryData || [];

    console.log('📸 Final gallery images found:', galleryImages.length);

    // Format images with proper URLs
    const imagesWithFullUrl = galleryImages.map(image => {
      const imageObj = image;
      
      console.log('🔍 Processing image:', {
        _id: imageObj._id,
        imageUrl: imageObj.imageUrl,
        fullImageUrl: imageObj.fullImageUrl
      });

      // Handle image URLs - try multiple approaches
      let finalImageUrl = '';
      
      if (imageObj.fullImageUrl) {
        finalImageUrl = imageObj.fullImageUrl;
      } else if (imageObj.imageUrl) {
        // Handle relative URLs
        if (imageObj.imageUrl.startsWith('/')) {
          finalImageUrl = `${req.protocol}://${req.get('host')}${imageObj.imageUrl}`;
        } else if (imageObj.imageUrl.startsWith('http')) {
          finalImageUrl = imageObj.imageUrl;
        } else {
          finalImageUrl = `${req.protocol}://${req.get('host')}/uploads/gallery/${imageObj.imageUrl}`;
        }
      }

      console.log('🖼️ Final image URL:', finalImageUrl);

      return {
        ...imageObj,
        imageUrl: finalImageUrl,
        fullImageUrl: finalImageUrl
      };
    });

    res.json({
      success: true,
      data: {
        docs: imagesWithFullUrl,
        totalDocs: imagesWithFullUrl.length,
        limit: parseInt(limit),
        totalPages: 1,
        page: 1,
        pagingCounter: 1,
        hasPrevPage: false,
        hasNextPage: false,
        prevPage: null,
        nextPage: null
      }
    });
  } catch (error) {
    console.error('❌ Get provider gallery error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider gallery'
    });
  }
});

app.get('/api/debug/all-ratings', async (req, res) => {
  try {
    const ratings = await Rating.find({})
      .populate('customerId', 'name email')
      .populate('providerId', 'name email')
      .populate('bookingId', 'serviceType customerName providerName')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    console.log('📊 All ratings in database:', ratings.length);

    const formattedRatings = ratings.map(rating => ({
      _id: rating._id,
      providerId: rating.providerId?._id,
      providerName: rating.providerId?.name,
      customerId: rating.customerId?._id,
      customerName: rating.customerId?.name || rating.bookingId?.customerName,
      providerRating: rating.providerRating,
      providerComment: rating.providerComment,
      customerRated: rating.customerRated,
      providerRated: rating.providerRated,
      serviceType: rating.bookingId?.serviceType,
      createdAt: rating.createdAt
    }));

    res.json({
      success: true,
      data: {
        totalRatings: ratings.length,
        ratings: formattedRatings
      }
    });
  } catch (error) {
    console.error('Debug ratings error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug endpoint to check all gallery images
app.get('/api/debug/all-gallery', async (req, res) => {
  try {
    const gallery = await Gallery.find({})
      .populate('userId', 'name email')
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    console.log('🖼️ All gallery images in database:', gallery.length);

    const formattedGallery = gallery.map(image => ({
      _id: image._id,
      userId: image.userId?._id,
      userName: image.userId?.name,
      title: image.title,
      imageUrl: image.imageUrl,
      fullImageUrl: image.fullImageUrl,
      category: image.category,
      createdAt: image.createdAt
    }));

    res.json({
      success: true,
      data: {
        totalImages: gallery.length,
        images: formattedGallery
      }
    });
  } catch (error) {
    console.error('Debug gallery error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Debug endpoint to test image URL construction
app.get('/api/debug/test-image-urls', async (req, res) => {
  try {
    const testImages = await Gallery.find().limit(5).lean();
    
    const urlTests = testImages.map(image => {
      const originalUrl = image.imageUrl;
      let constructedUrl = '';
      
      if (image.fullImageUrl) {
        constructedUrl = image.fullImageUrl;
      } else if (image.imageUrl) {
        if (image.imageUrl.startsWith('/')) {
          constructedUrl = `${req.protocol}://${req.get('host')}${image.imageUrl}`;
        } else if (image.imageUrl.startsWith('http')) {
          constructedUrl = image.imageUrl;
        } else {
          constructedUrl = `${req.protocol}://${req.get('host')}/uploads/gallery/${image.imageUrl}`;
        }
      }
      
      return {
        _id: image._id,
        title: image.title,
        originalUrl: originalUrl,
        constructedUrl: constructedUrl,
        hasFullImageUrl: !!image.fullImageUrl
      };
    });

    res.json({
      success: true,
      data: urlTests
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
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

async function testBucketAccess() {
  try {
    console.log('🔍 Testing GCS bucket access...');
    console.log('📋 Fixed Configuration:', {
      projectId: 'decent-carving-474920-v0', // Using correct project ID
      bucketName: 'home-heroes-bucket',
      keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
      keyFileExists: fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS || '')
    });

    // Test authentication first
    const [buckets] = await storage.getBuckets();
    console.log('✅ Authentication successful');
    
    // Test specific bucket access
    const [exists] = await bucket.exists();
    if (!exists) {
      console.log('⚠️ Bucket does not exist in project decent-carving-474920-v0');
      console.log('💡 Available buckets:', buckets.map(b => b.name));
      return false;
    }
    
    console.log('✅ Bucket access successful');
    console.log('📁 Bucket name:', bucketName);
    console.log('🏢 Project:', 'decent-carving-474920-v0');
    
    return true;
  } catch (error) {
    console.error('❌ Bucket access failed:', error.message);
    console.log('💡 Immediate fixes:');
    console.log('   1. Make sure bucket "home-heroes-bucket" exists in project "decent-carving-474920-v0"');
    console.log('   2. Grant Storage Admin role to the service account');
    console.log('   3. Check IAM permissions in Google Cloud Console');
    return false;
  }
}

app.get('/api/debug/service-account-details', (req, res) => {
  try {
    const keyFilePath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    const keyFileContent = fs.readFileSync(keyFilePath, 'utf8');
    const serviceAccount = JSON.parse(keyFileContent);
    
    // Check for common issues
    const issues = [];
    
    if (!serviceAccount.private_key) {
      issues.push('❌ Missing private_key');
    } else if (!serviceAccount.private_key.includes('BEGIN PRIVATE KEY')) {
      issues.push('❌ Invalid private_key format');
    }
    
    if (!serviceAccount.client_email) {
      issues.push('❌ Missing client_email');
    }
    
    if (!serviceAccount.project_id) {
      issues.push('❌ Missing project_id');
    }
    
    if (serviceAccount.private_key) {
      const keyLines = serviceAccount.private_key.split('\n');
      if (keyLines.length < 2) {
        issues.push('❌ Private key appears truncated');
      }
    }
    
    const details = {
      project_id: serviceAccount.project_id,
      client_email: serviceAccount.client_email,
      private_key_id: serviceAccount.private_key_id ? 'Present' : 'Missing',
      private_key_length: serviceAccount.private_key ? serviceAccount.private_key.length : 0,
      private_key_format: serviceAccount.private_key ? 
        (serviceAccount.private_key.includes('BEGIN PRIVATE KEY') ? '✅ Correct' : '❌ Incorrect') : 'Missing',
      issues: issues,
      allFieldsPresent: !issues.length
    };
    
    console.log('🔍 Service Account Details:', details);
    
    res.json({
      success: true,
      data: details,
      hasIssues: issues.length > 0,
      issues: issues
    });
    
  } catch (error) {
    console.error('Service account details error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.get('/api/debug/test-auth-only', async (req, res) => {
  try {
    console.log('🔐 Testing GCS authentication only...');
    
    // Create a new storage instance for testing
    const testStorage = new Storage({
      keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
      projectId: 'decent-carving-474920-v0'
    });
    
    // Just try to get project info - this tests authentication only
    const [projectInfo] = await testStorage.getServiceAccount();
    console.log('✅ Authentication successful!');
    console.log('📧 Service Account:', projectInfo.emailAddress);
    
    res.json({
      success: true,
      message: 'Authentication successful',
      serviceAccount: projectInfo.emailAddress
    });
    
  } catch (error) {
    console.error('❌ Authentication failed:', error.message);
    
    // Provide specific suggestions based on the error
    let suggestion = '';
    if (error.message.includes('invalid_grant')) {
      suggestion = 'The service account key may be expired, revoked, or invalid. Generate a new key.';
    } else if (error.message.includes('ENOENT')) {
      suggestion = 'Service account file not found. Check the file path.';
    } else if (error.message.includes('Unexpected token')) {
      suggestion = 'Service account file is corrupted or invalid JSON.';
    }
    
    res.status(500).json({
      success: false,
      message: 'Authentication failed',
      error: error.message,
      suggestion: suggestion
    });
  }
});

app.get('/api/debug/list-all-buckets', async (req, res) => {
  try {
    console.log('📋 Listing all buckets in project...');
    
    const [buckets] = await storage.getBuckets();
    
    const bucketInfo = buckets.map(bucket => ({
      name: bucket.name,
      location: bucket.metadata?.location,
      storageClass: bucket.metadata?.storageClass,
      timeCreated: bucket.metadata?.timeCreated
    }));
    
    console.log('🏪 Available buckets:', bucketInfo);
    
    const targetBucketExists = bucketInfo.some(b => b.name === 'home-heroes-bucket');
    
    res.json({
      success: true,
      data: {
        project: 'decent-carving-474920-v0',
        totalBuckets: bucketInfo.length,
        targetBucket: 'homeheroes-storage-access',
        targetExists: targetBucketExists,
        buckets: bucketInfo
      }
    });
    
  } catch (error) {
    console.error('List buckets error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      suggestion: 'Cannot list buckets - authentication or permissions issue'
    });
  }
});
app.get('/api/debug/gcs-permissions', async (req, res) => {
  try {
    console.log('🔐 Testing GCS permissions...');
    
    // Test 1: List buckets (requires storage.buckets.list)
    const [buckets] = await storage.getBuckets();
    console.log('✅ Can list buckets');
    
    // Test 2: Check bucket exists
    const [bucketExists] = await bucket.exists();
    console.log('✅ Bucket exists:', bucketExists);
    
    // Test 3: Test file upload with a small test file
    const testFileName = `test-${Date.now()}.txt`;
    const testFile = bucket.file(testFileName);
    
    await testFile.save('Test content', {
      metadata: {
        contentType: 'text/plain',
      },
    });
    console.log('✅ Can upload files');
    
    // Test 4: Test file deletion
    await testFile.delete();
    console.log('✅ Can delete files');
    
    // Test 5: Test making files public
    const publicTestFile = bucket.file(`public-test-${Date.now()}.txt`);
    await publicTestFile.save('Public test content');
    await publicTestFile.makePublic();
    console.log('✅ Can make files public');
    await publicTestFile.delete();
    
    res.json({
      success: true,
      message: 'All GCS permissions are working correctly',
      tests: {
        listBuckets: true,
        bucketExists: true,
        uploadFiles: true,
        deleteFiles: true,
        makePublic: true
      }
    });
    
  } catch (error) {
    console.error('❌ GCS permissions test failed:', error);
    res.status(500).json({
      success: false,
      message: 'GCS permissions test failed',
      error: error.message,
      step: 'Check service account has Storage Admin role'
    });
  }
});

testBucketAccess();

// Get provider reviews
app.get('/api/providers/:id/reviews', async (req, res) => {
  try {
    const providerId = req.params.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    console.log('📝 Fetching REAL reviews for provider:', providerId);

    // Get ALL ratings where customer rated the provider
    const ratings = await Rating.find({
      providerId: providerId,
      customerRated: true,
      providerRating: { $exists: true, $ne: null, $gte: 1, $lte: 5 }
    })
    .populate('customerId', 'name profileImage')
    .populate('bookingId', 'serviceType requestedAt')
    .sort({ ratedAt: -1, createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();

    console.log('📊 Raw ratings found:', ratings.length);
    console.log('🔍 Sample rating:', ratings[0]);

    const totalReviews = await Rating.countDocuments({
      providerId: providerId,
      customerRated: true,
      providerRating: { $exists: true, $ne: null, $gte: 1, $lte: 5 }
    });

    // Format reviews properly - handle different data structures
    const formattedReviews = ratings.map(rating => {
      console.log('🔍 Processing rating:', {
        _id: rating._id,
        customerId: rating.customerId,
        providerRating: rating.providerRating,
        providerComment: rating.providerComment,
        bookingId: rating.bookingId
      });

      // Get customer name from multiple possible sources
      const customerName = 
        rating.customerId?.name ||
        rating.bookingId?.customerName ||
        'Customer';

      const customerProfileImage = 
        rating.customerId?.profileImage || null;

      const customerId = 
        rating.customerId?._id || 'unknown';

      // Get service type from multiple possible sources
      const serviceType = 
        rating.bookingId?.serviceType ||
        rating.serviceType ||
        'General Service';

      return {
        _id: rating._id,
        customerId: {
          _id: customerId,
          name: customerName,
          profileImage: customerProfileImage
        },
        rating: rating.providerRating,
        comment: rating.providerComment || '',
        serviceType: serviceType,
        createdAt: rating.ratedAt || rating.createdAt || new Date(),
        helpful: rating.helpful || 0,
        verified: rating.verified || false
      };
    }).filter(review => review.rating && review.rating >= 1); // Only include valid ratings

    console.log('✅ Formatted reviews:', formattedReviews.length);
    console.log('📋 Sample formatted review:', formattedReviews[0]);

    res.json({
      success: true,
      data: {
        reviews: formattedReviews,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(totalReviews / limit),
          totalReviews: totalReviews,
          hasNextPage: page < Math.ceil(totalReviews / limit),
          hasPrevPage: page > 1
        }
      }
    });
  } catch (error) {
    console.error('❌ Get provider reviews error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider reviews'
    });
  }
});

async function updateProviderAverageRating(providerId) {
  try {
    const ratings = await Rating.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          customerRated: true,
          providerRating: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: '$providerId',
          averageRating: { $avg: '$providerRating' },
          totalRatings: { $sum: 1 }
        }
      }
    ]);

    if (ratings.length > 0) {
      const ratingData = ratings[0];
      const averageRating = Math.round(ratingData.averageRating * 10) / 10;
      
      await User.findByIdAndUpdate(providerId, {
        averageRating: averageRating,
        reviewCount: ratingData.totalRatings
      });

      console.log(`✅ Updated provider ${providerId} rating: ${averageRating} from ${ratingData.totalRatings} reviews`);
    }
  } catch (error) {
    console.error('Error updating provider average rating:', error);
  }
}


app.post('/api/test-email-simple', async (req, res) => {
  const transporter = nodemailer.createTransport({
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
    const testTransporter = nodemailer.createTransport({
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
    // Make sure we have the provider information
    if (provider && provider.email) {
      const emailResult = await sendBookingNotification({
        serviceType,
        description,
        location,
        timeframe,
        budget,
        contactInfo,
        specialRequests
      }, provider.email);
      
      if (!emailResult.success) {
        console.log('⚠️ Email notification failed but booking was created');
        console.log('⚠️ Email error:', emailResult.error);
      }
    } else {
      console.log('⚠️ Provider email not available for notification');
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
    console.log('=== GALLERY UPLOAD (LOCAL TEST) ===');
    
    if (!req.files || !req.files.image) {
      return res.status(400).json({
        success: false,
        message: 'No image file provided'
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

    // Create relative URL
    const imageUrl = `/uploads/gallery/${fileName}`;
    const fullImageUrl = `http://localhost:3001${imageUrl}`;

    // Create gallery entry
    const newImage = new Gallery({
      title: title.trim(),
      description: description ? description.trim() : '',
      category: category || 'other',
      imageUrl: imageUrl,
      fullImageUrl: fullImageUrl,
      userId: req.user.id,
      tags: tags ? tags.split(',').map(tag => tag.trim()).filter(tag => tag) : [],
      featured: featured === 'true' || featured === true
    });

    const savedImage = await newImage.save();
    await savedImage.populate('userId', 'name profileImage');

    console.log('✅ Image saved locally:', savedImage._id);

    res.status(201).json({
      success: true,
      message: 'Image uploaded successfully',
      data: savedImage
    });
    
  } catch (error) {
    console.error('Gallery upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to upload image',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
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
    const userId = req.user.id;
    const user = await User.findById(userId).select('identityVerification hasSubmittedVerification verificationStatus userType');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const verificationData = user.identityVerification || {};
    
    // Determine verification status with proper mapping
    let verificationStatus = 'not_submitted';
    let isVerified = false;
    let isNinVerified = false;
    let isNepaVerified = false;
    
    if (user.hasSubmittedVerification) {
      if (verificationData.verificationStatus === 'approved') {
        verificationStatus = 'verified';
        isVerified = true;
        isNinVerified = verificationData.isNinVerified || false;
        isNepaVerified = verificationData.isNepaVerified || false;
      } else if (verificationData.verificationStatus === 'rejected') {
        verificationStatus = 'rejected';
      } else if (verificationData.verificationStatus === 'pending') {
        verificationStatus = 'pending';
      } else {
        verificationStatus = 'submitted';
      }
    }

    // Return the exact structure that frontend expects
    res.json({
      success: true,
      data: {
        hasSubmittedVerification: user.hasSubmittedVerification,
        verificationStatus: verificationStatus,
        isVerified: isVerified,
        isNinVerified: isNinVerified, // Add this field
        isNepaVerified: isNepaVerified, // Add this field
        details: {
          ninVerified: verificationData.isNinVerified || false,
          nepaVerified: verificationData.isNepaVerified || false,
          selfieVerified: verificationData.isSelfieVerified || false,
          submittedAt: verificationData.verificationSubmittedAt,
          reviewedAt: verificationData.verificationReviewedAt,
          notes: verificationData.verificationNotes || ''
        }
      }
    });

  } catch (error) {
    console.error('Check verification status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check verification status'
    });
  }
});

app.get('/api/debug/verification-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select('identityVerification hasSubmittedVerification');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Return raw data for debugging
    res.json({
      success: true,
      data: {
        rawUserData: {
          hasSubmittedVerification: user.hasSubmittedVerification,
          identityVerification: user.identityVerification
        },
        frontendExpected: {
          hasSubmittedVerification: user.hasSubmittedVerification,
          verificationStatus: user.identityVerification?.verificationStatus || 'not_submitted',
          isVerified: user.identityVerification?.verificationStatus === 'approved',
          isNinVerified: user.identityVerification?.isNinVerified || false,
          isNepaVerified: user.identityVerification?.isNepaVerified || false,
          details: {
            ninVerified: user.identityVerification?.isNinVerified || false,
            nepaVerified: user.identityVerification?.isNepaVerified || false,
            selfieVerified: user.identityVerification?.isSelfieVerified || false
          }
        }
      }
    });

  } catch (error) {
    console.error('Debug verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch debug verification data'
    });
  }
});

app.get('/api/debug/verification-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select('identityVerification hasSubmittedVerification');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user._id,
          hasSubmittedVerification: user.hasSubmittedVerification
        },
        identityVerification: user.identityVerification || {},
        rawData: JSON.stringify(user.identityVerification, null, 2)
      }
    });
  } catch (error) {
    console.error('Debug verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Debug failed'
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

    await Notification.createNotification({
      userId: userId,
      type: 'system',
      title: 'Identity Verified!',
      message: 'Your identity verification has been approved. You can now apply for jobs.',
      relatedId: userId,
      relatedType: 'user',
      roleContext: 'both', // Show to both customer and provider views
      priority: 'high'
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
    
    console.log('📊 Fetching dashboard data for user:', userId);

    // Fetch user data with latest stats
    const user = await User.findById(userId).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Fetch ALL bookings for this provider with proper population
    const allBookings = await Booking.find({ providerId: userId })
      .populate('customerId', 'name email phoneNumber profileImage')
      .sort({ requestedAt: -1 })
      .limit(20);

    console.log('📋 All bookings found for provider:', allBookings.length);
    console.log('📋 Booking status breakdown:', {
      pending: allBookings.filter(b => b.status === 'pending').length,
      confirmed: allBookings.filter(b => b.status === 'confirmed').length,
      accepted: allBookings.filter(b => b.status === 'accepted').length,
      completed: allBookings.filter(b => b.status === 'completed').length,
      cancelled: allBookings.filter(b => b.status === 'cancelled').length
    });

    // CRITICAL FIX: Get schedule entries and actively filter out completed ones
    const scheduleEntries = await Schedule.find({ 
      providerId: userId
    })
    .sort({ date: 1, time: 1 })
    .populate('customerId', 'name email phoneNumber')
    .populate('bookingId', 'serviceType status');

    console.log('📅 Raw schedule entries from DB:', scheduleEntries.length);

    // ENHANCED FILTERING: Remove schedule entries for completed bookings
    const activeScheduleEntries = [];
    const completedScheduleEntries = [];

    for (const entry of scheduleEntries) {
      if (entry.bookingId) {
        // If schedule entry has a linked booking, check its status
        if (entry.bookingId.status === 'completed') {
          completedScheduleEntries.push(entry);
          console.log('🔍 Filtering out completed booking from schedule:', entry.bookingId._id);
          
          // AUTO-DELETE completed schedule entries in background
          try {
            await Schedule.findByIdAndDelete(entry._id);
            console.log('🗑️ Auto-deleted completed schedule entry:', entry._id);
          } catch (deleteError) {
            console.error('⚠️ Failed to auto-delete schedule entry:', deleteError.message);
          }
        } else {
          activeScheduleEntries.push(entry);
        }
      } else {
        // If no booking linked, keep it in schedule (manual entries)
        activeScheduleEntries.push(entry);
      }
    }

    console.log('📅 Active schedule entries (non-completed):', activeScheduleEntries.length);
    console.log('📅 Completed schedule entries filtered out:', completedScheduleEntries.length);

    // Fetch provider rating stats
    let ratingStats;
    try {
      ratingStats = await Rating.getProviderAverageRating(userId);
    } catch (ratingError) {
      console.log('⚠️ Rating stats not available, using defaults');
      ratingStats = {
        averageRating: 0,
        totalRatings: 0
      };
    }

    // Calculate real-time stats from completed bookings
    const completedBookingsFromDB = await Booking.find({ 
      providerId: userId, 
      status: 'completed' 
    }).populate('customerId', 'name email phoneNumber');

    // Calculate real-time earnings
    const realTimeEarnings = completedBookingsFromDB.reduce((total, booking) => {
      const amount = extractBudgetAmount(booking.budget);
      return total + amount;
    }, 0);

    // Calculate real-time active clients (last 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const recentCompletedBookings = completedBookingsFromDB.filter(booking => 
      booking.completedAt && new Date(booking.completedAt) >= ninetyDaysAgo
    );
    
    const uniqueCustomerIds = [...new Set(recentCompletedBookings
      .map(booking => booking.customerId ? booking.customerId._id.toString() : null)
      .filter(id => id !== null)
    )];

    // Use real-time calculated stats or fallback to stored stats
    const stats = {
      totalEarnings: realTimeEarnings > 0 ? realTimeEarnings : (user.totalEarnings || 0),
      jobsCompleted: completedBookingsFromDB.length > 0 ? completedBookingsFromDB.length : (user.completedJobs || 0),
      averageRating: ratingStats.averageRating || user.averageRating || 0,
      activeClients: uniqueCustomerIds.length > 0 ? uniqueCustomerIds.length : (user.activeClients?.length || 0),
      totalRatings: ratingStats.totalRatings || user.reviewCount || 0
    };

    console.log('📈 Final dashboard stats (real-time):', stats);

    // Generate recent jobs from COMPLETED bookings in the allBookings array
    const completedBookings = allBookings.filter(booking => booking.status === 'completed');
    console.log('🔍 Completed bookings for recent jobs:', completedBookings.length);

    const recentJobs = completedBookings
      .slice(0, 5)
      .map(booking => ({
        id: booking._id,
        title: booking.serviceType,
        client: booking.customerId?.name || booking.customerName || 'Unknown Client',
        category: booking.serviceType.toLowerCase().includes('clean') ? 'cleaning' : 'handyman',
        payment: extractBudgetAmount(booking.budget),
        status: booking.status,
        location: booking.location || 'Location not specified',
        date: booking.completedAt ? 
          new Date(booking.completedAt).toISOString().split('T')[0] : 
          new Date(booking.updatedAt).toISOString().split('T')[0],
        time: booking.completedAt ? 
          new Date(booking.completedAt).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true }) : 
          'Completed'
      }));

    console.log('📋 Recent jobs prepared:', recentJobs.length);

    // Generate upcoming tasks from pending and confirmed/accepted bookings
    const upcomingBookings = allBookings.filter(booking => 
      ['pending', 'confirmed', 'accepted'].includes(booking.status)
    ).slice(0, 3);

    const upcomingTasks = upcomingBookings.map(booking => ({
      id: booking._id,
      title: booking.serviceType,
      client: booking.customerName || 'Unknown Client',
      category: booking.serviceType.toLowerCase().includes('clean') ? 'cleaning' : 'handyman',
      time: '10:00 AM',
      duration: '2 hours',
      priority: 'medium'
    }));

    const responseData = {
      user: {
        name: user.name,
        email: user.email,
        id: user._id,
        country: user.country,
        phoneNumber: user.phoneNumber
      },
      businessHours: user.businessHours || [],
      recentJobs, // Only completed jobs go here
      upcomingTasks,
      bookings: allBookings, // ALL bookings for the "Recent Bookings" section
      schedule: activeScheduleEntries, // Schedule without completed entries
      stats
    };

    console.log('✅ Dashboard data prepared successfully');
    console.log('📦 Sending to frontend:', {
      totalBookings: allBookings.length,
      upcomingBookings: allBookings.filter(b => ['pending', 'confirmed', 'accepted'].includes(b.status)).length,
      completedBookings: allBookings.filter(b => b.status === 'completed').length,
      recentJobsCount: recentJobs.length,
      scheduleEntriesCount: activeScheduleEntries.length
    });

    res.json(responseData);
  } catch (error) {
    console.error('❌ Dashboard API error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard data',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});







function extractBudgetAmount(budget) {
  if (!budget) return 0;
  const numericString = budget.replace(/[^\d.]/g, '');
  return parseFloat(numericString) || 0;
}

app.get('/api/providers/:id/stats', async (req, res) => {
  try {
    const providerId = req.params.id;
    
    // Calculate real performance stats from bookings and ratings
    const completedJobs = await Booking.countDocuments({ 
      providerId, 
      status: 'completed' 
    });
    
    // Calculate on-time delivery rate
    const onTimeJobs = await Booking.countDocuments({
      providerId,
      status: 'completed',
      completedAt: { $lte: '$scheduledEndTime' } // Assuming you have scheduled times
    });
    
    const onTimeDelivery = completedJobs > 0 ? Math.round((onTimeJobs / completedJobs) * 100) : 95;
    
    // Calculate response rate (you might need a different metric)
    const respondedBookings = await Booking.countDocuments({
      providerId,
      respondedAt: { $exists: true }
    });
    
    const totalBookings = await Booking.countDocuments({ providerId });
    const responseRate = totalBookings > 0 ? Math.round((respondedBookings / totalBookings) * 100) : 98;
    
    // Calculate total earnings
    const earningsResult = await Booking.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          totalEarnings: { $sum: { $toDouble: '$budget' } }
        }
      }
    ]);
    
    const totalEarnings = earningsResult.length > 0 ? earningsResult[0].totalEarnings : 0;
    
    // Count active clients (last 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const activeClients = await Booking.distinct('customerId', {
      providerId,
      status: 'completed',
      completedAt: { $gte: ninetyDaysAgo }
    });
    
    res.json({
      success: true,
      data: {
        completedJobs,
        onTimeDelivery,
        responseRate,
        totalEarnings,
        activeClients: activeClients.length,
        repeatClients: 0 // You can calculate this based on customer repeat bookings
      }
    });
  } catch (error) {
    console.error('Get provider stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider stats'
    });
  }
});

// Performance stats endpoint
app.get('/api/providers/:id/stats', async (req, res) => {
  try {
    const providerId = req.params.id;
    
    console.log('📊 Fetching performance stats for provider:', providerId);

    // Calculate completed jobs
    const completedJobs = await Booking.countDocuments({ 
      providerId, 
      status: 'completed' 
    });

    // Calculate on-time delivery (simplified for now)
    const onTimeJobs = await Booking.countDocuments({
      providerId,
      status: 'completed',
      // You can add actual on-time logic here based on your booking model
    });
    
    const onTimeDelivery = completedJobs > 0 ? Math.round((onTimeJobs / completedJobs) * 100) : 95;

    // Calculate response rate (based on accepted bookings)
    const respondedBookings = await Booking.countDocuments({
      providerId,
      status: { $in: ['accepted', 'confirmed', 'completed'] }
    });
    
    const totalBookings = await Booking.countDocuments({ providerId });
    const responseRate = totalBookings > 0 ? Math.round((respondedBookings / totalBookings) * 100) : 98;

    // Calculate total earnings
    const earningsResult = await Booking.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          status: 'completed'
        }
      },
      {
        $group: {
          _id: null,
          totalEarnings: { 
            $sum: { 
              $convert: {
                input: {
                  $replaceAll: {
                    input: {
                      $replaceAll: {
                        input: { 
                          $arrayElemAt: [
                            { 
                              $split: ["$budget", "₦"] 
                            }, 
                            1 
                          ] 
                        },
                        find: ",",
                        replacement: ""
                      }
                    },
                    find: " ",
                    replacement: ""
                  }
                },
                to: "double",
                onError: 0,
                onNull: 0
              }
            } 
          }
        }
      }
    ]);
    
    const totalEarnings = earningsResult.length > 0 ? earningsResult[0].totalEarnings : 0;

    // Count active clients (last 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const activeClients = await Booking.distinct('customerId', {
      providerId,
      status: 'completed',
      completedAt: { $gte: ninetyDaysAgo }
    });

    res.json({
      success: true,
      data: {
        completedJobs,
        onTimeDelivery,
        responseRate,
        totalEarnings,
        activeClients: activeClients.length,
        repeatClients: 0 // You can calculate this based on customer repeat bookings
      }
    });
  } catch (error) {
    console.error('❌ Get provider stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch provider stats',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/debug/user-stats/:userId', authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId;
    
    const user = await User.findById(userId).select('totalEarnings completedJobs activeClients');
    const bookings = await Booking.find({ providerId: userId, status: 'completed' });
    
    const calculatedEarnings = bookings.reduce((sum, booking) => {
      const amount = booking.budget ? parseFloat(booking.budget.replace(/[^\d.]/g, '')) || 0 : 0;
      return sum + amount;
    }, 0);
    
    const uniqueClients = [...new Set(bookings.map(b => b.customerId.toString()))];
    
    res.json({
      success: true,
      data: {
        userStats: {
          totalEarnings: user?.totalEarnings,
          completedJobs: user?.completedJobs,
          activeClients: user?.activeClients?.length
        },
        calculatedFromBookings: {
          totalEarnings: calculatedEarnings,
          completedJobs: bookings.length,
          activeClients: uniqueClients.length
        },
        bookingsCount: bookings.length,
        bookingsSample: bookings.slice(0, 3).map(b => ({
          id: b._id,
          budget: b.budget,
          customer: b.customerId,
          status: b.status
        }))
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

//Business Hours
app.post('/api/business-hours/bulk', authenticateToken, async (req, res) => {
  try {
    const { businessHours } = req.body;
    const userId = req.user.id;

    console.log('💼 Saving business hours for user:', userId);

    if (!businessHours || !Array.isArray(businessHours)) {
      return res.status(400).json({
        success: false,
        message: 'Business hours array is required'
      });
    }

    // Update user's business hours
    const user = await User.findByIdAndUpdate(
      userId,
      { 
        businessHours: businessHours.map(hours => ({
          dayOfWeek: hours.dayOfWeek,
          startTime: hours.startTime,
          endTime: hours.endTime,
          isAvailable: hours.isAvailable !== undefined ? hours.isAvailable : true,
          serviceTypes: hours.serviceTypes || [],
          notes: hours.notes || ''
        }))
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // AUTOMATICALLY UPDATE AVAILABILITY BASED ON NEW BUSINESS HOURS
    await updateProviderAvailability(userId);

    // Get updated user data
    const updatedUser = await User.findById(userId);

    console.log('✅ Business hours saved and availability updated');

    res.json({
      success: true,
      message: 'Business hours saved successfully',
      data: {
        businessHours: updatedUser.businessHours,
        isAvailableNow: updatedUser.isAvailableNow // Return current availability status
      }
    });
  } catch (error) {
    console.error('Business hours save error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to save business hours',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/availability/check-now', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const isAvailable = await updateProviderAvailability(userId);
    const user = await User.findById(userId).select('isAvailableNow businessHours');

    res.json({
      success: true,
      data: {
        isAvailableNow: user.isAvailableNow,
        businessHours: user.businessHours,
        message: `You are currently ${user.isAvailableNow ? 'available' : 'unavailable'} based on your business hours`
      }
    });
  } catch (error) {
    console.error('Manual availability check error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check availability'
    });
  }
});

cron.schedule('*/5 * * * *', async () => {
  try {
    console.log('⏰ Running scheduled availability check...');
    await updateAllProvidersAvailability();
  } catch (error) {
    console.error('Scheduled availability check failed:', error);
  }
});

// Also run on server startup
updateAllProvidersAvailability();



app.get('/api/business-hours', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('businessHours');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        businessHours: user.businessHours || []
      }
    });
  } catch (error) {
    console.error('Get business hours error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch business hours'
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


async function updateProviderAvailability(userId) {
  try {
    const user = await User.findById(userId);
    if (!user || !user.businessHours || user.businessHours.length === 0) {
      return false;
    }

    const now = new Date();
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' }); // e.g., "Monday"
    const currentTime = now.toTimeString().slice(0, 5); // "HH:MM" format

    // Find today's business hours
    const todayHours = user.businessHours.find(hours => 
      hours.dayOfWeek.toLowerCase() === currentDay.toLowerCase() && 
      hours.isAvailable
    );

    if (!todayHours) {
      // No business hours for today or not available
      user.isAvailableNow = false;
      await user.save();
      return false;
    }

    // Check if current time is within business hours
    const isAvailable = currentTime >= todayHours.startTime && currentTime <= todayHours.endTime;
    
    // Update user's availability
    user.isAvailableNow = isAvailable;
    await user.save();

    console.log(`🕒 Availability updated for ${user.name}: ${isAvailable ? 'Available' : 'Unavailable'}`);
    return isAvailable;

  } catch (error) {
    console.error('Error updating provider availability:', error);
    return false;
  }
}

// Function to update all providers' availability
async function updateAllProvidersAvailability() {
  try {
    console.log('🔄 Updating availability for all providers based on business hours...');
    
    const providers = await User.find({ 
      userType: { $in: ['provider', 'both'] },
      businessHours: { $exists: true, $ne: [] }
    });

    let updatedCount = 0;
    
    for (const provider of providers) {
      const wasAvailable = provider.isAvailableNow;
      await updateProviderAvailability(provider._id);
      
      // Re-fetch to get updated status
      const updatedProvider = await User.findById(provider._id);
      if (updatedProvider.isAvailableNow !== wasAvailable) {
        updatedCount++;
      }
    }

    console.log(`✅ Availability update completed. ${updatedCount} providers updated.`);
  } catch (error) {
    console.error('Error updating all providers availability:', error);
  }
}




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
  
  // More lenient location matching
  mainQuery.$or = [
    { city: { $regex: mainLocationTerm, $options: 'i' } },
    { state: { $regex: mainLocationTerm, $options: 'i' } },
    { country: { $regex: mainLocationTerm, $options: 'i' } },
    { address: { $regex: mainLocationTerm, $options: 'i' } },
    // Add fallback for providers with incomplete location
    { 
      $and: [
        { $or: [
          { city: { $exists: false } },
          { city: null },
          { city: '' }
        ]},
        { $or: [
          { state: { $exists: false } },
          { state: null },
          { state: '' }
        ]}
      ]
    }
  ];
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
      //customer provider profile 
      app.use('/api/providers', providerRoutes);



      // Rating scoring
      const rating = provider.averageRating || provider.rating || 1.0;
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
      
      const ratingA = a.averageRating || a.rating || 1.0;
      const ratingB = b.averageRating || b.rating || 1.0;
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
        averageRating: provider.averageRating || provider.rating || 1.0,
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
          rating: 1.0
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
          rating: 1.0
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

    console.log('📝 Creating booking with providerId:', providerId);
    console.log('📝 Booking details:', {
      providerId,
      providerName,
      providerEmail,
      serviceType,
      customerName: contactInfo?.name,
      customerEmail: contactInfo?.email,
      customerPhone: contactInfo?.phone,
      location,
      budget,
      timeframe,
      bookingType
    });

    // Validate required fields
    if (!providerId || !serviceType || !location || !contactInfo) {
      return res.status(400).json({
        success: false,
        message: 'Provider ID, service type, location, and contact info are required'
      });
    }

    // Validate provider exists
    const provider = await User.findById(providerId);
    if (!provider) {
      return res.status(404).json({
        success: false,
        message: 'Provider not found'
      });
    }

    console.log('✅ Provider found:', {
      id: provider._id,
      name: provider.name,
      email: provider.email
    });

    // Create new booking
    const newBooking = new Booking({
      providerId,
      providerName: providerName || provider.name || 'Unknown Provider',
      providerEmail: providerEmail || provider.email || '',
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
    console.log('✅ Booking created successfully:', {
      bookingId: savedBooking._id,
      providerId: savedBooking.providerId,
      customerId: savedBooking.customerId,
      status: savedBooking.status
    });

    // Populate customer and provider info
    await savedBooking.populate('customerId', 'name email phoneNumber');
    await savedBooking.populate('providerId', 'name email phoneNumber');

    console.log('✅ Booking populated:', {
      customer: savedBooking.customerId?.name,
      provider: savedBooking.providerId?.name
    });

    // ✅ RENDER PRODUCTION: SEND EMAIL NOTIFICATION TO PROVIDER
    try {
      const { sendBookingNotificationToProvider } = await import('./utils/emailService.js');
      
      const bookingData = {
        providerName: savedBooking.providerName,
        serviceType: savedBooking.serviceType,
        location: savedBooking.location,
        timeframe: savedBooking.timeframe,
        budget: savedBooking.budget,
        description: savedBooking.description,
        specialRequests: savedBooking.specialRequests,
        bookingType: savedBooking.bookingType
      };

      const customerInfo = {
        name: savedBooking.customerName,
        email: savedBooking.customerEmail,
        phone: savedBooking.customerPhone
      };

      // Send email notification to provider
      const emailResult = await sendBookingNotificationToProvider(
        savedBooking.providerEmail,
        bookingData,
        customerInfo
      );

      // Log results for Render monitoring
      if (emailResult.success) {
        console.log('✅ [RENDER] Booking notification sent successfully');
        console.log('📨 Provider:', savedBooking.providerEmail);
        console.log('🔧 Service:', emailResult.provider);
        
        if (emailResult.simulated) {
          console.log('🔄 Simulation mode - check Render logs for details');
        }
      } else {
        console.log('⚠️ [RENDER] Email notification failed:', emailResult.error);
        console.log('🔧 Failed provider:', emailResult.provider);
        // Don't fail the booking - email is secondary
      }
    } catch (emailError) {
      console.error('⚠️ [RENDER] Email notification error (non-critical):', emailError);
      // Don't fail the booking if email fails
    }

    // Create notification in database
    try {
      await Notification.createNotification({
        userId: providerId,
        type: 'booking',
        title: 'New Booking Request',
        message: `You have a new booking request for ${serviceType} from ${contactInfo.name}`,
        relatedId: savedBooking._id,
        relatedType: 'booking',
        priority: 'high'
      });
      console.log('✅ Notification created for provider');
    } catch (notificationError) {
      console.error('⚠️ Notification creation failed (non-critical):', notificationError);
    }

    // Also create notification for customer
    try {
      await Notification.createNotification({
        userId: req.user.id,
        type: 'booking',
        title: 'Booking Request Sent',
        message: `Your booking request for ${serviceType} has been sent to ${providerName}`,
        relatedId: savedBooking._id,
        relatedType: 'booking',
        priority: 'medium'
      });
      console.log('✅ Notification created for customer');
    } catch (notificationError) {
      console.error('⚠️ Customer notification creation failed (non-critical):', notificationError);
    }

    // Debug: Check if booking is retrievable immediately
    try {
      const verifyBooking = await Booking.findById(savedBooking._id)
        .populate('customerId', 'name email')
        .populate('providerId', 'name email');
      
      console.log('🔍 Booking verification - found:', {
        id: verifyBooking._id,
        providerId: verifyBooking.providerId?._id,
        customerId: verifyBooking.customerId?._id,
        status: verifyBooking.status,
        serviceType: verifyBooking.serviceType
      });
    } catch (verifyError) {
      console.error('❌ Booking verification failed:', verifyError);
    }

    res.status(201).json({
      success: true,
      message: 'Booking request sent successfully! The provider has been notified.',
      data: savedBooking
    });

  } catch (error) {
    console.error('❌ Create booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create booking',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.patch('/api/bookings/:id/update-price', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { price, amount } = req.body;

    console.log('💰 Updating booking price:', { bookingId, price, amount });

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Update price and amount
    if (price !== undefined) booking.price = price;
    if (amount !== undefined) booking.amount = amount;
    
    // If both are undefined, try to extract from budget
    if ((price === undefined && amount === undefined) && booking.budget) {
      const numericValue = booking.budget.replace(/[^\d.]/g, '');
      const extractedPrice = parseFloat(numericValue) || 0;
      booking.price = extractedPrice;
      booking.amount = extractedPrice;
      console.log('💰 Extracted price from budget:', extractedPrice);
    }

    await booking.save();

    console.log('✅ Booking price updated:', {
      bookingId: booking._id,
      price: booking.price,
      amount: booking.amount
    });

    res.json({
      success: true,
      message: 'Booking price updated successfully',
      data: {
        price: booking.price,
        amount: booking.amount
      }
    });

  } catch (error) {
    console.error('❌ Update booking price error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update booking price',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/debug/bookings-prices', authenticateToken, async (req, res) => {
  try {
    const bookings = await Booking.find({})
      .select('_id serviceType price amount budget status')
      .sort({ createdAt: -1 })
      .limit(50);

    const bookingsWithIssues = bookings.filter(b => 
      b.price === undefined || b.amount === undefined || b.price === 0
    );

    res.json({
      success: true,
      data: {
        totalBookings: bookings.length,
        bookingsWithPriceIssues: bookingsWithIssues.length,
        sampleBookings: bookings.slice(0, 10).map(b => ({
          id: b._id,
          serviceType: b.serviceType,
          price: b.price,
          amount: b.amount,
          budget: b.budget,
          status: b.status,
          hasPrice: b.price !== undefined && b.price !== null,
          hasAmount: b.amount !== undefined && b.amount !== null
        })),
        problematicBookings: bookingsWithIssues.map(b => ({
          id: b._id,
          serviceType: b.serviceType,
          price: b.price,
          amount: b.amount,
          budget: b.budget,
          status: b.status
        }))
      }
    });
  } catch (error) {
    console.error('Debug bookings prices error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch booking prices',
      error: error.message
    });
  }
});

app.post('/api/debug/fix-all-booking-prices', authenticateToken, async (req, res) => {
  try {
    const bookings = await Booking.find({
      $or: [
        { price: { $exists: false } },
        { price: null },
        { price: 0 },
        { amount: { $exists: false } },
        { amount: null },
        { amount: 0 }
      ]
    });

    console.log(`🔄 Found ${bookings.length} bookings with price issues`);

    let fixedCount = 0;
    const results = [];

    for (const booking of bookings) {
      try {
        let newPrice = booking.price;
        let newAmount = booking.amount;

        // If price is missing, try to extract from budget
        if (!newPrice || newPrice === 0) {
          if (booking.budget) {
            const numericValue = booking.budget.replace(/[^\d.]/g, '');
            newPrice = parseFloat(numericValue) || 100; // Default to 100 if can't parse
            console.log(`💰 Extracted price from budget: ${booking.budget} -> ${newPrice}`);
          } else {
            newPrice = 100; // Default price
          }
        }

        // If amount is missing, use the same as price
        if (!newAmount || newAmount === 0) {
          newAmount = newPrice;
        }

        // Update the booking
        booking.price = newPrice;
        booking.amount = newAmount;
        await booking.save();

        fixedCount++;
        results.push({
          id: booking._id,
          serviceType: booking.serviceType,
          oldPrice: booking.price,
          newPrice: newPrice,
          newAmount: newAmount,
          budget: booking.budget,
          status: 'fixed'
        });

        console.log(`✅ Fixed booking ${booking._id}: price=${newPrice}, amount=${newAmount}`);

      } catch (error) {
        console.error(`❌ Failed to fix booking ${booking._id}:`, error.message);
        results.push({
          id: booking._id,
          serviceType: booking.serviceType,
          error: error.message,
          status: 'failed'
        });
      }
    }

    res.json({
      success: true,
      message: `Fixed ${fixedCount} out of ${bookings.length} bookings with price issues`,
      data: {
        totalFound: bookings.length,
        fixedCount: fixedCount,
        failedCount: bookings.length - fixedCount,
        results: results
      }
    });

  } catch (error) {
    console.error('Fix all booking prices error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fix booking prices',
      error: error.message
    });
  }
});

app.get('/api/debug/gcs-config', (req, res) => {
  const config = {
    bucketName: process.env.GCLOUD_BUCKET_NAME,
    projectId: process.env.GCLOUD_PROJECT_ID,
    keyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    keyFileExists: fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS || ''),
    currentKeyFile: process.env.GOOGLE_APPLICATION_CREDENTIALS
  };
  
  console.log('GCS Config:', config);
  res.json({ success: true, data: config });
});



app.get('/api/email/status', async (req, res) => {
  const { getEmailServiceStatus } = await import('./utils/emailService.js');
  const status = getEmailServiceStatus();
  
  res.json({
    success: true,
    data: {
      environment: process.env.NODE_ENV,
      emailService: status,
      mailjetConfigured: !!(process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY),
      gmailConfigured: !!(process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
      frontendUrl: process.env.FRONTEND_URL,
      apiUrl: process.env.API_URL,
      timestamp: new Date().toISOString()
    }
  });
});

app.post('/api/email/send-booking-accepted', authenticateToken, async (req, res) => {
  try {
    const { customerEmail, bookingData, providerInfo } = req.body;

    if (!customerEmail || !bookingData || !providerInfo) {
      return res.status(400).json({
        success: false,
        message: 'Customer email, booking data, and provider info are required'
      });
    }

    console.log('📧 Sending booking acceptance email to customer:', customerEmail);

    const { sendBookingAcceptedNotificationToCustomer } = await import('./utils/emailService.js');
    
    const emailResult = await sendBookingAcceptedNotificationToCustomer(
      customerEmail,
      bookingData,
      providerInfo
    );

    if (emailResult.success) {
      console.log('✅ Booking acceptance email sent successfully to:', customerEmail);
      
      if (emailResult.simulated) {
        console.log('🔄 Email simulation mode - check logs for details');
      } else {
        console.log('📨 Actual email sent with ID:', emailResult.messageId);
      }
      
      res.json({
        success: true,
        message: 'Booking acceptance email sent successfully',
        data: emailResult
      });
    } else {
      console.log('⚠️ Failed to send booking acceptance email:', emailResult.error);
      
      res.status(500).json({
        success: false,
        message: 'Failed to send booking acceptance email',
        error: emailResult.error
      });
    }

  } catch (error) {
    console.error('❌ Send booking acceptance email error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send booking acceptance email',
      error: error.message
    });
  }
});

app.post('/api/debug/test-booking-email', authenticateToken, async (req, res) => {
  try {
    const { providerEmail } = req.body;
    
    if (!providerEmail) {
      return res.status(400).json({
        success: false,
        message: 'Provider email is required'
      });
    }

    console.log('🧪 Testing booking email to:', providerEmail);

    const { sendBookingNotificationToProvider } = await import('./utils/emailService.js');
    
    const testBookingData = {
      providerName: 'Test Provider',
      serviceType: 'House Cleaning',
      location: 'Test Location, Lagos',
      timeframe: 'ASAP',
      budget: '₦15,000',
      description: 'Test booking description',
      specialRequests: 'Test special requests',
      bookingType: 'immediate'
    };

    const testCustomerInfo = {
      name: 'Test Customer',
      email: 'customer@example.com',
      phone: '+234 123 456 7890'
    };

    const result = await sendBookingNotificationToProvider(
      providerEmail,
      testBookingData,
      testCustomerInfo
    );

    res.json({
      success: true,
      message: 'Booking email test completed',
      data: result
    });
  } catch (error) {
    console.error('Test booking email error:', error);
    res.status(500).json({
      success: false,
      message: 'Booking email test failed',
      error: error.message
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
    
    console.log('📋 Received schedule data:', scheduleData);
    
    // Validate required fields
    const requiredFields = ['providerId', 'customerId', 'bookingId'];
    const missingFields = requiredFields.filter(field => !scheduleData[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(', ')}`,
        missingFields
      });
    }
    
    // Validate status enum
    const validStatuses = ['pending', 'confirmed', 'completed', 'cancelled'];
    if (scheduleData.status && !validStatuses.includes(scheduleData.status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status: ${scheduleData.status}. Must be one of: ${validStatuses.join(', ')}`,
        validStatuses
      });
    }
    
    // Ensure status is set to a valid value
    const finalScheduleData = {
      ...scheduleData,
      status: scheduleData.status && validStatuses.includes(scheduleData.status) 
        ? scheduleData.status 
        : 'confirmed'
    };
    
    console.log('💾 Saving schedule entry:', finalScheduleData);
    
    // Save to database
    const newScheduleEntry = new Schedule(finalScheduleData);
    await newScheduleEntry.save();
    
    console.log('✅ Schedule entry created successfully:', newScheduleEntry._id);
    
    res.json({
      success: true,
      message: 'Booking added to schedule successfully',
      data: newScheduleEntry
    });
  } catch (error) {
    console.error('❌ Add to schedule error:', error);
    
    // Provide more specific error messages
    if (error.name === 'ValidationError') {
      const validationErrors = Object.keys(error.errors).map(key => ({
        field: key,
        message: error.errors[key].message,
        value: error.errors[key].value
      }));
      
      return res.status(400).json({
        success: false,
        message: 'Schedule validation failed',
        errors: validationErrors
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to add booking to schedule',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
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
async function updateProviderStatsOnCompletion(bookingId) {
  try {
    console.log('🔄 Updating provider stats for completed booking:', bookingId);
    
    const booking = await Booking.findById(bookingId)
      .populate('providerId')
      .populate('customerId');
    
    if (!booking || booking.status !== 'completed') {
      console.log('❌ Booking not found or not completed');
      return;
    }

    const provider = await User.findById(booking.providerId);
    if (!provider) {
      console.log('❌ Provider not found');
      return;
    }

    // Extract numeric value from budget
    const extractBudgetAmount = (budget) => {
      if (!budget) return 0;
      const numericString = budget.replace(/[^\d.]/g, '');
      return parseFloat(numericString) || 0;
    };

    const earningsAmount = extractBudgetAmount(booking.budget);
    console.log('💰 Earnings amount:', earningsAmount);

    // Update provider stats
    provider.completedJobs = (provider.completedJobs || 0) + 1;
    provider.totalEarnings = (provider.totalEarnings || 0) + earningsAmount;
    
    // Update active clients (unique customers)
    if (!provider.activeClients) {
      provider.activeClients = [];
    }
    
    const customerIdStr = booking.customerId._id.toString();
    if (!provider.activeClients.includes(customerIdStr)) {
      provider.activeClients.push(customerIdStr);
    }

    // Update average rating
    const ratingStats = await Rating.getProviderAverageRating(provider._id);
    provider.averageRating = ratingStats.averageRating;
    provider.reviewCount = ratingStats.totalRatings;

    await provider.save();
    
    console.log('✅ Provider stats updated:', {
      provider: provider.name,
      completedJobs: provider.completedJobs,
      totalEarnings: provider.totalEarnings,
      activeClients: provider.activeClients.length,
      averageRating: provider.averageRating
    });

  } catch (error) {
    console.error('❌ Error updating provider stats:', error);
  }
}


app.patch('/api/bookings/:id/status', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    const bookingId = req.params.id;

    console.log('🔄 Updating booking status:', { bookingId, status });

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    // Authorization check
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }

    // SIMPLE WORKING VERSION - Use only existing statuses
    const oldStatus = booking.status;
    booking.status = status; // Use the status directly from frontend
    
    // If provider is accepting, ensure payment is set up
    if ((status === 'accepted' || status === 'confirmed') && !booking.payment) {
      booking.payment = {
        status: 'requires_payment_method',
        amount: booking.price || booking.amount || 100,
        currency: 'NGN',
        processor: 'paystack'
      };
    }

    await booking.save();
    
    console.log(`✅ Status updated: ${oldStatus} → ${status}`);

    res.json({
      success: true,
      message: `Booking ${status} successfully`,
      data: booking
    });

  } catch (error) {
    console.error('❌ Status update error:', error);
    
    if (error.name === 'ValidationError') {
      // Get valid statuses from the error
      const validStatuses = error.errors?.status?.properties?.enumValues || 
                           ['pending', 'confirmed', 'accepted', 'completed', 'cancelled'];
      
      return res.status(400).json({
        success: false,
        message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`,
        validStatuses: validStatuses
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to update booking status'
    });
  }
});



function isPaymentRequired(booking) {
  return (
    booking.status === 'awaiting_payment' ||
    (booking.status === 'confirmed' && 
     booking.payment && 
     booking.payment.status === 'requires_payment_method') ||
    (booking.status === 'accepted' && 
     (!booking.payment || booking.payment.status === 'requires_payment_method'))
  );
}


app.post('/api/schedule/force-cleanup-completed', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    console.log('🚨 FORCE CLEANUP: Removing all completed bookings from schedule for user:', userId);

    // Get all completed bookings
    const completedBookings = await Booking.find({ 
      providerId: userId, 
      status: 'completed' 
    });

    console.log(`📋 Found ${completedBookings.length} completed bookings`);

    let totalRemoved = 0;

    // Remove schedule entries for each completed booking using multiple methods
    for (const booking of completedBookings) {
      console.log(`🧹 Cleaning up schedule for completed booking: ${booking._id}`);
      
      // Method 1: Remove by bookingId
      const result1 = await Schedule.deleteMany({ bookingId: booking._id });
      console.log(`   Removed ${result1.deletedCount} by bookingId`);
      
      // Method 2: Remove by customer/service match
      const result2 = await Schedule.deleteMany({
        providerId: userId,
        client: booking.customerName,
        title: booking.serviceType
      });
      console.log(`   Removed ${result2.deletedCount} by customer/service match`);
      
      totalRemoved += (result1.deletedCount + result2.deletedCount);
    }

    // Final verification
    const remainingSchedule = await Schedule.find({ providerId: userId })
      .populate('bookingId', 'status');
    
    const remainingCompleted = remainingSchedule.filter(entry => 
      entry.bookingId && entry.bookingId.status === 'completed'
    );

    console.log(`✅ Force cleanup completed. Total removed: ${totalRemoved}`);
    console.log(`📊 Remaining schedule entries: ${remainingSchedule.length}`);
    console.log(`📊 Remaining completed in schedule: ${remainingCompleted.length}`);

    res.json({
      success: true,
      message: `Force cleanup completed! Removed ${totalRemoved} schedule entries for completed bookings.`,
      data: {
        removedCount: totalRemoved,
        remainingScheduleCount: remainingSchedule.length,
        remainingCompletedCount: remainingCompleted.length
      }
    });
  } catch (error) {
    console.error('❌ Force cleanup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to force cleanup schedule',
      error: error.message
    });
  }
});




//Shedule

async function removeCompletedBookingFromSchedule(bookingId) {
  try {
    console.log('🗑️ Removing completed booking from schedule:', bookingId);
    
    const result = await Schedule.findOneAndDelete({
      bookingId: bookingId
    });
    
    if (result) {
      console.log('✅ Successfully removed booking from schedule:', bookingId);
    } else {
      console.log('ℹ️ No schedule entry found for booking:', bookingId);
    }
    
    return result;
  } catch (error) {
    console.error('❌ Error removing booking from schedule:', error);
    throw error;
  }
}




app.post('/api/debug/cleanup-duplicate-schedules', authenticateToken, async (req, res) => {
  try {
    // Find and remove schedule entries with missing required fields
    const result = await Schedule.deleteMany({
      $or: [
        { providerId: { $exists: false } },
        { customerId: { $exists: false } },
        { bookingId: { $exists: false } },
        { providerId: null },
        { customerId: null },
        { bookingId: null }
      ]
    });
    
    console.log('🧹 Cleaned up invalid schedule entries:', result.deletedCount);
    
    res.json({
      success: true,
      message: `Cleaned up ${result.deletedCount} invalid schedule entries`
    });
  } catch (error) {
    console.error('Cleanup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cleanup schedule entries',
      error: error.message
    });
  }
});

app.post('/api/schedule/cleanup-completed', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    console.log('🧹 Cleaning up completed bookings from schedule for user:', userId);

    // Find all schedule entries for this provider
    const scheduleEntries = await Schedule.find({ providerId: userId })
      .populate('bookingId', 'status');

    let removedCount = 0;
    
    // Remove schedule entries for completed bookings
    for (const entry of scheduleEntries) {
      if (entry.bookingId && entry.bookingId.status === 'completed') {
        await Schedule.findByIdAndDelete(entry._id);
        removedCount++;
        console.log('🗑️ Removed completed booking from schedule:', entry.bookingId._id);
      }
    }

    res.json({
      success: true,
      message: `Cleaned up ${removedCount} completed bookings from schedule`,
      data: { removedCount }
    });
  } catch (error) {
    console.error('Schedule cleanup error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to cleanup schedule',
      error: error.message
    });
  }
});




app.use('/api/schedule', (req, res, next) => {
  console.log('📨 Schedule API Request:', {
    method: req.method,
    url: req.url,
    body: req.body,
    headers: req.headers
  });
  next();
});

app.get('/api/schedule', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { date } = req.query; // Optional: filter by specific date

    let filter = { providerId: userId };
    
    if (date) {
      filter.date = date; // Filter by specific date
    }

    const scheduleEntries = await Schedule.find(filter)
      .sort({ date: 1, time: 1 })
      .populate('customerId', 'name email phoneNumber')
      .populate('bookingId', 'serviceType status');

    res.json({
      success: true,
      data: {
        schedule: scheduleEntries
      }
    });
  } catch (error) {
    console.error('Get schedule error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch schedule',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/debug/test-schedule-validation', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.body;
    
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }

    // Test schedule creation
    const testScheduleData = {
      title: booking.serviceType,
      client: booking.customerName,
      phone: booking.customerPhone || 'Not provided',
      location: booking.location,
      date: new Date().toISOString().split('T')[0],
      time: '10:00 AM',
      endTime: '12:00 PM',
      duration: '2 hours',
      payment: booking.budget,
      status: 'confirmed',
      notes: booking.description,
      category: 'cleaning',
      priority: 'medium',
      providerId: booking.providerId,
      customerId: booking.customerId,
      bookingId: booking._id
    };

    console.log('🧪 Testing schedule validation with:', testScheduleData);

    const testSchedule = new Schedule(testScheduleData);
    await testSchedule.validate(); // This will throw if validation fails

    res.json({
      success: true,
      message: 'Schedule validation passed',
      data: testScheduleData
    });

  } catch (error) {
    console.error('❌ Schedule validation test failed:', error);
    res.status(400).json({
      success: false,
      message: 'Schedule validation failed',
      error: error.message,
      errors: error.errors
    });
  }
});





app.post('/api/ratings/customer', authenticateToken, async (req, res) => {
  try {
    const { bookingId, rating, comment } = req.body;

    console.log('📝 Customer rating request:', { bookingId, rating, comment, customerId: req.user.id });

    if (!bookingId || !rating) {
      return res.status(400).json({
        success: false,
        message: 'Booking ID and rating are required'
      });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        message: 'Rating must be between 1 and 5'
      });
    }

    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Check if user is the customer for this booking
    if (booking.customerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to rate this booking'
      });
    }

    // Check if booking is completed
    if (booking.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Can only rate completed bookings'
      });
    }

    // Find or create rating
    let ratingDoc = await Rating.findOne({ bookingId });
    
    if (!ratingDoc) {
      ratingDoc = new Rating({
        bookingId,
        providerId: booking.providerId,
        customerId: booking.customerId,
        providerRating: rating,
        providerComment: comment || '',
        customerRated: true
      });
    } else {
      ratingDoc.providerRating = rating;
      ratingDoc.providerComment = comment || '';
      ratingDoc.customerRated = true;
    }

    await ratingDoc.save();

    // Update booking rating status
    if (!booking.ratingStatus) {
      booking.ratingStatus = {
        customerRated: false,
        providerRated: false
      };
    }
    booking.ratingStatus.customerRated = true;
    await booking.save();

    // Update provider's average rating
    await updateProviderAverageRating(booking.providerId);

    console.log('✅ Customer rating submitted successfully for booking:', bookingId);

    // Create notification for PROVIDER
    await Notification.createNotification({
      userId: booking.providerId,
      type: 'rating_received',
      title: 'New Rating Received',
      message: `You've received a ${rating} star rating from ${booking.customerName}`,
      relatedId: booking._id,
      relatedType: 'rating',
      roleContext: 'provider', // Only show to provider
      priority: 'low'
    });

    // Create notification for CUSTOMER
    await Notification.createNotification({
      userId: req.user.id,
      type: 'rating_received',
      title: 'Rating Submitted',
      message: `You rated ${booking.providerName} ${rating} stars`,
      relatedId: booking._id,
      relatedType: 'rating',
      roleContext: 'customer', // Only show to customer
      priority: 'low'
    });


    res.json({
      success: true,
      message: 'Rating submitted successfully',
      data: { rating: ratingDoc }
    });

  } catch (error) {
    console.error('❌ Customer rating error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit rating',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/ratings/provider', authenticateToken, async (req, res) => {
  try {
    const { bookingId, rating } = req.body;

    console.log('📝 Provider rating request:', { bookingId, rating, providerId: req.user.id });

    if (!bookingId || !rating) {
      return res.status(400).json({
        success: false,
        message: 'Booking ID and rating are required'
      });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        message: 'Rating must be between 1 and 5'
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

    // Check if user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to rate this booking'
      });
    }

    // Check if booking is completed
    if (booking.status !== 'completed') {
      return res.status(400).json({
        success: false,
        message: 'Can only rate completed bookings'
      });
    }

    // Find or create rating
    let ratingDoc = await Rating.findOne({ bookingId });
    
    if (!ratingDoc) {
      ratingDoc = new Rating({
        bookingId,
        providerId: booking.providerId,
        customerId: booking.customerId,
        customerRating: rating,
        providerRated: true
      });
    } else {
      ratingDoc.customerRating = rating;
      ratingDoc.providerRated = true;
    }

    await ratingDoc.save();

    // Update booking rating status
    if (!booking.ratingStatus) {
      booking.ratingStatus = {
        customerRated: false,
        providerRated: false
      };
    }
    booking.ratingStatus.providerRated = true;
    await booking.save();

    console.log('✅ Provider rating submitted successfully for booking:', bookingId);

    res.json({
      success: true,
      message: 'Customer rating submitted successfully',
      data: { rating: ratingDoc }
    });

    // Create notification for CUSTOMER
    await Notification.createNotification({
      userId: booking.customerId,
      type: 'rating_received',
      title: 'New Rating Received',
      message: `You've received a ${rating} star rating from ${booking.providerName}`,
      relatedId: booking._id,
      relatedType: 'rating',
      roleContext: 'customer', // Only show to customer
      priority: 'low'
    });

    // Create notification for PROVIDER
    await Notification.createNotification({
      userId: req.user.id,
      type: 'rating_received',
      title: 'Rating Submitted',
      message: `You rated ${booking.customerName} ${rating} stars`,
      relatedId: booking._id,
      relatedType: 'rating',
      roleContext: 'provider', // Only show to provider
      priority: 'low'
    });

  } catch (error) {
    console.error('❌ Provider rating error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit customer rating',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


async function updateProviderRating(providerId) {
  try {
    const ratings = await Rating.find({ 
      providerId, 
      customerRated: true,
      providerRating: { $exists: true, $ne: null }
    });
    
    if (ratings.length > 0) {
      const averageRating = ratings.reduce((sum, rating) => sum + rating.providerRating, 0) / ratings.length;
      
      await User.findByIdAndUpdate(providerId, {
        averageRating: Math.round(averageRating * 10) / 10,
        reviewCount: ratings.length
      });

      console.log(`✅ Updated provider ${providerId} rating: ${averageRating.toFixed(1)} from ${ratings.length} reviews`);
    }
  } catch (error) {
    console.error('Error updating provider rating:', error);
  }
}

app.get('/api/provider/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const providerId = req.user.id;
    
    console.log('📊 Fetching provider stats for:', providerId);

    // Calculate total earnings from completed bookings
    const earningsResult = await Booking.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          status: 'completed'
        }
      },
      {
        $addFields: {
          // Extract numeric value from budget string (e.g., "₦15,000" -> 15000)
          numericBudget: {
            $convert: {
              input: {
                $replaceAll: {
                  input: {
                    $replaceAll: {
                      input: { 
                        $arrayElemAt: [
                          { 
                            $split: ["$budget", "₦"] 
                          }, 
                          1 
                        ] 
                      },
                      find: ",",
                      replacement: ""
                    }
                  },
                  find: " ",
                  replacement: ""
                }
              },
              to: "double",
              onError: 0,
              onNull: 0
            }
          }
        }
      },
      {
        $group: {
          _id: null,
          totalEarnings: { $sum: "$numericBudget" },
          jobsCompleted: { $sum: 1 }
        }
      }
    ]);

    console.log('💰 Earnings result:', earningsResult);

    // Count unique active clients (customers who have completed bookings in last 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);

    const activeClients = await Booking.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          status: 'completed',
          completedAt: { $gte: ninetyDaysAgo }
        }
      },
      {
        $group: {
          _id: "$customerId"
        }
      },
      {
        $count: "totalActiveClients"
      }
    ]);

    console.log('👥 Active clients result:', activeClients);

    // Get recent completed jobs (last 5)
    const recentJobs = await Booking.find({
      providerId: providerId,
      status: 'completed'
    })
    .sort({ completedAt: -1 })
    .limit(5)
    .populate('customerId', 'name email')
    .lean();

    console.log('📅 Recent jobs count:', recentJobs.length);

    // Get average rating
    const ratingStats = await Rating.aggregate([
      {
        $match: {
          providerId: new mongoose.Types.ObjectId(providerId),
          customerRated: true,
          providerRating: { $exists: true, $ne: null }
        }
      },
      {
        $group: {
          _id: null,
          averageRating: { $avg: "$providerRating" },
          totalRatings: { $sum: 1 }
        }
      }
    ]);

    console.log('⭐ Rating stats:', ratingStats);

    const stats = {
      totalEarnings: earningsResult.length > 0 ? earningsResult[0].totalEarnings : 0,
      activeClients: activeClients.length > 0 ? activeClients[0].totalActiveClients : 0,
      jobsCompleted: earningsResult.length > 0 ? earningsResult[0].jobsCompleted : 0,
      averageRating: ratingStats.length > 0 ? Math.round(ratingStats[0].averageRating * 10) / 10 : 0,
      totalRatings: ratingStats.length > 0 ? ratingStats[0].totalRatings : 0,
      recentJobs: recentJobs.map(job => ({
        id: job._id,
        serviceType: job.serviceType,
        customerName: job.customerId?.name || 'Unknown Customer',
        completedAt: job.completedAt,
        budget: job.budget,
        location: job.location
      }))
    };

    console.log('✅ Final stats:', stats);

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('❌ Dashboard stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard stats',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});


app.patch('/api/bookings/:id/complete', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;
    
    console.log('✅ Completing booking and removing from schedule:', bookingId);

    // Find and update booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify the user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to complete this booking'
      });
    }

    // Update booking status to completed
    booking.status = 'completed';
    booking.completedAt = new Date();
    await booking.save();

    // Remove from schedule
    try {
      const scheduleRemoval = await Schedule.findOneAndDelete({
        bookingId: booking._id
      });
      
      if (scheduleRemoval) {
        console.log('🗑️ Removed completed booking from schedule:', booking._id);
      } else {
        console.log('ℹ️ No schedule entry found for booking:', booking._id);
      }
    } catch (scheduleError) {
      console.error('⚠️ Schedule removal error (non-critical):', scheduleError);
    }

    console.log('📊 Booking marked as completed and removed from schedule');

    res.json({
      success: true,
      message: 'Booking marked as completed successfully and removed from schedule',
      data: booking
    });
  } catch (error) {
    console.error('❌ Complete booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete booking',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.post('/api/bookings/:id/complete', authenticateToken, async (req, res) => {
  try {
    const bookingId = req.params.id;
    
    console.log('🔄 Completing booking and updating dashboard:', bookingId);

    // Find the booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify the user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to complete this booking'
      });
    }

    // Extract numeric value from budget (e.g., "₦15,000" -> 15000)
    const extractBudgetAmount = (budget) => {
      if (!budget) return 0;
      const numericString = budget.replace(/[^\d.]/g, '');
      return parseFloat(numericString) || 0;
    };

    const earningsAmount = extractBudgetAmount(booking.budget);
    console.log('💰 Extracted earnings amount:', earningsAmount, 'from budget:', booking.budget);

    // Update provider stats
    const provider = await User.findById(booking.providerId);
    if (provider) {
      // Increment jobs completed
      provider.completedJobs = (provider.completedJobs || 0) + 1;
      
      // Add to total earnings
      provider.totalEarnings = (provider.totalEarnings || 0) + earningsAmount;
      
      // Add to active clients (unique customers)
      if (!provider.activeClients) {
        provider.activeClients = [];
      }
      
      const customerIdStr = booking.customerId.toString();
      if (!provider.activeClients.includes(customerIdStr)) {
        provider.activeClients.push(customerIdStr);
      }
      
      await provider.save();
      console.log('✅ Updated provider stats:', {
        completedJobs: provider.completedJobs,
        totalEarnings: provider.totalEarnings,
        activeClients: provider.activeClients.length
      });
    } else {
      console.log('❌ Provider not found:', booking.providerId);
    }

    res.json({
      success: true,
      message: 'Booking completed and dashboard updated successfully',
      data: {
        earningsAdded: earningsAmount,
        completedJobs: provider?.completedJobs,
        totalEarnings: provider?.totalEarnings,
        activeClients: provider?.activeClients?.length
      }
    });
  } catch (error) {
    console.error('❌ Complete booking error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to complete booking',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});




app.get('/api/client/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const clientId = req.user.id;
    
    console.log('📊 Fetching client stats for:', clientId);

    // Count completed jobs for this client
    const jobsCompleted = await Booking.countDocuments({
      customerId: clientId,
      status: 'completed'
    });

    // Get total spent
    const spendingResult = await Booking.aggregate([
      {
        $match: {
          customerId: new mongoose.Types.ObjectId(clientId),
          status: 'completed'
        }
      },
      {
        $addFields: {
          numericBudget: {
            $convert: {
              input: {
                $replaceAll: {
                  input: {
                    $replaceAll: {
                      input: { 
                        $arrayElemAt: [
                          { 
                            $split: ["$budget", "₦"] 
                          }, 
                          1 
                        ] 
                      },
                      find: ",",
                      replacement: ""
                    }
                  },
                  find: " ",
                  replacement: ""
                }
              },
              to: "double",
              onError: 0,
              onNull: 0
            }
          }
        }
      },
      {
        $group: {
          _id: null,
          totalSpent: { $sum: "$numericBudget" }
        }
      }
    ]);

    // Get recent completed jobs
    const recentJobs = await Booking.find({
      customerId: clientId,
      status: 'completed'
    })
    .sort({ completedAt: -1 })
    .limit(5)
    .populate('providerId', 'name email')
    .lean();

    const stats = {
      jobsCompleted: jobsCompleted,
      totalSpent: spendingResult.length > 0 ? spendingResult[0].totalSpent : 0,
      recentJobs: recentJobs.map(job => ({
        id: job._id,
        serviceType: job.serviceType,
        providerName: job.providerId?.name || 'Unknown Provider',
        completedAt: job.completedAt,
        budget: job.budget,
        location: job.location
      }))
    };

    console.log('✅ Client stats:', stats);

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('❌ Client dashboard stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch client dashboard stats',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});



app.post('/api/debug/test-booking-accepted-email', authenticateToken, async (req, res) => {
  try {
    const { customerEmail } = req.body;
    
    if (!customerEmail) {
      return res.status(400).json({
        success: false,
        message: 'Customer email is required'
      });
    }

    console.log('🧪 Testing booking acceptance email to:', customerEmail);

    const { sendBookingAcceptedNotificationToCustomer } = await import('./utils/emailService.js');
    
    const testBookingData = {
      customerName: 'Test Customer',
      serviceType: 'House Cleaning',
      location: 'Test Location, Lagos',
      timeframe: 'ASAP',
      budget: '₦15,000',
      description: 'Test booking description',
      specialRequests: 'Test special requests'
    };

    const testProviderInfo = {
      name: 'Test Provider',
      phone: '+234 123 456 7890',
      email: 'provider@example.com'
    };

    const result = await sendBookingAcceptedNotificationToCustomer(
      customerEmail,
      testBookingData,
      testProviderInfo
    );

    res.json({
      success: true,
      message: 'Booking acceptance email test completed',
      data: result
    });
  } catch (error) {
    console.error('Test booking acceptance email error:', error);
    res.status(500).json({
      success: false,
      message: 'Booking acceptance email test failed',
      error: error.message
    });
  }
});

// Add this endpoint to your server.js
app.delete('/api/schedule/booking/:bookingId', authenticateToken, async (req, res) => {
  try {
    const { bookingId } = req.params;
    const userId = req.user.id;

    console.log('🗑️ Removing schedule entry for booking:', bookingId);

    // Find and delete the schedule entry for this booking
    const result = await Schedule.findOneAndDelete({
      bookingId: bookingId,
      providerId: userId
    });

    if (!result) {
      console.log('📅 No schedule entry found for booking:', bookingId);
      return res.json({
        success: true,
        message: 'No schedule entry found to remove'
      });
    }

    console.log('✅ Schedule entry removed:', result._id);

    res.json({
      success: true,
      message: 'Booking removed from schedule successfully',
      data: { deletedScheduleId: result._id }
    });

  } catch (error) {
    console.error('❌ Remove from schedule error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to remove booking from schedule',
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
    console.log('📅 Adding booking to schedule:', booking._id);
    
    // Check if schedule entry already exists for this booking
    const existingSchedule = await Schedule.findOne({ bookingId: booking._id });
    if (existingSchedule) {
      console.log('📅 Schedule entry already exists for booking:', booking._id);
      return existingSchedule;
    }

    // Calculate end time based on service type
    const calculateEndTime = (startTime, serviceType) => {
      const [time, modifier] = startTime.split(' ');
      let [hours, minutes] = time.split(':').map(Number);
      
      if (modifier === 'PM' && hours !== 12) hours += 12;
      if (modifier === 'AM' && hours === 12) hours = 0;
      
      // Add duration based on service type
      let durationHours = 2; // default 2 hours
      if (serviceType.includes('Cleaning')) durationHours = 3;
      if (serviceType.includes('Maintenance')) durationHours = 4;
      if (serviceType.includes('Repair')) durationHours = 2;
      
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
    let scheduleTime = '10:00 AM'; // Default time
    
    if (booking.timeframe.toLowerCase().includes('tomorrow')) {
      scheduleDate.setDate(scheduleDate.getDate() + 1);
    } else if (booking.timeframe.toLowerCase().includes('next week')) {
      scheduleDate.setDate(scheduleDate.getDate() + 7);
    } else if (booking.timeframe.toLowerCase().includes('today')) {
      // Use today's date
    } else {
      // Try to parse specific date from timeframe
      const dateMatch = booking.timeframe.match(/\d{1,2}\/\d{1,2}\/\d{4}/);
      if (dateMatch) {
        scheduleDate = new Date(dateMatch[0]);
      }
    }

    // Create schedule data with ALL required fields
    const scheduleData = {
      title: booking.serviceType,
      client: booking.customerName || 'Unknown Client',
      phone: booking.customerPhone || 'Not provided',
      location: booking.location || 'Location not specified',
      date: scheduleDate.toISOString().split('T')[0], // YYYY-MM-DD format
      time: scheduleTime,
      endTime: calculateEndTime(scheduleTime, booking.serviceType),
      duration: '2 hours',
      payment: booking.budget || 'Not specified',
      status: 'confirmed', // FIXED: Use valid enum value
      notes: booking.specialRequests || booking.description || '',
      category: booking.serviceType.toLowerCase().includes('clean') ? 'cleaning' : 
               booking.serviceType.toLowerCase().includes('garden') ? 'gardening' : 'handyman',
      priority: 'medium',
      
      // REQUIRED FIELDS - ensure these are properly set
      providerId: booking.providerId,
      customerId: booking.customerId,
      bookingId: booking._id
    };

    console.log('📋 Final schedule data:', scheduleData);

    const newSchedule = new Schedule(scheduleData);
    await newSchedule.save();
    
    console.log('✅ Booking added to schedule successfully:', newSchedule._id);
    return newSchedule;
  } catch (error) {
    console.error('❌ Error adding booking to schedule:', error);
    throw error;
  }
}



app.get('/api/debug/schedule', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const scheduleEntries = await Schedule.find({ providerId: userId })
      .populate('customerId', 'name email')
      .populate('providerId', 'name email')
      .populate('bookingId', 'serviceType status timeframe');
    
    res.json({
      success: true,
      data: {
        count: scheduleEntries.length,
        schedule: scheduleEntries
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});


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
        exists: true,
        customerId: booking.customerId,
        currentUserId: req.user.id,
        isAuthorized: booking.customerId.toString() === req.user.id
      }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
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
    
    // Get current user role from path or user data
    const userRole = req.path.includes('/provider/') ? 'provider' : 'customer';
    
    const options = {
      page,
      limit,
      unreadOnly
    };

    const result = await Notification.getNotificationsByRole(req.user.id, userRole, options);

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
    // Get current user role from path or user data
    const userRole = req.path.includes('/provider/') ? 'provider' : 'customer';
    
    const count = await Notification.getUnreadCountByRole(req.user.id, userRole);

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
    const userRole = req.path.includes('/provider/') ? 'provider' : 'customer';
    
    await Notification.updateMany(
      { 
        userId: req.user.id,
        isRead: false,
        $or: [
          { roleContext: 'both' },
          { roleContext: userRole }
        ]
      },
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




app.patch('/api/jobs/:id/accept', authenticateToken, async (req, res) => {
  try {
    const job = await ServiceRequest.findById(req.params.id);
    
    // Update job status to accepted
    job.status = 'accepted';
    job.providerId = req.user.id; // or the provider who applied
    await job.save();

    // Create notification for the provider who applied
    await Notification.createNotification({
      userId: job.providerId,
      type: 'job_accepted',
      title: 'Job Application Accepted!',
      message: `Your application for ${job.serviceType} has been accepted`,
      relatedId: job._id,
      relatedType: 'job',
      roleContext: 'provider', // Only show to provider
      priority: 'high'
    });

    await Notification.createNotification({
      userId: job.customerId,
      type: 'job_accepted',
      title: 'Provider Hired',
      message: `You hired a provider for your ${job.serviceType} job`,
      relatedId: job._id,
      relatedType: 'job',
      roleContext: 'customer', // Only show to customer
      priority: 'medium'
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

    await Notification.createNotification({
      userId: req.user.id,
      type: 'job_posted',
      title: 'Job Posted Successfully',
      message: `Your ${serviceType} job has been posted and is now visible to providers`,
      relatedId: savedRequest._id,
      relatedType: 'job',
      roleContext: 'customer', // Only show to customer
      priority: 'medium'
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

    console.log('📊 Fetching service requests for customer:', req.user.id);

    let filter = { customerId: req.user.id };
    
    if (status && status !== 'all') {
      filter.status = status;
    }

    const options = {
      page,
      limit,
      sort: { createdAt: -1 },
      populate: [
        { 
          path: 'customerId', 
          select: 'name email phoneNumber profileImage' 
        },
        { 
          path: 'proposals.providerId', 
          select: 'name email profileImage' 
        }
      ],
      lean: true // Use lean for better performance
    };

    // Use ServiceRequest model to fetch jobs
    const result = await ServiceRequest.paginate(filter, options);

    console.log('✅ Found', result.docs.length, 'service requests for customer');

    // Add cache control headers to prevent 304 responses
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Debug: Check for missing _id
    const jobsWithMissingId = result.docs.filter(job => !job._id);
    if (jobsWithMissingId.length > 0) {
      console.error('❌ Found jobs with missing _id:', jobsWithMissingId.length);
      console.error('Sample job without _id:', jobsWithMissingId[0]);
    }

    // Ensure all jobs have _id
    const safeJobs = result.docs.map(job => {
      if (!job._id) {
        console.warn('⚠️ Job without _id found, generating temporary ID:', {
          serviceType: job.serviceType,
          description: job.description?.substring(0, 50)
        });
        // Generate a temporary ID for jobs without _id
        job._id = `temp-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
        job.id = job._id;
      }
      return job;
    });

    res.json({
      success: true,
      data: {
        jobs: safeJobs,
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
    console.error('❌ Get customer service requests error:', error);
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

app.post('/api/service-requests/:jobId/proposals/:proposalId/accept', authenticateToken, async (req, res) => {
  try {
    const { jobId, proposalId } = req.params;
    const userId = req.user.id;

    console.log('🔄 Accepting proposal:', { jobId, proposalId, userId });

    // Validate IDs
    if (!jobId || !mongoose.Types.ObjectId.isValid(jobId) || 
        !proposalId || !mongoose.Types.ObjectId.isValid(proposalId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid job ID and proposal ID are required'
      });
    }

    const serviceRequest = await ServiceRequest.findById(jobId);
    if (!serviceRequest) {
      return res.status(404).json({
        success: false,
        message: 'Service request not found'
      });
    }

    // Check if user owns the service request
    if (serviceRequest.customerId.toString() !== userId) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to accept proposals for this job'
      });
    }

    // Find the proposal
    const proposal = serviceRequest.proposals.id(proposalId);
    if (!proposal) {
      return res.status(404).json({
        success: false,
        message: 'Proposal not found'
      });
    }

    // Check if already accepted
    if (proposal.status === 'accepted') {
      return res.json({
        success: true,
        message: 'Proposal was already accepted',
        data: {
          serviceRequestId: serviceRequest._id,
          proposalId: proposal._id,
          providerId: proposal.providerId,
          alreadyAccepted: true
        }
      });
    }

    // Accept the proposal
    proposal.status = 'accepted';
    proposal.acceptedAt = new Date();
    
    // Update service request
    serviceRequest.status = 'accepted';
    serviceRequest.providerId = proposal.providerId;
    serviceRequest.acceptedAt = new Date();
    serviceRequest.acceptedProposalId = proposal._id;

    // Disable refunds once a proposal is accepted
    serviceRequest.canRefund = false;

    // Reject other proposals
    serviceRequest.proposals.forEach(p => {
      if (p._id.toString() !== proposalId && p.status === 'pending') {
        p.status = 'rejected';
      }
    });

    await serviceRequest.save();

    console.log('✅ Proposal accepted successfully:', {
      proposalId: proposal._id,
      providerId: proposal.providerId,
      newStatus: serviceRequest.status
    });

    // Send notification to provider
    try {
      await Notification.createNotification({
        userId: proposal.providerId,
        type: 'proposal_accepted',
        title: 'Proposal Accepted! 🎉',
        message: `Your proposal for "${serviceRequest.serviceType}" has been accepted! Contact the customer to schedule the service.`,
        relatedId: serviceRequest._id,
        relatedType: 'job',
        priority: 'high'
      });

      // Also notify customer
      await Notification.createNotification({
        userId: serviceRequest.customerId,
        type: 'proposal_accepted',
        title: 'Proposal Accepted',
        message: `You have accepted ${user.name}'s proposal. They will contact you soon.`,
        relatedId: serviceRequest._id,
        relatedType: 'job',
        priority: 'medium'
      });
    } catch (notifError) {
      console.error('❌ Notification error:', notifError);
    }

    res.json({
      success: true,
      message: 'Proposal accepted successfully! The provider has been notified.',
      data: {
        serviceRequestId: serviceRequest._id,
        proposalId: proposal._id,
        providerId: proposal.providerId,
        newStatus: serviceRequest.status
      }
    });

  } catch (error) {
    console.error('❌ Accept proposal error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to accept proposal',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
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
    const bcrypt = await import('bcryptjs');
    const hashedPassword = await bcrypt.hash('test123', 10);
    
    const testUser = new User({
      name: 'Test User',
      email: 'test@example.com',
      password: hashedPassword,
      userType: 'customer',
      country: 'NIGERIA',
      isEmailVerified: true,
      isActive: true
    });
    
    await testUser.save();
    
    res.json({
      success: true,
      message: 'Test user created',
      data: {
        email: 'test@example.com',
        password: 'test123'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
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

// Add this to your server.js
app.post('/api/debug/test-email-production', async (req, res) => {
  try {
    const { email } = req.body;
    
    console.log('🧪 Testing production email to:', email);
    console.log('🔧 Mailjet config:', {
      hasApiKey: !!process.env.MAILJET_API_KEY,
      hasSecret: !!process.env.MAILJET_SECRET_KEY,
      frontendUrl: process.env.FRONTEND_URL
    });

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Test with a simple verification token
    const testToken = 'test123';
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${testToken}&email=${encodeURIComponent(email)}`;
    
    console.log('🔗 Would send verification link:', verificationUrl);

    res.json({
      success: true,
      message: 'Email test completed',
      data: {
        debugLink: verificationUrl,
        mailjetConfigured: !!(process.env.MAILJET_API_KEY && process.env.MAILJET_SECRET_KEY),
        environment: process.env.NODE_ENV
      }
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({
      success: false,
      message: 'Test failed',
      error: error.message
    });
  }
});

app.get('/api/debug/email-config-full', (req, res) => {
  res.json({
    success: true,
    data: {
      domain: 'homeheroes.help',
      status: 'Pending DNS validation',
      currentSender: 'noreply@homeheroes.help',
      verifiedSender: 'techbursterdev@gmail.com',
      dnsRecordsNeeded: [
        {
          type: 'TXT',
          host: 'mailjet._d390662c',
          value: 'd390662cce7b923f40237ebf4f7fc678',
          purpose: 'Domain validation'
        },
        {
          type: 'TXT', 
          host: '@',
          value: 'v=spf1 include:spf.mailjet.com ~all',
          purpose: 'SPF authentication'
        }
      ],
      immediateAction: 'Add TXT record to DNS and change sender to techbursterdev@gmail.com temporarily'
    }
  });
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

app.post('/api/bookings/:id/rating-prompt', authenticateToken, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    
    if (!booking) {
      return res.status(404).json({
        success: false,
        message: 'Booking not found'
      });
    }

    // Verify the user is the provider for this booking
    if (booking.providerId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to trigger rating prompt for this booking'
      });
    }

    // Set flag to prompt customer for rating
    booking.ratingPrompted = true;
    await booking.save();

    // Send email notification to customer to rate the provider
    try {
      const { sendRatingPromptToCustomer } = await import('./utils/emailService.js');
      await sendRatingPromptToCustomer(booking);
    } catch (emailError) {
      console.error('Failed to send rating prompt email:', emailError);
      // Continue even if email fails
    }

    console.log('✅ Rating prompt triggered for customer:', booking.customerEmail);

    res.json({
      success: true,
      message: 'Customer rating prompt sent successfully'
    });
  } catch (error) {
    console.error('❌ Rating prompt error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send rating prompt',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

app.get('/api/reviews', async (req, res) => {
  try {
    const { providerId, page = 1, limit = 10 } = req.query;

    let filter = {};
    if (providerId) {
      filter.providerId = providerId;
    }

    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: { ratedAt: -1 },
      populate: [
        { path: 'customerId', select: 'name profileImage' },
        { path: 'providerId', select: 'name profileImage' }
      ]
    };

    const result = await Rating.paginate(filter, options);

    res.json({
      success: true,
      data: {
        reviews: result.docs,
        totalDocs: result.totalDocs,
        totalPages: result.totalPages,
        page: result.page
      }
    });
  } catch (error) {
    console.error('Get reviews error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch reviews'
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
// app.use('/api/*', (req, res) => {
//   res.status(404).json({
//     success: false,
//     message: 'API endpoint not found'
//   });
// });

// ==================== STATIC FILES (PRODUCTION ONLY) ====================

// Static files (only in production)
// if (process.env.NODE_ENV === 'production') {
//   app.use(express.static(path.join(__dirname, 'client/dist')));
// }

// Catch-all handler for SPA (only in production)
// if (process.env.NODE_ENV === 'production') {
//   app.get('*', (req, res) => {
//     res.sendFile(path.join(__dirname, 'client/dist', 'index.html'));
//   });
// }

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'HomeHero API Server',
    version: '2.0.0',
    environment: process.env.NODE_ENV,
    endpoints: {
      docs: 'https://github.com/your-repo/docs',
      health: '/api/health',
      auth: '/api/auth'
    }
  });
});

app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // No content
});

// API 404 handler
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    requestedUrl: req.originalUrl
  });
});


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








// app.use(cors({
//   origin: function (origin, callback) {
//     if (!origin) return callback(null, true);
//     if (process.env.NODE_ENV !== 'production') return callback(null, true);
//     if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    
//     console.warn('CORS blocked origin:', origin);
//     return callback(new Error('Not allowed by CORS'), false);
//   },
//   credentials: true
// }));

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
      message: 'API endpoint not found: ' + req.originalUrl
    });
  }
  
  // For non-API routes, return API info
  res.json({
    success: false,
    message: 'This is an API server. Please use API endpoints.',
    baseUrl: '/api',
    example: '/api/health'
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
  console.log(`HomeHero API server running on port ${PORT}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/api/health`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
}).on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
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