import express from 'express';
import path from 'path';
import Gallery from '../models/Gallery.js';
import { fileURLToPath } from 'url';
import fs from 'fs';
import { authenticateToken } from '../middleware/auth.js';
import multer from 'multer';

const router = express.Router();

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Get the project root directory (one level up from routes)
const projectRoot = path.join(__dirname, '..');

// Configure multer for file uploads with absolute path
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Use absolute path to avoid any relative path issues
    const uploadDir = path.join(projectRoot, 'uploads', 'gallery');
    console.log('Upload directory absolute path:', uploadDir);
    
    try {
      // Create directory if it doesn't exist with proper permissions
      if (!fs.existsSync(uploadDir)) {
        console.log('Creating upload directory:', uploadDir);
        fs.mkdirSync(uploadDir, { recursive: true, mode: 0o755 });
        console.log('Directory created successfully');
      }
      
      cb(null, uploadDir);
    } catch (error) {
      console.error('Error accessing upload directory:', error.message);
      cb(new Error(`Cannot access upload directory: ${error.message}`), null);
    }
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    // Sanitize filename
    const originalName = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const safeFilename = `gallery-${uniqueSuffix}${path.extname(originalName)}`;
    cb(null, safeFilename);
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: fileFilter
});

// Upload new gallery image
// Add more detailed error logging
router.post('/', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    console.log('=== GALLERY UPLOAD REQUEST ===');
    console.log('User:', req.user.id);
    console.log('File received:', req.file ? `Yes - ${req.file.originalname}` : 'No');
    console.log('File details:', req.file);
    console.log('Request body:', req.body);
    console.log('Request headers:', req.headers['content-type']);
    
    if (!req.file) {
      console.log('ERROR: No file uploaded');
      return res.status(400).json({
        success: false,
        message: 'No image file provided. Please select an image to upload.'
      });
    }

    // Validate file type
    if (!req.file.mimetype.startsWith('image/')) {
      // Clean up uploaded file
      if (req.file.path && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({
        success: false,
        message: 'Only image files are allowed (jpg, png, gif, etc.)'
      });
    }

    const { title, description, category, tags, featured } = req.body;
    
    // Validate required fields with better error messages
    if (!title || !title.trim()) {
      // Clean up uploaded file
      if (req.file.path && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({
        success: false,
        message: 'Title is required'
      });
    }

    // Validate category
    const validCategories = ['cleaning', 'handyman', 'gardening', 'other'];
    if (category && !validCategories.includes(category)) {
      if (req.file.path && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({
        success: false,
        message: `Invalid category. Must be one of: ${validCategories.join(', ')}`
      });
    }

    // Create image URL relative to server
    const imageUrl = `/uploads/gallery/${req.file.filename}`;

    // Create gallery entry
    const newImage = new Gallery({
      title: title.trim(),
      description: description ? description.trim() : '',
      category: category || 'other',
      imageUrl,
      userId: req.user.id,
      tags: tags ? tags.split(',').map(tag => tag.trim()).filter(tag => tag) : [],
      featured: featured === 'true' || featured === true
    });

    // Save to database
    const savedImage = await newImage.save();
    await savedImage.populate('userId', 'name profileImage');

    console.log('Image uploaded successfully:', savedImage._id);

    res.status(201).json({
      success: true,
      message: 'Image uploaded successfully',
      data: savedImage
    });
    
  } catch (error) {
    console.error('Gallery upload error:', error);
    
    // Clean up uploaded file on error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('Cleaned up uploaded file due to error');
      } catch (cleanupError) {
        console.error('Error cleaning up file:', cleanupError);
      }
    }
    
    let errorMessage = 'Failed to upload image';
    let statusCode = 500;
    
    if (error.name === 'ValidationError') {
      errorMessage = 'Invalid data: ' + Object.values(error.errors).map(e => e.message).join(', ');
      statusCode = 400;
    }
    
    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      ...(process.env.NODE_ENV === 'development' && { 
        error: error.message,
        stack: error.stack 
      })
    });
  }
});

// Get all gallery images
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const category = req.query.category;
    const search = req.query.search;

    let filter = {};
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

    res.json({
      success: true,
      data: {
        docs: result.docs,
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

// Get single image
router.get('/:id', async (req, res) => {
  try {
    const image = await Gallery.findById(req.params.id)
      .populate('userId', 'name profileImage');
    
    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }

    // Increment view count
    image.views = (image.views || 0) + 1;
    await image.save();

    res.json({
      success: true,
      data: image
    });
  } catch (error) {
    console.error('Get image error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch image'
    });
  }
});

// Like an image
router.post('/:id/like', authenticateToken, async (req, res) => {
  try {
    const image = await Gallery.findById(req.params.id);
    
    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
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

export default router;