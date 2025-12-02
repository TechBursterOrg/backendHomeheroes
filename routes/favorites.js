// In your routes/favorites.js or wherever you have the favorites route:

import express from 'express';
import User from '../models/User.js';
import { authenticateToken } from '../middleware/auth.js';
import cors from 'cors';

const router = express.Router();

// Enable CORS for favorites routes
router.use(cors({
  origin: function (origin, callback) {
    // Allow all origins for now, or specify your frontend origins
    callback(null, true);
  },
  credentials: true
}));

// Handle OPTIONS preflight request
router.options('/:providerId/favorite', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

// POST - Add/Remove provider from favorites
router.post('/:providerId/favorite', authenticateToken, async (req, res) => {
  try {
    const { providerId } = req.params;
    const userId = req.user.id;
    
    console.log(`⭐ Favorite request - User: ${userId}, Provider: ${providerId}`);
    
    // Set CORS headers
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    // Check if already in favorites
    const existingIndex = user.favorites.findIndex(fav => 
      fav.providerId && fav.providerId.toString() === providerId
    );
    
    if (existingIndex >= 0) {
      // Remove from favorites
      user.favorites.splice(existingIndex, 1);
      await user.save();
      
      console.log(`✅ Removed provider ${providerId} from favorites for user ${user.email}`);
      
      return res.json({
        success: true,
        message: 'Removed from favorites',
        data: { 
          isFavorite: false, 
          favorites: user.favorites 
        }
      });
    } else {
      // Add to favorites
      user.favorites.push({
        providerId: providerId,
        addedAt: new Date()
      });
      await user.save();
      
      console.log(`✅ Added provider ${providerId} to favorites for user ${user.email}`);
      
      return res.json({
        success: true,
        message: 'Added to favorites',
        data: { 
          isFavorite: true, 
          favorites: user.favorites 
        }
      });
    }
  } catch (error) {
    console.error('❌ Error toggling favorite:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update favorites' 
    });
  }
});

// GET - Get user's favorite providers
router.get('/', authenticateToken, async (req, res) => {
  try {
    // Set CORS headers
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    const user = await User.findById(req.user.id)
      .populate('favorites.providerId', 'name email services hourlyRate city state country profileImage isAvailableNow experience rating reviewCount phoneNumber address completedJobs isVerified isTopRated responseTime');
    
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    
    console.log(`📋 Retrieved ${user.favorites.length} favorites for user ${user.email}`);
    
    res.json({
      success: true,
      data: {
        favorites: user.favorites || []
      }
    });
  } catch (error) {
    console.error('❌ Error fetching favorites:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch favorites' 
    });
  }
});

export default router;