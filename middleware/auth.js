import jwt from 'jsonwebtoken';
import User from '../models/User.js';

// Authentication middleware
export async function authenticateToken(req, res, next) { // ✅ Added async
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
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
    console.error('JWT verification error:', error);
    return res.status(403).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
}

// Optional: Role-based authentication
export function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const userRoles = Array.isArray(roles) ? roles : [roles];
    
    if (!userRoles.includes(req.user.userType) && !userRoles.includes(req.user.actualUserType)) {
      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
}