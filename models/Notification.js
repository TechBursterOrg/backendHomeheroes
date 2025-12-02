// models/Notification.js
import mongoose from 'mongoose';
import mongoosePaginate from 'mongoose-paginate-v2';

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  type: {
    type: String,
    enum: ['message', 'booking', 'job_accepted', 'job_applied', 'job_posted', 'rating_received', 'booking_request', 'system','proposal_received', 'proposal_accepted','job_started','job_completed','payment_received','message_received','booking_confirmed','booking_cancelled','review_received',],
    required: true
  },
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  relatedId: {
    type: mongoose.Schema.Types.ObjectId,
    // Can reference different models
    required: false
  },
  relatedType: {
    type: String,
    enum: ['conversation', 'booking', 'job', 'user', 'rating'],
    required: false
  },
  roleContext: {
    type: String,
    enum: ['customer', 'provider', 'both'],
    default: 'both',
    required: true
  },
  isRead: {
    type: Boolean,
    default: false
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  metadata: {
    type: Object,
    default: {}
  }
}, {
  timestamps: true
});

notificationSchema.plugin(mongoosePaginate);

// Static method to create notifications with role context
notificationSchema.statics.createNotification = async function(notificationData) {
  try {
    const notification = new this(notificationData);
    await notification.save();
    
    // Emit real-time event (for WebSocket implementation)
    if (global.io) {
      global.io.to(notificationData.userId.toString()).emit('new_notification', notification);
    }
    
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
    throw error;
  }
};

// Method to get notifications filtered by role context
notificationSchema.statics.getNotificationsByRole = async function(userId, userRole, options = {}) {
  try {
    const { page = 1, limit = 20, unreadOnly = false } = options;
    
    let filter = { 
      userId,
      $or: [
        { roleContext: 'both' },
        { roleContext: userRole }
      ]
    };
    
    if (unreadOnly) {
      filter.isRead = false;
    }

    const result = await this.paginate(filter, {
      page,
      limit,
      sort: { createdAt: -1 }
    });

    return result;
  } catch (error) {
    console.error('Error getting notifications by role:', error);
    throw error;
  }
};

// Method to get unread count by role
notificationSchema.statics.getUnreadCountByRole = async function(userId, userRole) {
  try {
    const count = await this.countDocuments({
      userId,
      isRead: false,
      $or: [
        { roleContext: 'both' },
        { roleContext: userRole }
      ]
    });
    
    return count;
  } catch (error) {
    console.error('Error getting unread count by role:', error);
    throw error;
  }
};

export default mongoose.model('Notification', notificationSchema);