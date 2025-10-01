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
    enum: ['message', 'booking', 'job_accepted', 'job_applied', 'system'],
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
    enum: ['conversation', 'booking', 'job', 'user'],
    required: false
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

// Static method to create notifications
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

export default mongoose.model('Notification', notificationSchema);