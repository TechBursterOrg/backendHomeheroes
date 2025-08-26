import mongoose from 'mongoose';

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/homehero';
    
    const conn = await mongoose.connect(mongoURI, {
      // MongoDB connection options
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      maxPoolSize: 10, // Maintain up to 10 socket connections
      bufferMaxEntries: 0, // Disable mongoose buffering
      bufferCommands: false, // Disable mongoose buffering
    });

    console.log(`🍃 MongoDB connected: ${conn.connection.host}`);
    console.log(`📊 Database: ${conn.connection.name}`);
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ MongoDB disconnected');
    });
    
    // Handle app termination
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('🔒 MongoDB connection closed through app termination');
        process.exit(0);
      } catch (error) {
        console.error('Error closing MongoDB connection:', error);
        process.exit(1);
      }
    });
    
    return conn;
  } catch (error) {
    console.error('❌ Error connecting to MongoDB:', error.message);
    
    // Provide helpful error messages
    if (error.message.includes('ECONNREFUSED')) {
      console.log('💡 Make sure MongoDB is running on your system');
      console.log('💡 Start MongoDB with: brew services start mongodb/brew/mongodb-community');
      console.log('💡 Or install MongoDB: https://docs.mongodb.com/manual/installation/');
    }
    
    if (error.message.includes('authentication failed')) {
      console.log('💡 Check your MongoDB credentials in the connection string');
    }
    
    process.exit(1);
  }
};

export default connectDB;