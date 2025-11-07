// gcs-fix.js - Run this to fix GCS configuration
import { Storage } from '@google-cloud/storage';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function fixGCSConfiguration() {
  try {
    console.log('🔧 Fixing Google Cloud Storage Configuration...');
    
    // Configuration
    const config = {
      projectId: 'decent-carving-474920-v0',
      bucketName: 'home-heroes-bucket',
      keyFilePath: process.env.GOOGLE_APPLICATION_CREDENTIALS
    };

    console.log('📋 Configuration:', config);

    // Initialize storage with explicit configuration
    const storage = new Storage({
      keyFilename: config.keyFilePath,
      projectId: config.projectId
    });

    // Test authentication
    console.log('🔐 Testing authentication...');
    const [serviceAccount] = await storage.getServiceAccount();
    console.log('✅ Service Account:', serviceAccount.emailAddress);

    // Test bucket access
    console.log('📦 Testing bucket access...');
    const bucket = storage.bucket(config.bucketName);
    const [exists] = await bucket.exists();
    
    if (!exists) {
      throw new Error(`Bucket ${config.bucketName} does not exist`);
    }
    console.log('✅ Bucket exists:', config.bucketName);

    // Test bucket permissions
    console.log('🔑 Testing bucket permissions...');
    const [metadata] = await bucket.getMetadata();
    console.log('✅ Bucket metadata access successful');
    console.log('📍 Bucket location:', metadata.location);
    console.log('📊 Storage class:', metadata.storageClass);

    // Test file upload
    console.log('📤 Testing file upload...');
    const testFileName = `test-${Date.now()}.txt`;
    const testFile = bucket.file(testFileName);
    
    await testFile.save('Test content for GCS configuration', {
      metadata: {
        contentType: 'text/plain',
      },
    });
    console.log('✅ File upload test successful');

    // Test making file public
    console.log('🌐 Testing public access...');
    await testFile.makePublic();
    console.log('✅ File public access test successful');

    // Test file deletion
    await testFile.delete();
    console.log('✅ File deletion test successful');

    console.log('🎉 All GCS tests passed! Configuration is correct.');

    return {
      success: true,
      projectId: config.projectId,
      bucketName: config.bucketName,
      serviceAccount: serviceAccount.emailAddress
    };

  } catch (error) {
    console.error('❌ GCS configuration error:', error.message);
    
    // Provide specific solutions based on error type
    if (error.message.includes('invalid_grant')) {
      console.log('💡 SOLUTION: Service account key is invalid or expired.');
      console.log('   1. Generate a new service account key in Google Cloud Console');
      console.log('   2. Download the new JSON key file');
      console.log('   3. Update GOOGLE_APPLICATION_CREDENTIALS environment variable');
    } else if (error.message.includes('Bucket does not exist')) {
      console.log('💡 SOLUTION: Bucket does not exist in this project.');
      console.log('   1. Create bucket in Google Cloud Console');
      console.log('   2. Or use an existing bucket name');
    } else if (error.message.includes('Permission denied')) {
      console.log('💡 SOLUTION: Service account lacks permissions.');
      console.log('   1. Go to Google Cloud Console → IAM & Admin');
      console.log('   2. Find your service account email');
      console.log('   3. Add "Storage Admin" role');
    }
    
    return {
      success: false,
      error: error.message
    };
  }
}

// Run the fix
fixGCSConfiguration();