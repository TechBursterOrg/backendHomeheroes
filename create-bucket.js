// create-bucket.js
import { Storage } from '@google-cloud/storage';

const storage = new Storage({
  keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
  projectId: process.env.GCLOUD_PROJECT_ID
});

async function createBucket() {
  try {
    const bucketName = 'homehero-gallery';
    
    // Check if bucket exists
    const [buckets] = await storage.getBuckets();
    const bucketExists = buckets.some(bucket => bucket.name === bucketName);
    
    if (!bucketExists) {
      // Create the bucket
      await storage.createBucket(bucketName);
      console.log(`✅ Bucket ${bucketName} created successfully.`);
    } else {
      console.log(`✅ Bucket ${bucketName} already exists.`);
    }
    
    // Configure bucket for public access
    const bucket = storage.bucket(bucketName);
    
    // Set uniform bucket-level access
    await bucket.setMetadata({
      iamConfiguration: {
        uniformBucketLevelAccess: {
          enabled: true,
        },
      },
    });
    
    console.log('✅ Bucket configured for uniform access.');
    
  } catch (error) {
    console.error('❌ Error creating bucket:', error);
  }
}

createBucket();