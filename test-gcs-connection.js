const { Storage } = require('@google-cloud/storage');

console.log('🔧 Testing Google Cloud Storage connection...');

const storage = new Storage({
  keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
  projectId: process.env.GCLOUD_PROJECT_ID
});

async function testConnection() {
  try {
    console.log('1. Testing authentication...');
    
    // Test authentication by making a simple API call
    const [buckets] = await storage.getBuckets();
    
    console.log('✅ Authentication successful!');
    console.log(`📦 Found ${buckets.length} buckets in project`);
    
    buckets.forEach(bucket => {
      console.log(`   - ${bucket.name}`);
    });
    
    // Check if our target bucket exists
    const targetBucket = 'homehero-gallery';
    const bucketExists = buckets.some(b => b.name === targetBucket);
    
    if (bucketExists) {
      console.log(`✅ Bucket "${targetBucket}" exists`);
    } else {
      console.log(`❌ Bucket "${targetBucket}" does not exist`);
      console.log('💡 Please create it manually in Google Cloud Console');
    }
    
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    
    if (error.message.includes('invalid_grant')) {
      console.log('\n🔍 Possible solutions:');
      console.log('   1. Service account might be disabled');
      console.log('   2. Service account might not have proper permissions');
      console.log('   3. The key file might be corrupted');
      console.log('   4. The project might not have Storage API enabled');
    }
  }
}

testConnection();