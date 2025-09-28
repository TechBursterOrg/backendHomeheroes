import mongoose from 'mongoose';

const verificationTokenSchema = new mongoose.Schema({
  phoneNumber: {
    type: String,
    required: true,
    trim: true
  },
  country: {
    type: String,
    required: true,
    enum: ['NIGERIA', 'UK', 'USA', 'CANADA']
  },
  token: {
    type: String,
    required: true
  },
  verified: {
    type: Boolean,
    default: false
  },
  verifiedAt: {
    type: Date
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 } // TTL index for automatic deletion
  },
  attempts: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Compound index for faster queries
verificationTokenSchema.index({ phoneNumber: 1, country: 1 });
verificationTokenSchema.index({ expiresAt: 1 });

// Static method to verify token
verificationTokenSchema.statics.verifyToken = async function(phoneNumber, country, token) {
  const verification = await this.findOne({
    phoneNumber,
    country,
    token,
    expiresAt: { $gt: new Date() },
    verified: false
  });

  if (!verification) {
    return null;
  }

  // Increment attempts
  verification.attempts += 1;
  
  if (verification.attempts >= 5) {
    // Too many attempts, invalidate token
    verification.expiresAt = new Date();
    await verification.save();
    return null;
  }

  await verification.save();
  return verification;
};

const VerificationToken = mongoose.model('VerificationToken', verificationTokenSchema);

export default VerificationToken;