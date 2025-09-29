import axios from 'axios';
import User from '../models/User.js';

const VerificationController = {
  async verifyNINWithDojah(req, res) {
    try {
      const { nin } = req.body;

      // Validate required fields
      if (!nin) {
        return res.status(400).json({
          success: false,
          message: 'NIN is required'
        });
      }

      // Validate NIN format
      if (nin.length !== 11 || !/^\d+$/.test(nin)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid NIN format. Must be 11 digits.'
        });
      }

      console.log('🔐 Starting Dojah NIN verification for:', nin);

      // Call Dojah API for NIN verification
      const dojahResponse = await axios.get(
        `https://api.dojah.io/api/v1/kyc/nin`,
        {
          params: {
            nin: nin
          },
          headers: {
            'Authorization': process.env.DOJAH_APP_ID,
            'AppId': process.env.DOJAH_APP_ID,
            'Content-Type': 'application/json'
          },
          timeout: 30000 // 30 second timeout
        }
      );

      console.log('📊 Dojah API Response:', dojahResponse.data);

      // Check if verification was successful
      if (dojahResponse.data.entity) {
        const ninData = dojahResponse.data.entity;

        // Prepare verification data
        const verificationData = {
          nin: nin,
          isNinVerified: true,
          verificationStatus: 'verified',
          verificationDate: new Date(),
          provider: 'dojah',
          verificationDetails: {
            fullName: ninData.firstname + ' ' + ninData.lastname,
            firstName: ninData.firstname,
            lastName: ninData.lastname,
            middleName: ninData.middlename,
            gender: ninData.gender,
            birthDate: ninData.birthdate,
            phone: ninData.telephoneno,
            state: ninData.state,
            lga: ninData.lga,
            nin: ninData.nin,
            photo: ninData.photo, // Base64 photo from NIN
          }
        };

        // Update user in database
        const updatedUser = await User.findByIdAndUpdate(
          req.user.id,
          {
            identityVerification: verificationData,
            isIdentityVerified: true,
            verificationSubmittedAt: new Date()
          },
          { new: true }
        ).select('-password');

        console.log('✅ User NIN verification completed:', updatedUser._id);

        return res.json({
          success: true,
          message: 'NIN verified successfully!',
          data: {
            isNinVerified: true,
            verificationStatus: 'verified',
            full_name: ninData.firstname + ' ' + ninData.lastname,
            firstname: ninData.firstname,
            lastname: ninData.lastname,
            gender: ninData.gender,
            state: ninData.state,
            birthdate: ninData.birthdate
          }
        });

      } else {
        console.log('❌ NIN verification failed:', dojahResponse.data);
        
        return res.status(400).json({
          success: false,
          message: 'NIN verification failed. Please check the number and try again.',
          details: dojahResponse.data.error || 'Verification failed'
        });
      }

    } catch (error) {
      console.error('❌ Dojah NIN verification error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });

      // Handle specific error cases
      if (error.response?.status === 401) {
        return res.status(500).json({
          success: false,
          message: 'Verification service configuration error. Please contact support.'
        });
      }

      if (error.response?.status === 400) {
        const errorMessage = error.response.data?.error || 'Invalid NIN';
        return res.status(400).json({
          success: false,
          message: errorMessage
        });
      }

      if (error.code === 'ECONNABORTED') {
        return res.status(408).json({
          success: false,
          message: 'Verification timeout. Please try again.'
        });
      }

      return res.status(500).json({
        success: false,
        message: 'Verification service temporarily unavailable. Please try again later.',
        debug: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  },

  async verifyNINWithSelfie(req, res) {
    try {
      const { nin, selfieImage } = req.body;

      // Validate required fields
      if (!nin || !selfieImage) {
        return res.status(400).json({
          success: false,
          message: 'NIN and selfie image are required'
        });
      }

      // Validate NIN format
      if (nin.length !== 11 || !/^\d+$/.test(nin)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid NIN format. Must be 11 digits.'
        });
      }

      console.log('🔐 Starting Dojah NIN + Selfie verification for:', nin);

      // Call Dojah API for NIN with selfie verification
      const dojahResponse = await axios.post(
        `https://api.dojah.io/api/v1/kyc/nin_verify`,
        {
          nin: nin,
          image: selfieImage // Base64 encoded selfie image
        },
        {
          headers: {
            'Authorization': process.env.DOJAH_APP_ID,
            'AppId': process.env.DOJAH_APP_ID,
            'Content-Type': 'application/json'
          },
          timeout: 30000 // 30 second timeout
        }
      );

      console.log('📊 Dojah NIN + Selfie Response:', dojahResponse.data);

      // Check if verification was successful
      if (dojahResponse.data.entity) {
        const verificationData = dojahResponse.data.entity;

        // Prepare verification data
        const userVerificationData = {
          nin: nin,
          isNinVerified: true,
          isSelfieVerified: verificationData.selfie_verification === true,
          verificationStatus: 'verified',
          verificationDate: new Date(),
          provider: 'dojah',
          verificationDetails: {
            fullName: verificationData.full_name,
            firstName: verificationData.firstname,
            lastName: verificationData.lastname,
            gender: verificationData.gender,
            birthDate: verificationData.birthdate,
            phone: verificationData.phone,
            state: verificationData.state,
            nin: verificationData.nin,
            selfieVerification: verificationData.selfie_verification,
            confidence: verificationData.confidence
          }
        };

        // Update user in database
        const updatedUser = await User.findByIdAndUpdate(
          req.user.id,
          {
            identityVerification: userVerificationData,
            isIdentityVerified: true,
            verificationSubmittedAt: new Date()
          },
          { new: true }
        ).select('-password');

        console.log('✅ User NIN + Selfie verification completed:', updatedUser._id);

        return res.json({
          success: true,
          message: 'NIN and selfie verified successfully!',
          data: {
            isNinVerified: true,
            isSelfieVerified: verificationData.selfie_verification === true,
            verificationStatus: 'verified',
            full_name: verificationData.full_name,
            firstname: verificationData.firstname,
            lastname: verificationData.lastname,
            gender: verificationData.gender,
            state: verificationData.state,
            selfie_verification: verificationData.selfie_verification,
            confidence: verificationData.confidence
          }
        });

      } else {
        console.log('❌ NIN + Selfie verification failed:', dojahResponse.data);
        
        return res.status(400).json({
          success: false,
          message: 'NIN and selfie verification failed.',
          details: dojahResponse.data.error || 'Verification failed'
        });
      }

    } catch (error) {
      console.error('❌ Dojah NIN + Selfie verification error:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });

      // Handle specific error cases
      if (error.response?.status === 401) {
        return res.status(500).json({
          success: false,
          message: 'Verification service configuration error. Please contact support.'
        });
      }

      if (error.response?.status === 400) {
        const errorMessage = error.response.data?.error || 'Invalid NIN or selfie';
        return res.status(400).json({
          success: false,
          message: errorMessage
        });
      }

      if (error.code === 'ECONNABORTED') {
        return res.status(408).json({
          success: false,
          message: 'Verification timeout. Please try again.'
        });
      }

      return res.status(500).json({
        success: false,
        message: 'Verification service temporarily unavailable. Please try again later.',
        debug: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
};

export default VerificationController;