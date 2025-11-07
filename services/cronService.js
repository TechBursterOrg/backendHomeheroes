import cron from 'node-cron';
import Booking from '../models/Booking.js';
import StripeService from './stripeService.js';

export class CronService {
  static startAutoRefundJob() {
    // Run every hour to check for expired bookings
    cron.schedule('0 * * * *', async () => {
      try {
        console.log('🔄 Running auto-refund check...');
        
        const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);
        
        const expiredBookings = await Booking.find({
          status: 'pending',
          'payment.status': 'held',
          'payment.heldAt': { $lte: fourHoursAgo }
        }).populate('customerId providerId');

        for (const booking of expiredBookings) {
          try {
            console.log(`🔄 Auto-refunding booking ${booking._id}`);
            
            const refundResult = await StripeService.cancelPayment(booking.payment.paymentIntentId);
            
            if (refundResult.success) {
              booking.payment.status = 'refunded';
              booking.payment.refundedAt = new Date();
              booking.status = 'cancelled';
              await booking.save();
              
              console.log(`✅ Auto-refunded booking ${booking._id}`);
            }
          } catch (error) {
            console.error(`❌ Failed to auto-refund booking ${booking._id}:`, error);
          }
        }
        
        console.log(`✅ Auto-refund check completed. Processed ${expiredBookings.length} bookings.`);
      } catch (error) {
        console.error('❌ Auto-refund job error:', error);
      }
    });
  }
}

export default CronService;