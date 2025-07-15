const express = require('express');
const SmsMessage = require('../models/SmsMessage');
const City = require('../models/City');
const Technician = require('../models/Technician');
const MessageTemplate = require('../models/MessageTemplate');
const simpleTextingService = require('../services/simpleTextingService');
const bitlyService = require('../services/bitlyService');
const { requireUser } = require('./middleware/auth');

const router = express.Router();

// POST /api/sms/send - Send SMS review request
router.post('/send', requireUser, async (req, res) => {
  console.log('SMS ENDPOINT: Request received at /api/sms/send');
  console.log('SMS ENDPOINT: Request body:', JSON.stringify(req.body, null, 2));

  try {
    const { cityId, technicianId, customerName, customerPhone } = req.body;

    // Validation
    if (!cityId || !technicianId || !customerName || !customerPhone) {
      console.log('SMS ENDPOINT: Validation failed - missing fields');
      return res.status(400).json({
        error: 'All fields are required: cityId, technicianId, customerName, customerPhone'
      });
    }

    // Validate phone number format
    const phoneRegex = /^\d{3}-\d{3}-\d{4}$/;
    if (!phoneRegex.test(customerPhone)) {
      console.log('SMS ENDPOINT: Validation failed - invalid phone format');
      return res.status(400).json({
        error: 'Invalid phone number format. Please use XXX-XXX-XXXX format'
      });
    }

    console.log('SMS ENDPOINT: Validation passed, fetching data from database');

    // Get city information
    const city = await City.findById(cityId);
    if (!city || !city.isActive) {
      console.log('SMS ENDPOINT: City not found or inactive');
      return res.status(404).json({
        error: 'City not found or inactive'
      });
    }

    // Get technician information
    const technician = await Technician.findById(technicianId);
    if (!technician || !technician.isActive) {
      console.log('SMS ENDPOINT: Technician not found or inactive');
      return res.status(404).json({
        error: 'Technician not found or inactive'
      });
    }

    // Get default message template
    const template = await MessageTemplate.findOne({ isDefault: true, isActive: true });
    if (!template) {
      console.log('SMS ENDPOINT: No default message template found');
      return res.status(500).json({
        error: 'No default message template configured'
      });
    }

    console.log('SMS ENDPOINT: Found city:', city.name);
    console.log('SMS ENDPOINT: Found technician:', technician.name);
    console.log('SMS ENDPOINT: Found template:', template.name);

    // Shorten the Google review URL
    console.log('SMS ENDPOINT: Shortening URL:', city.googleReviewLink);
    let reviewUrl = city.googleReviewLink;
    const shortenResult = await bitlyService.shortenUrl(city.googleReviewLink);
    if (shortenResult.success) {
      reviewUrl = shortenResult.shortUrl;
      console.log('SMS ENDPOINT: URL shortened to:', reviewUrl);
    } else {
      console.log('SMS ENDPOINT: URL shortening failed, using original');
    }

    // Generate message content
    const messageContent = template.template
      .replace(/{customerName}/g, customerName)
      .replace(/{cityName}/g, city.name)
      .replace(/{googleReviewLink}/g, reviewUrl)
      .replace(/{technicianName}/g, technician.name);

    console.log('SMS ENDPOINT: Generated message content:', messageContent);
    console.log('SMS ENDPOINT: Message length:', messageContent.length);

    // Create SMS message record
    const smsMessage = new SmsMessage({
      cityId,
      technicianId,
      customerName: customerName.trim(),
      customerPhone: customerPhone.trim(),
      messageContent,
      originalUrl: city.googleReviewLink,
      shortenedUrl: shortenResult.success ? shortenResult.shortUrl : null,
      status: 'pending'
    });

    await smsMessage.save();
    console.log('SMS ENDPOINT: Created SMS message record with ID:', smsMessage._id);

    console.log('SMS ENDPOINT: About to call simpleTextingService.sendSMS()');
    console.log('SMS ENDPOINT: Calling with phone:', customerPhone);
    console.log('SMS ENDPOINT: Calling with message length:', messageContent.length);

    // Send SMS via SimpleTexting
    const sendResult = await simpleTextingService.sendSMS(customerPhone, messageContent);

    console.log('SMS ENDPOINT: simpleTextingService.sendSMS() completed');
    console.log('SMS ENDPOINT: sendResult:', JSON.stringify(sendResult, null, 2));

    if (sendResult.success) {
      // Update message record with success
      smsMessage.status = 'sent';
      smsMessage.externalMessageId = sendResult.messageId;
      smsMessage.sentAt = new Date();
      await smsMessage.save();

      console.log('SMS ENDPOINT: SMS sent successfully, updated database');

      const successResponse = {
        success: true,
        message: sendResult.isMockMode
          ? `Mock SMS sent successfully to ${customerName} at ${customerPhone} (Development Mode)`
          : `Review request sent successfully to ${customerName} at ${customerPhone}`,
        messageId: smsMessage._id,
        externalMessageId: sendResult.messageId,
        isMockMode: sendResult.isMockMode || false
      };

      console.log('SMS ENDPOINT: Sending success response');
      res.json(successResponse);
    } else {
      // Update message record with failure
      smsMessage.status = 'failed';
      smsMessage.errorMessage = sendResult.error;
      await smsMessage.save();

      console.log('SMS ENDPOINT: SMS sending failed:', sendResult.error);

      const errorResponse = {
        success: false,
        error: sendResult.error || 'Failed to send SMS',
        isMockMode: sendResult.isMockMode || false
      };

      console.log('SMS ENDPOINT: Sending error response');
      res.status(500).json(errorResponse);
    }

  } catch (error) {
    console.error('SMS ENDPOINT: Unexpected error occurred:', error.message);
    console.error('SMS ENDPOINT: Error stack:', error.stack);
    res.status(500).json({
      success: false,
      error: 'Failed to send SMS request'
    });
  }
});

// GET /api/sms/history - Get SMS message history
router.get('/history', requireUser, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    console.log(`SMS History: Fetching page ${page}, limit ${limit}`);

    const messages = await SmsMessage.find()
      .populate('cityId', 'name')
      .populate('technicianId', 'name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalCount = await SmsMessage.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);

    console.log(`SMS History: Retrieved ${messages.length} messages, total: ${totalCount}`);

    const formattedMessages = messages.map(message => ({
      id: message._id,
      cityName: message.cityId?.name || 'Unknown City',
      technicianName: message.technicianId?.name || 'Unknown Technician',
      customerName: message.customerName,
      customerPhone: message.customerPhone.replace(/(\d{3})-(\d{3})-(\d{4})/, 'XXX-XXX-$3'),
      status: message.status.charAt(0).toUpperCase() + message.status.slice(1),
      sentAt: message.sentAt || message.createdAt
    }));

    res.json({
      messages: formattedMessages,
      total: totalCount, // Changed from totalCount to total to match frontend expectation
      totalCount, // Keep both for backward compatibility
      currentPage: page,
      totalPages
    });

  } catch (error) {
    console.error('SMS History: Error fetching message history:', error);
    res.status(500).json({
      error: 'Failed to fetch message history'
    });
  }
});

// GET /api/sms/status/:messageId - Get message status
router.get('/status/:messageId', requireUser, async (req, res) => {
  try {
    const { messageId } = req.params;
    console.log(`SMS Status: Checking status for message ${messageId}`);

    const message = await SmsMessage.findById(messageId);
    if (!message) {
      return res.status(404).json({
        error: 'Message not found'
      });
    }

    // If we have an external message ID, check with SimpleTexting
    if (message.externalMessageId && message.status === 'sent') {
      const statusResult = await simpleTextingService.getMessageStatus(message.externalMessageId);

      if (statusResult.success && statusResult.status !== message.status) {
        message.status = statusResult.status;
        if (statusResult.status === 'delivered') {
          message.deliveredAt = new Date();
        }
        await message.save();
        console.log(`SMS Status: Updated message status to ${statusResult.status}`);
      }
    }

    res.json({
      messageId: message._id,
      status: message.status,
      sentAt: message.sentAt,
      deliveredAt: message.deliveredAt,
      errorMessage: message.errorMessage
    });

  } catch (error) {
    console.error('SMS Status: Error checking message status:', error);
    res.status(500).json({
      error: 'Failed to check message status'
    });
  }
});

module.exports = router;