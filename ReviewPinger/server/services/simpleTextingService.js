const axios = require('axios');

class SimpleTextingService {
  constructor() {
    this.apiKey = process.env.SIMPLETEXTING_API_KEY;
    this.baseUrl = process.env.SIMPLETEXTING_BASE_URL || 'https://app.simpletexting.com/v2';

    // Use mock mode only if:
    // 1. No API key configured, OR
    // 2. MOCK_SMS environment variable is set to 'true'
    this.mockMode = !this.apiKey || process.env.MOCK_SMS === 'true';

    console.log('SIMPLETEXTING SERVICE: Constructor called');
    console.log('SIMPLETEXTING SERVICE: API Key present:', !!this.apiKey);
    console.log('SIMPLETEXTING SERVICE: Mock mode:', this.mockMode);
  }

  async sendSMS(phoneNumber, message) {
    console.log('SIMPLETEXTING SERVICE: sendSMS called');
    console.log('SIMPLETEXTING SERVICE: Phone:', phoneNumber);
    console.log('SIMPLETEXTING SERVICE: Message length:', message.length);
    console.log('SIMPLETEXTING SERVICE: Mock mode:', this.mockMode);

    try {
      // Use mock mode for development
      if (this.mockMode) {
        console.log('SIMPLETEXTING SERVICE: Using mock mode - no real SMS sent');

        await new Promise(resolve => setTimeout(resolve, 1000));

        const mockResponse = {
          id: `mock_${Date.now()}`,
          status: 'sent',
          phone: phoneNumber,
          message: message,
          timestamp: new Date().toISOString()
        };

        console.log('SIMPLETEXTING SERVICE: Mock SMS completed');

        return {
          success: true,
          messageId: mockResponse.id,
          status: mockResponse.status,
          data: mockResponse,
          isMockMode: true
        };
      }

      // Real API implementation
      console.log('SIMPLETEXTING SERVICE: Using real API mode');
      console.log('SIMPLETEXTING SERVICE: API Key configured:', !!this.apiKey);
      console.log('SIMPLETEXTING SERVICE: Base URL:', this.baseUrl);

      if (!this.apiKey) {
        throw new Error('SimpleTexting API key not configured');
      }

      // Clean and format phone number
      const cleanPhone = phoneNumber.replace(/\D/g, '');
      const formattedPhone = cleanPhone.startsWith('1') ? cleanPhone : `1${cleanPhone}`;

      console.log('SIMPLETEXTING SERVICE: Formatted phone:', formattedPhone);

      const payload = {
      message: message,
      contactPhone: formattedPhone
      };

      const headers = {
      'Authorization': `Bearer ${this.apiKey}`,
      'Content-Type': 'application/json'
      };

      const fullUrl = `${this.baseUrl}/api/messages`;

      console.log('SIMPLETEXTING SERVICE: Making API request to:', fullUrl);
      console.log('SIMPLETEXTING SERVICE: Request payload phone:', formattedPhone);
      console.log('SIMPLETEXTING SERVICE: Request payload text length:', message.length);

      const response = await axios.post(fullUrl, payload, {
        headers,
        timeout: 10000
      });

      console.log('SIMPLETEXTING SERVICE: API request successful');
      console.log('SIMPLETEXTING SERVICE: Response status:', response.status);
      console.log('SIMPLETEXTING SERVICE: Response data:', JSON.stringify(response.data, null, 2));

      return {
        success: true,
        messageId: response.data.id || response.data.message_id || `sms_${Date.now()}`,
        status: response.data.status || 'sent',
        data: response.data,
        isMockMode: false
      };

    } catch (error) {
      console.error('SIMPLETEXTING SERVICE: Error occurred');
      console.error('SIMPLETEXTING SERVICE: Error message:', error.message);

      if (error.response) {
        console.error('SIMPLETEXTING SERVICE: HTTP Error Status:', error.response.status);
        console.error('SIMPLETEXTING SERVICE: HTTP Error Data:', JSON.stringify(error.response.data, null, 2));
      } else if (error.request) {
        console.error('SIMPLETEXTING SERVICE: Network error - no response received');
      } else {
        console.error('SIMPLETEXTING SERVICE: Request setup error');
      }

      return {
        success: false,
        error: error.response?.data?.message || error.response?.data?.error || error.message,
        statusCode: error.response?.status,
        isMockMode: false
      };
    }
  }

  async getMessageStatus(messageId) {
    try {
      if (this.mockMode) {
        return {
          success: true,
          status: 'delivered',
          data: { id: messageId, status: 'delivered' },
          isMockMode: true
        };
      }

      const response = await axios.get(`${this.baseUrl}/api/messages/${messageId}`, {
        headers: {
          'X-API-Key': this.apiKey,
          'Content-Type': 'application/json'
        },
        timeout: 5000
      });

      return {
        success: true,
        status: response.data.status,
        data: response.data,
        isMockMode: false
      };

    } catch (error) {
      return {
        success: false,
        error: error.response?.data?.message || error.message,
        isMockMode: false
      };
    }
  }
}

module.exports = new SimpleTextingService();
