# ReviewPinger Deployment Guide

## Environment Configuration

### Required Environment Variables

For production deployment, ensure the following environment variables are properly set:

#### Database Configuration
```bash
DATABASE_URL=mongodb://your-mongodb-connection-string
```

#### JWT Configuration
```bash
JWT_SECRET=your-secure-jwt-secret-key
REFRESH_TOKEN_SECRET=your-secure-refresh-token-secret
```

#### SimpleTexting API Configuration
```bash
SIMPLETEXTING_API_KEY=your-actual-simpletexting-api-key
SIMPLETEXTING_BASE_URL=https://app.simpletexting.com/v2
```

#### Bitly API Configuration
```bash
BITLY_ACCESS_TOKEN=your-actual-bitly-access-token
BITLY_BASE_URL=https://api-ssl.bitly.com/v4
```

#### Production Settings
```bash
NODE_ENV=production
PORT=3000
```

### SMS Mode Configuration

The app automatically determines whether to send real SMS messages or use mock mode based on:

1. **Real SMS Mode** (Production):
   - `SIMPLETEXTING_API_KEY` is configured with a valid API key
   - `NODE_ENV` is NOT set to 'development'
   - `MOCK_SMS` is NOT set to 'true'

2. **Mock SMS Mode** (Development):
   - `NODE_ENV=development`, OR
   - `SIMPLETEXTING_API_KEY` is missing, OR
   - `MOCK_SMS=true`

### Testing SMS Functionality

#### Development Testing
In development mode, SMS sending will be simulated. The diagnostics tool will show:
- "Mock Mode" badge in the response
- Warning message about development mode
- Simulated success responses

#### Production Testing
In production mode with proper API keys:
- Real SMS messages will be sent
- No "Mock Mode" indicators
- Actual delivery confirmations from SimpleTexting API

## Pre-Deployment Checklist

### 1. Database Setup
- [ ] MongoDB instance is running and accessible
- [ ] Database connection string is configured
- [ ] Run database seeding script: `npm run seed`

### 2. API Keys Configuration
- [ ] SimpleTexting API key is obtained and configured
- [ ] Bitly access token is obtained and configured
- [ ] JWT secrets are generated and configured

### 3. Environment Variables
- [ ] All required environment variables are set
- [ ] `NODE_ENV=production` is set for production deployment
- [ ] Secrets are properly secured (not in version control)

### 4. Testing
- [ ] Test SMS sending functionality using the diagnostics tool
- [ ] Verify real SMS messages are being sent (not mock mode)
- [ ] Test user authentication and authorization
- [ ] Test all CRUD operations for cities, technicians, and templates

### 5. Build Process
- [ ] Frontend builds successfully: `cd client && npm run build`
- [ ] Backend starts without errors: `cd server && npm start`
- [ ] All dependencies are installed

## Deployment Steps

### 1. Environment Setup
```bash
# Set production environment variables
export NODE_ENV=production
export DATABASE_URL=your-mongodb-connection
export SIMPLETEXTING_API_KEY=your-api-key
export BITLY_ACCESS_TOKEN=your-bitly-token
export JWT_SECRET=your-jwt-secret
export REFRESH_TOKEN_SECRET=your-refresh-secret
```

### 2. Install Dependencies
```bash
# Install root dependencies
npm install

# Install client dependencies
cd client && npm install

# Install server dependencies
cd ../server && npm install
```

### 3. Build Frontend
```bash
cd client
npm run build
```

### 4. Seed Database
```bash
cd server
npm run seed
```

### 5. Start Application
```bash
# From root directory
npm start
```

## Verification

After deployment, verify the following:

1. **Application Access**: Visit the deployed URL and ensure login works
2. **SMS Functionality**: Use the SMS Diagnostics Tool to send a test SMS
3. **Real SMS Delivery**: Confirm actual SMS messages are received on test phone numbers
4. **Database Operations**: Test creating cities, technicians, and templates
5. **Reporting**: Verify reports and analytics are working

## Troubleshooting

### SMS Not Sending (Mock Mode Active)
If the diagnostics tool shows "Mock Mode" in production:
1. Verify `SIMPLETEXTING_API_KEY` is set correctly
2. Ensure `NODE_ENV=production`
3. Check that `MOCK_SMS` is not set to 'true'
4. Restart the application after environment changes

### Database Connection Issues
1. Verify MongoDB is running and accessible
2. Check `DATABASE_URL` format and credentials
3. Ensure network connectivity to database server

### API Key Issues
1. Verify SimpleTexting API key is valid and active
2. Check Bitly access token permissions
3. Test API keys independently using curl or Postman

## Security Considerations

1. **Environment Variables**: Never commit API keys or secrets to version control
2. **JWT Secrets**: Use strong, randomly generated secrets
3. **Database Security**: Ensure MongoDB is properly secured
4. **HTTPS**: Use HTTPS in production for secure communication
5. **Rate Limiting**: Consider implementing rate limiting for SMS endpoints

## Monitoring

Monitor the following in production:
1. SMS delivery rates and failures
2. API usage and quotas (SimpleTexting, Bitly)
3. Database performance and storage
4. Application logs for errors
5. User activity and authentication issues