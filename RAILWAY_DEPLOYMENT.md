# Railway Deployment Guide for SqExcelWeb

This guide will help you deploy the SqExcelWeb proxy server to Railway and test the connection chain.

## Prerequisites

1. Railway account (sign up at https://railway.app)
2. Git repository with the SqExcelWeb code
3. Excel add-in (SqExcel) ready for testing

## Deployment Steps

### 1. Deploy to Railway

1. Go to [Railway](https://railway.app) and sign in
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your SqExcelWeb repository
4. Railway will automatically detect the Python app and deploy it
5. Wait for deployment to complete
6. Note the generated URL (e.g., `https://sqexcelweb-production.up.railway.app`)

### 2. Update Excel Add-in

1. Open `/Users/austin/Documents/GitHub/SqExcel/src/taskpane/seeq-api-client.ts`
2. Update line 76 with your actual Railway URL:
   ```typescript
   this.proxyUrl = 'https://your-actual-railway-url.up.railway.app';
   ```
3. Build and deploy your Excel add-in

### 3. Test the Connection Chain

#### Step 1: Test Railway Server Directly
```bash
# Test the hello world endpoint
curl https://your-railway-url.up.railway.app/

# Test the test endpoint
curl https://your-railway-url.up.railway.app/test
```

#### Step 2: Test from Excel Add-in
1. Open Excel and load your add-in
2. Enter any Seeq server URL (can be fake for now)
3. Click "Test Connection"
4. You should see a success message indicating the proxy is working

#### Step 3: Test Full Chain (when ready)
1. Enter a real Seeq server URL
2. Enter valid credentials
3. Test authentication and data retrieval

## Local Testing

Before deploying to Railway, you can test locally:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask app
python app.py

# In another terminal, run tests
python test_local.py
```

## File Structure

```
SqExcelWeb/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Procfile              # Railway deployment config
├── railway.json          # Railway configuration
├── test_local.py         # Local testing script
└── RAILWAY_DEPLOYMENT.md # This file
```

## API Endpoints

The proxy server provides these endpoints:

- `GET /` - Hello world endpoint
- `GET /test` - Test endpoint
- `POST /api/seeq/test-connection` - Test connection to Seeq server
- `POST /api/seeq/auth` - Authenticate with Seeq server
- `POST /api/seeq/search` - Search for sensors (currently mock)
- `POST /api/seeq/data` - Get sensor data (currently mock)

## Troubleshooting

### Railway Deployment Issues
- Check Railway logs for errors
- Ensure `requirements.txt` has all dependencies
- Verify `Procfile` or `railway.json` is correct

### Excel Add-in Connection Issues
- Verify the Railway URL is correct in `seeq-api-client.ts`
- Check browser console for CORS errors
- Ensure Railway app is running and accessible

### Seeq API Issues
- Verify Seeq server URL is accessible
- Check credentials are correct
- Review Seeq server logs for authentication issues

## Next Steps

1. ✅ Deploy to Railway
2. ✅ Test hello world connection
3. 🔄 Test full Seeq API integration
4. 🔄 Add real Seeq API functionality
5. 🔄 Test end-to-end data flow
