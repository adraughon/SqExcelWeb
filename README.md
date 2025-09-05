# SqExcelWeb - FastAPI Proxy for Seeq Authentication

A serverless FastAPI application that acts as a proxy between Office Excel add-ins and Seeq servers, eliminating CORS issues by handling all Seeq API calls server-side.

## Overview

This proxy service allows Office Excel add-ins to authenticate with Seeq servers without encountering CORS (Cross-Origin Resource Sharing) restrictions. The add-in makes requests to this proxy, which then makes authenticated requests to Seeq servers and returns the results.

## Features

- **Authentication Proxy**: Handles Seeq authentication requests
- **Connection Testing**: Tests connectivity to Seeq servers
- **Session Management**: Temporarily stores authentication credentials
- **CORS Enabled**: Configured for Office add-in domains
- **Serverless**: Deployed on Vercel for scalability
- **Health Monitoring**: Built-in health check endpoints

## API Endpoints

### Health & Status
- `GET /` - Root endpoint with API information
- `GET /health` - Health check for monitoring

### Authentication
- `POST /api/seeq/test-connection` - Test connection to Seeq server
- `POST /api/seeq/auth` - Authenticate with Seeq server
- `DELETE /api/seeq/auth` - Logout and clear session

### Debugging
- `GET /api/seeq/sessions` - View active sessions (for debugging)

## Request/Response Examples

### Test Connection
```bash
POST /api/seeq/test-connection
{
  "url": "https://your-seeq-server.seeq.site"
}
```

### Authenticate
```bash
POST /api/seeq/auth
{
  "url": "https://your-seeq-server.seeq.site",
  "access_key": "your-access-key",
  "password": "your-password",
  "auth_provider": "Seeq",
  "ignore_ssl_errors": false
}
```

## Deployment to Vercel

### Prerequisites
- Vercel account
- GitHub repository with this code

### Steps

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Add SqExcelWeb FastAPI proxy"
   git push origin main
   ```

2. **Deploy to Vercel**
   - Go to [vercel.com](https://vercel.com)
   - Click "New Project"
   - Import your GitHub repository
   - Vercel will automatically detect the Python project
   - Deploy!

3. **Configure Environment** (if needed)
   - No environment variables required for basic functionality
   - All configuration is in the code

### Local Development

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Locally**
   ```bash
   python main.py
   ```
   The API will be available at `http://localhost:8000`

3. **Test Endpoints**
   ```bash
   # Health check
   curl http://localhost:8000/health
   
   # Test connection
   curl -X POST http://localhost:8000/api/seeq/test-connection \
     -H "Content-Type: application/json" \
     -d '{"url": "https://your-seeq-server.seeq.site"}'
   ```

## Integration with Office Add-in

Once deployed, update your Office add-in to use the proxy URL:

```typescript
// In your Office add-in code
const proxyUrl = 'https://your-vercel-app.vercel.app';

// Test connection
const response = await fetch(`${proxyUrl}/api/seeq/test-connection`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: seeqServerUrl })
});
```

## Security Considerations

- **Session Storage**: Currently uses in-memory storage (sessions are lost on restart)
- **Credential Handling**: Credentials are stored temporarily in memory only
- **CORS**: Configured for specific Office add-in domains
- **SSL**: All communication should use HTTPS in production

## Monitoring

- Use the `/health` endpoint for health checks
- Monitor active sessions with `/api/seeq/sessions`
- Check Vercel function logs for debugging

## Troubleshooting

### Common Issues

1. **CORS Errors**: Ensure your Office add-in domain is in the `allow_origins` list
2. **Timeout Errors**: Vercel functions have a 30-second timeout limit
3. **Authentication Failures**: Check Seeq server URL and credentials

### Debugging

1. Check Vercel function logs
2. Use the `/api/seeq/sessions` endpoint to see active sessions
3. Test endpoints locally first

## Future Enhancements

- Add sensor search endpoints
- Add data retrieval endpoints
- Implement proper session storage (Redis)
- Add rate limiting
- Add authentication tokens
- Add comprehensive logging

## License

MIT License - See LICENSE file for details
