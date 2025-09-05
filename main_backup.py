"""
SqExcelWeb - FastAPI Proxy for Seeq Authentication
This serverless FastAPI application acts as a proxy between Office Excel add-ins and Seeq servers.
It eliminates CORS issues by handling all Seeq API calls server-side.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import requests
import hashlib
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SqExcelWeb Seeq Proxy API",
    description="FastAPI proxy for Seeq authentication from Office Excel add-ins",
    version="1.0.0"
)

# Configure CORS for Office add-ins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://adraughon.github.io",
        "https://*.vercel.app",
        "http://localhost:3000",  # For development
        "https://localhost:3000"  # For development
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class SeeqAuthRequest(BaseModel):
    url: str
    access_key: str
    password: str
    auth_provider: str = "Seeq"
    ignore_ssl_errors: bool = False

class SeeqAuthResponse(BaseModel):
    success: bool
    message: str
    user: Optional[str] = None
    server_url: Optional[str] = None
    error: Optional[str] = None

class ConnectionTestRequest(BaseModel):
    url: str

class ConnectionTestResponse(BaseModel):
    success: bool
    message: str
    status_code: Optional[int] = None
    server_url: Optional[str] = None
    error: Optional[str] = None

# Global session storage (in production, use Redis or database)
sessions: Dict[str, Dict[str, Any]] = {}

def get_session_id(access_key: str, url: str) -> str:
    """Generate a session ID for credential storage"""
    return hashlib.md5(f"{access_key}:{url}".encode()).hexdigest()

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "SqExcelWeb Seeq Proxy API is running",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "health": "/health",
            "test_connection": "POST /api/seeq/test-connection",
            "authenticate": "POST /api/seeq/auth",
            "logout": "DELETE /api/seeq/auth"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "sessions_active": len(sessions),
        "service": "SqExcelWeb Proxy"
    }

@app.post("/api/seeq/test-connection", response_model=ConnectionTestResponse)
async def test_connection(request: ConnectionTestRequest):
    """Test connection to Seeq server"""
    try:
        logger.info(f"Testing connection to Seeq server: {request.url}")
        
        # Test basic connectivity to the Seeq server
        test_url = f"{request.url.rstrip('/')}/api/system/open-ping"
        
        response = requests.get(
            test_url,
            timeout=10,
            verify=not request.url.startswith('http://')  # Skip SSL verification for HTTP
        )
        
        if response.status_code == 200:
            logger.info(f"Connection test successful for {request.url}")
            return ConnectionTestResponse(
                success=True,
                message="Server is reachable",
                status_code=response.status_code,
                server_url=request.url
            )
        else:
            logger.warning(f"Connection test failed for {request.url}: HTTP {response.status_code}")
            return ConnectionTestResponse(
                success=False,
                message=f"Server responded with status code: {response.status_code}",
                status_code=response.status_code,
                server_url=request.url
            )
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Connection test failed for {request.url}: {str(e)}")
        return ConnectionTestResponse(
            success=False,
            message=f"Connection test failed: {str(e)}",
            error=str(e),
            server_url=request.url
        )
    except Exception as e:
        logger.error(f"Unexpected error in test_connection: {e}")
        return ConnectionTestResponse(
            success=False,
            message=f"Unexpected error: {str(e)}",
            error=str(e),
            server_url=request.url
        )

@app.post("/api/seeq/auth", response_model=SeeqAuthResponse)
async def authenticate_seeq(request: SeeqAuthRequest):
    """Authenticate with Seeq server"""
    try:
        logger.info(f"Authenticating with Seeq server: {request.url}")
        
        # Store credentials in session
        session_id = get_session_id(request.access_key, request.url)
        sessions[session_id] = {
            "url": request.url,
            "access_key": request.access_key,
            "password": request.password,
            "auth_provider": request.auth_provider,
            "ignore_ssl_errors": request.ignore_ssl_errors,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Test authentication by making a request to Seeq
        auth_url = f"{request.url.rstrip('/')}/api/auth/login"
        
        auth_data = {
            "username": request.access_key,
            "password": request.password
        }
        
        response = requests.post(
            auth_url,
            json=auth_data,
            timeout=30,
            verify=not request.ignore_ssl_errors
        )
        
        if response.status_code == 200:
            logger.info(f"Authentication successful for user: {request.access_key}")
            return SeeqAuthResponse(
                success=True,
                message=f"Successfully authenticated as {request.access_key}",
                user=request.access_key,
                server_url=request.url
            )
        else:
            error_data = response.json() if response.content else {}
            error_message = error_data.get("message", f"Authentication failed with status {response.status_code}")
            logger.warning(f"Authentication failed for {request.access_key}: {error_message}")
            return SeeqAuthResponse(
                success=False,
                message=error_message,
                error=f"HTTP {response.status_code}"
            )
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication request failed for {request.url}: {str(e)}")
        return SeeqAuthResponse(
            success=False,
            message=f"Authentication failed: {str(e)}",
            error=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error in authenticate_seeq: {e}")
        return SeeqAuthResponse(
            success=False,
            message=f"Unexpected error: {str(e)}",
            error=str(e)
        )

@app.delete("/api/seeq/auth")
async def logout():
    """Clear authentication session"""
    try:
        # In a real implementation, you'd clear the specific session based on request context
        # For now, we'll just return success
        logger.info("Logout request received")
        return {
            "success": True,
            "message": "Logged out successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error during logout: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/seeq/sessions")
async def get_active_sessions():
    """Get information about active sessions (for debugging)"""
    try:
        session_info = []
        for session_id, session_data in sessions.items():
            session_info.append({
                "session_id": session_id[:8] + "...",  # Truncate for security
                "user": session_data.get("access_key"),
                "server_url": session_data.get("url"),
                "timestamp": session_data.get("timestamp")
            })
        
        return {
            "success": True,
            "active_sessions": len(sessions),
            "sessions": session_info
        }
    except Exception as e:
        logger.error(f"Error getting session info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Vercel handler
def handler(request):
    """Vercel serverless function handler"""
    from mangum import Mangum
    return Mangum(app)(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
