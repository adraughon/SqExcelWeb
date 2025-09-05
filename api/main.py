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
    allow_origins=["*"],  # Allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class SeeqAuthRequest(BaseModel):
    seeq_url: str
    username: str
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
    seeq_url: str

class ConnectionTestResponse(BaseModel):
    success: bool
    message: str
    status_code: Optional[int] = None
    server_url: Optional[str] = None
    error: Optional[str] = None

class SeeqSearchRequest(BaseModel):
    seeq_url: str
    sensor_names: list[str]
    username: str
    password: str
    auth_provider: str = "Seeq"

class SeeqSearchResponse(BaseModel):
    success: bool
    message: str
    search_results: list[dict] = []
    sensor_count: int = 0
    error: Optional[str] = None

class SeeqDataRequest(BaseModel):
    seeq_url: str
    sensor_names: list[str]
    start_time: str
    end_time: str
    grid: str = "15min"
    username: str
    password: str
    auth_provider: str = "Seeq"

class SeeqDataResponse(BaseModel):
    success: bool
    message: str
    search_results: list[dict] = []
    data: list[list] = []
    data_columns: list[str] = []
    data_index: list[str] = []
    sensor_count: int = 0
    time_range: dict = {}
    error: Optional[str] = None

# Global session storage (in production, use Redis or database)
sessions: Dict[str, Dict[str, Any]] = {}

def get_session_id(username: str, seeq_url: str) -> str:
    """Generate a session ID for credential storage"""
    return hashlib.md5(f"{username}:{seeq_url}".encode()).hexdigest()

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

@app.get("/test")
async def test_endpoint():
    """Simple test endpoint for debugging"""
    return {
        "message": "Test endpoint is working",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "ok"
    }

@app.post("/api/seeq/test-connection", response_model=ConnectionTestResponse)
async def test_connection(request: ConnectionTestRequest):
    """Test connection to Seeq server"""
    try:
        logger.info(f"Testing connection to Seeq server: {request.seeq_url}")
        
        # Test basic connectivity to the Seeq server
        test_url = f"{request.seeq_url.rstrip('/')}/api/system/open-ping"
        
        response = requests.get(
            test_url,
            timeout=10,
            verify=not request.seeq_url.startswith('http://')  # Skip SSL verification for HTTP
        )
        
        if response.status_code == 200:
            logger.info(f"Connection test successful for {request.seeq_url}")
            return ConnectionTestResponse(
                success=True,
                message="Server is reachable",
                status_code=response.status_code,
                server_url=request.seeq_url
            )
        else:
            logger.warning(f"Connection test failed for {request.seeq_url}: HTTP {response.status_code}")
            return ConnectionTestResponse(
                success=False,
                message=f"Server responded with status code: {response.status_code}",
                status_code=response.status_code,
                server_url=request.seeq_url
            )
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Connection test failed for {request.seeq_url}: {str(e)}")
        return ConnectionTestResponse(
            success=False,
            message=f"Connection test failed: {str(e)}",
            error=str(e),
            server_url=request.seeq_url
        )
    except Exception as e:
        logger.error(f"Unexpected error in test_connection: {e}")
        return ConnectionTestResponse(
            success=False,
            message=f"Unexpected error: {str(e)}",
            error=str(e),
            server_url=request.seeq_url
        )

@app.post("/api/seeq/auth", response_model=SeeqAuthResponse)
async def authenticate_seeq(request: SeeqAuthRequest):
    """Authenticate with Seeq server"""
    try:
        logger.info(f"Authenticating with Seeq server: {request.seeq_url}")
        
        # Store credentials in session
        session_id = get_session_id(request.username, request.seeq_url)
        sessions[session_id] = {
            "url": request.seeq_url,
            "access_key": request.username,
            "password": request.password,
            "auth_provider": request.auth_provider,
            "ignore_ssl_errors": request.ignore_ssl_errors,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Test authentication by making a request to Seeq
        auth_url = f"{request.seeq_url.rstrip('/')}/api/auth/login"
        
        auth_data = {
            "username": request.username,
            "password": request.password
        }
        
        response = requests.post(
            auth_url,
            json=auth_data,
            timeout=30,
            verify=not request.ignore_ssl_errors
        )
        
        if response.status_code == 200:
            logger.info(f"Authentication successful for user: {request.username}")
            return SeeqAuthResponse(
                success=True,
                message=f"Successfully authenticated as {request.username}",
                user=request.username,
                server_url=request.seeq_url
            )
        else:
            error_data = response.json() if response.content else {}
            error_message = error_data.get("message", f"Authentication failed with status {response.status_code}")
            logger.warning(f"Authentication failed for {request.username}: {error_message}")
            return SeeqAuthResponse(
                success=False,
                message=error_message,
                error=f"HTTP {response.status_code}"
            )
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Authentication request failed for {request.seeq_url}: {str(e)}")
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

@app.post("/api/seeq/search", response_model=SeeqSearchResponse)
async def search_sensors(request: SeeqSearchRequest):
    """Search for sensors in Seeq server"""
    try:
        logger.info(f"Searching for sensors in Seeq server: {request.seeq_url}")
        
        # Authenticate first
        auth_url = f"{request.seeq_url.rstrip('/')}/api/auth/login"
        auth_data = {
            "username": request.username,
            "password": request.password
        }
        
        auth_response = requests.post(
            auth_url,
            json=auth_data,
            timeout=30,
            verify=True
        )
        
        if auth_response.status_code != 200:
            return SeeqSearchResponse(
                success=False,
                message=f"Authentication failed with status {auth_response.status_code}",
                error=f"HTTP {auth_response.status_code}"
            )
        
        # Get session cookies for subsequent requests
        session = requests.Session()
        session.cookies.update(auth_response.cookies)
        
        # Search for sensors using the items API
        search_results = []
        for sensor_name in request.sensor_names:
            # Use the items API to search for signals
            search_url = f"{request.seeq_url.rstrip('/')}/api/items"
            search_params = {
                "q": sensor_name,
                "limit": 100
            }
            
            search_response = session.get(
                search_url,
                params=search_params,
                timeout=30
            )
            
            if search_response.status_code == 200:
                search_data = search_response.json()
                for item in search_data.get("items", []):
                    if item.get("type") == "Signal":
                        search_results.append({
                            "ID": item.get("id", ""),
                            "Name": item.get("name", ""),
                            "Type": item.get("type", "Signal"),
                            "Original_Name": item.get("originalName", ""),
                            "Status": "Available"
                        })
        
        logger.info(f"Found {len(search_results)} sensors")
        return SeeqSearchResponse(
            success=True,
            message=f"Found {len(search_results)} sensors",
            search_results=search_results,
            sensor_count=len(search_results)
        )
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Search request failed for {request.seeq_url}: {str(e)}")
        return SeeqSearchResponse(
            success=False,
            message=f"Search failed: {str(e)}",
            error=str(e)
        )
    except Exception as e:
        logger.error(f"Unexpected error in search_sensors: {e}")
        return SeeqSearchResponse(
            success=False,
            message=f"Unexpected error: {str(e)}",
            error=str(e)
        )

@app.post("/api/seeq/data", response_model=SeeqDataResponse)
async def get_sensor_data(request: SeeqDataRequest):
    """Get sensor data from Seeq server"""
    try:
        logger.info(f"Getting sensor data from Seeq server: {request.seeq_url}")
        
        # Authenticate first
        auth_url = f"{request.seeq_url.rstrip('/')}/api/auth/login"
        auth_data = {
            "username": request.username,
            "password": request.password
        }
        
        auth_response = requests.post(
            auth_url,
            json=auth_data,
            timeout=30,
            verify=True
        )
        
        if auth_response.status_code != 200:
            return SeeqDataResponse(
                success=False,
                message=f"Authentication failed with status {auth_response.status_code}",
                error=f"HTTP {auth_response.status_code}"
            )
        
        # Get session cookies for subsequent requests
        session = requests.Session()
        session.cookies.update(auth_response.cookies)
        
        # Search for sensors first
        search_results = []
        sensor_ids = []
        for sensor_name in request.sensor_names:
            # Use the items API to search for signals
            search_url = f"{request.seeq_url.rstrip('/')}/api/items"
            search_params = {
                "q": sensor_name,
                "limit": 100
            }
            
            search_response = session.get(
                search_url,
                params=search_params,
                timeout=30
            )
            
            if search_response.status_code == 200:
                search_data = search_response.json()
                for item in search_data.get("items", []):
                    if item.get("type") == "Signal":
                        search_results.append({
                            "ID": item.get("id", ""),
                            "Name": item.get("name", ""),
                            "Type": item.get("type", "Signal"),
                            "Original_Name": item.get("originalName", ""),
                            "Status": "Available"
                        })
                        sensor_ids.append(item.get("id"))
        
        if not sensor_ids:
            return SeeqDataResponse(
                success=False,
                message="No sensors found",
                error="No matching sensors found"
            )
        
        # Get data for each sensor individually using the signals API
        all_sensor_data = []
        for sensor_id in sensor_ids:
            data_url = f"{request.seeq_url.rstrip('/')}/api/signals/{sensor_id}/samples"
            data_params = {
                "start": request.start_time,
                "end": request.end_time
            }
            
            data_response = session.get(
                data_url,
                params=data_params,
                timeout=60
            )
            
            if data_response.status_code == 200:
                sensor_data = data_response.json()
                all_sensor_data.append({
                    "id": sensor_id,
                    "data": sensor_data.get("data", [])
                })
        
        if all_sensor_data:
            # Process the data into the expected format
            data_rows = []
            data_columns = ["Timestamp"] + [sensor["Name"] for sensor in search_results]
            data_index = []
            
            # Extract time series data from all sensors
            for sensor_data in all_sensor_data:
                sensor_id = sensor_data.get("id")
                sensor_name = next((s["Name"] for s in search_results if s["ID"] == sensor_id), sensor_id)
                
                for point in sensor_data.get("data", []):
                    timestamp = point.get("timestamp")
                    value = point.get("value")
                    
                    # Find or create row for this timestamp
                    row_index = None
                    for i, existing_timestamp in enumerate(data_index):
                        if existing_timestamp == timestamp:
                            row_index = i
                            break
                    
                    if row_index is None:
                        data_index.append(timestamp)
                        data_rows.append([timestamp] + [None] * len(search_results))
                        row_index = len(data_rows) - 1
                    
                    # Find sensor column index
                    sensor_col_index = next((i for i, s in enumerate(search_results) if s["ID"] == sensor_id), None)
                    if sensor_col_index is not None:
                        data_rows[row_index][sensor_col_index + 1] = value
            
            logger.info(f"Retrieved data for {len(search_results)} sensors with {len(data_rows)} data points")
            return SeeqDataResponse(
                success=True,
                message=f"Successfully retrieved data for {len(search_results)} sensors",
                search_results=search_results,
                data=data_rows,
                data_columns=data_columns,
                data_index=data_index,
                sensor_count=len(search_results),
                time_range={
                    "start": request.start_time,
                    "end": request.end_time,
                    "grid": request.grid
                }
            )
        else:
            return SeeqDataResponse(
                success=False,
                message="No data retrieved from any sensors",
                error="Data retrieval failed for all sensors",
                search_results=search_results,
                sensor_count=len(search_results),
                time_range={
                    "start": request.start_time,
                    "end": request.end_time,
                    "grid": request.grid
                }
            )
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Data request failed for {request.seeq_url}: {str(e)}")
        return SeeqDataResponse(
            success=False,
            message=f"Data retrieval failed: {str(e)}",
            error=str(e),
            time_range={
                "start": request.start_time,
                "end": request.end_time,
                "grid": request.grid
            }
        )
    except Exception as e:
        logger.error(f"Unexpected error in get_sensor_data: {e}")
        return SeeqDataResponse(
            success=False,
            message=f"Unexpected error: {str(e)}",
            error=str(e),
            time_range={
                "start": request.start_time,
                "end": request.end_time,
                "grid": request.grid
            }
        )
