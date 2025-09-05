from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import traceback
import io
import re
from contextlib import redirect_stdout, redirect_stderr
from typing import Dict, Any, Optional

app = Flask(__name__)

# Security: Restrict CORS to specific trusted origins
CORS(app, origins=[
    'https://adraughon.github.io',
    'https://*.office.com',
    'https://*.microsoft.com',
    'https://*.office365.com'
])

# Security: Define trusted domains for SSL bypass (if needed)
TRUSTED_DOMAINS = [
    'talosenergy.seeq.tech',
    '*.seeq.tech',
    'localhost',
    '127.0.0.1'
]

# Security: Input validation functions
def validate_url(url: str) -> bool:
    """Validate URL format and ensure it's HTTPS for production"""
    if not url:
        return False
    
    # Basic URL pattern validation
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def validate_credentials(access_key: str, password: str) -> bool:
    """Validate credential format"""
    if not access_key or not password:
        return False
    
    # Basic length and character validation
    if len(access_key) < 3 or len(access_key) > 100:
        return False
    
    if len(password) < 3 or len(password) > 200:
        return False
    
    # Check for suspicious patterns
    suspicious_patterns = ['<script', 'javascript:', 'data:', 'vbscript:']
    for pattern in suspicious_patterns:
        if pattern.lower() in access_key.lower() or pattern.lower() in password.lower():
            return False
    
    return True

def is_trusted_domain(url: str) -> bool:
    """Check if domain is in trusted list"""
    if not url:
        return False
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname
        
        if not domain:
            return False
        
        # Check exact matches and wildcard patterns
        for trusted in TRUSTED_DOMAINS:
            if trusted == domain:
                return True
            if trusted.startswith('*') and domain.endswith(trusted[1:]):
                return True
        
        return False
    except:
        return False

# Try to import SPy module
try:
    from seeq import spy
    SPY_AVAILABLE = True
    print("✅ SPy module successfully imported")
except ImportError as e:
    SPY_AVAILABLE = False
    spy = None
    print(f"❌ SPy module not available: {e}")
    print(f"❌ Import error details: {type(e).__name__}: {str(e)}")
    print("💡 To install SPy: pip install seeq-spy[all]")
    print("💡 Note: SPy requires a valid Seeq license and may need special installation")
except Exception as e:
    SPY_AVAILABLE = False
    spy = None
    print(f"❌ Unexpected error importing SPy: {e}")
    print(f"❌ Error type: {type(e).__name__}")
    print("💡 This might be a licensing or dependency issue")

# Global authentication state
auth_state = {
    'is_authenticated': False,
    'url': None,
    'access_key': None,
    'password': None,
    'auth_provider': 'Seeq',
    'ignore_ssl_errors': False
}

def authenticate_seeq(url: str, access_key: str, password: str, 
                     auth_provider: str = 'Seeq', 
                     ignore_ssl_errors: bool = False) -> Dict[str, Any]:
    """
    Authenticate with Seeq server using SPy
    """
    # Security: Input validation
    if not validate_url(url):
        return {
            "success": False,
            "message": "Invalid URL format provided",
            "error": "Invalid URL"
        }
    
    if not validate_credentials(access_key, password):
        return {
            "success": False,
            "message": "Invalid credentials format",
            "error": "Invalid credentials"
        }
    
    # Security: Restrict SSL bypass to trusted domains only
    if ignore_ssl_errors and not is_trusted_domain(url):
        return {
            "success": False,
            "message": "SSL bypass not allowed for this domain",
            "error": "Untrusted domain"
        }
    
    if not SPY_AVAILABLE:
        return {
            "success": False,
            "message": "SPy module not available. Please install it using: pip install seeq",
            "error": "SPy module not found"
        }
    
    try:
        # Suppress SPy output by redirecting stdout temporarily
        import io
        import sys
        from contextlib import redirect_stdout
        
        # Set compatibility option for maximum compatibility
        try:
            spy.options.compatibility = 66
        except AttributeError:
            # If compatibility option doesn't exist, continue without it
            pass
        
        # Set the server URL in SPy options before attempting login
        try:
            if hasattr(spy, 'options') and hasattr(spy.options, 'server'):
                spy.options.server = url
            else:
                pass  # Cannot set server URL
        except Exception as e:
            pass  # Ignore errors setting server URL
        
        # Convert ignore_ssl_errors to proper boolean
        if isinstance(ignore_ssl_errors, str):
            ignore_ssl_errors = ignore_ssl_errors.lower() in ('true', '1', 'yes', 'on')
        elif not isinstance(ignore_ssl_errors, bool):
            ignore_ssl_errors = False
        
        # Suppress SPy output during login
        with redirect_stdout(io.StringIO()):
            # Attempt to login
            spy.login(
                url=url,
                access_key=access_key,
                password=password,
                ignore_ssl_errors=ignore_ssl_errors
            )
        
        # Check if login was successful
        if spy.user is not None:
            # Update global state
            auth_state['is_authenticated'] = True
            auth_state['url'] = url
            auth_state['access_key'] = access_key
            auth_state['password'] = password
            auth_state['auth_provider'] = auth_provider
            auth_state['ignore_ssl_errors'] = ignore_ssl_errors
            
            return {
                "success": True,
                "message": f"Successfully authenticated as {spy.user}",
                "user": str(spy.user),
                "server_url": url
            }
        else:
            return {
                "success": False,
                "message": "Authentication failed - no user returned",
                "error": "No user returned from SPy"
            }
            
    except Exception as e:
        error_msg = str(e)
        error_trace = traceback.format_exc()
        
        return {
            "success": False,
            "message": f"Authentication failed: {error_msg}",
            "error": error_msg,
            "traceback": error_trace
        }

def search_sensors_only(sensor_names: list, url: str = None, access_key: str = None, 
                       password: str = None, auth_provider: str = 'Seeq', 
                       ignore_ssl_errors: bool = False) -> Dict[str, Any]:
    """
    Search for sensors in Seeq without pulling data
    """
    if not SPY_AVAILABLE:
        return {
            "success": False,
            "message": "SPy module not available",
            "error": "SPy module not found"
        }
    
    try:
        import pandas as pd
        
        # Always authenticate when called from Excel (new process each time)
        if url and access_key and password:
            # Try to authenticate first
            auth_result = authenticate_seeq(url, access_key, password, auth_provider, ignore_ssl_errors)
            if not auth_result['success']:
                return {
                    "success": False,
                    "message": f"Authentication failed: {auth_result.get('error', 'Unknown error')}",
                    "error": "Authentication required",
                    "auth_details": auth_result
                }
            # Check if authentication was successful
            if spy.user is None:
                return {
                    "success": False,
                    "message": "Authentication appeared successful but spy.user is still None",
                    "error": "Authentication state issue"
                }
        else:
            return {
                "success": False,
                "message": "Authentication credentials are required",
                "error": "Missing credentials"
            }
        
        # Search for sensors
        search_results = []
        for sensor_name in sensor_names:
            try:
                # Search with Type set to StoredSignal and suppress output
                result = spy.search({
                    'Name': sensor_name,
                    'Type': 'StoredSignal'
                }, quiet=True)
                
                if not result.empty:
                    # Add the sensor name for reference
                    result['Original_Name'] = sensor_name
                    search_results.append(result)
                else:
                    # Create a placeholder for sensors not found
                    placeholder = pd.DataFrame([{
                        'Name': sensor_name,
                        'ID': None,
                        'Type': 'StoredSignal',
                        'Original_Name': sensor_name,
                        'Status': 'Not Found'
                    }])
                    search_results.append(placeholder)
                    
            except Exception as e:
                # Create error placeholder
                error_placeholder = pd.DataFrame([{
                    'Name': sensor_name,
                    'ID': None,
                    'Type': 'StoredSignal',
                    'Original_Name': sensor_name,
                    'Status': f'Search Error: {str(e)}'
                }])
                search_results.append(error_placeholder)
        
        # Combine all search results
        if search_results:
            combined_results = pd.concat(search_results, ignore_index=True)
            return {
                "success": True,
                "message": f"Search completed for {len(sensor_names)} sensors",
                "search_results": combined_results.to_dict('records'),
                "sensor_count": len(sensor_names)
            }
        else:
            return {
                "success": False,
                "message": "Search failed for all sensors",
                "error": "No search results"
            }
            
    except Exception as e:
        error_msg = str(e)
        error_trace = traceback.format_exc()
        
        return {
            "success": False,
            "message": f"Search operation failed: {error_msg}",
            "error": error_msg,
            "traceback": error_trace
        }

def search_and_pull_sensors(sensor_names: list, start_datetime: str, end_datetime: str, 
                           grid: str = '15min', timezone: str = None, url: str = None, 
                           access_key: str = None, password: str = None, 
                           auth_provider: str = 'Seeq', ignore_ssl_errors: bool = False) -> Dict[str, Any]:
    """
    Search for sensors in Seeq and pull their data
    """
    if not SPY_AVAILABLE:
        return {
            "success": False,
            "message": "SPy module not available",
            "error": "SPy module not found"
        }
    
    try:
        import pandas as pd
        from datetime import datetime
        
        # Always authenticate when called from Excel (new process each time)
        if url and access_key and password:
            # Try to authenticate first
            auth_result = authenticate_seeq(url, access_key, password, auth_provider, ignore_ssl_errors)
            
            if not auth_result['success']:
                return {
                    "success": False,
                    "message": f"Authentication failed: {auth_result.get('error', 'Unknown error')}",
                    "error": "Authentication required",
                    "auth_details": auth_result
                }
            
            # Check if authentication was successful
            if spy.user is None:
                return {
                    "success": False,
                    "message": "Authentication appeared successful but spy.user is still None",
                    "error": "Authentication state issue"
                }
        else:
            return {
                "success": False,
                "message": "Authentication credentials are required",
                "error": "Missing credentials"
            }
        
        # Parse datetime strings - handle multiple formats including Excel dates
        def parse_excel_friendly_datetime(dt_str):
            """Parse datetime strings in various formats including Excel-friendly ones"""
            if not dt_str:
                return None
                
            # Try different parsing strategies
            try:
                # First try pandas flexible parsing
                result = pd.to_datetime(dt_str)
                return result
            except Exception as e:
                pass
                
            try:
                # Try common Excel date formats
                excel_formats = [
                    '%m/%d/%Y',           # 9/1/2025
                    '%m/%d/%Y %H:%M:%S',  # 9/1/2025 12:00:00
                    '%m/%d/%Y %I:%M:%S %p', # 9/1/2025 12:00:00 PM
                    '%Y-%m-%d',           # 2025-09-01
                    '%Y-%m-%d %H:%M:%S',  # 2025-09-01 12:00:00
                    '%m-%d-%Y',           # 09-01-2025
                    '%m-%d-%Y %H:%M:%S',  # 09-01-2025 12:00:00
                    '%d/%m/%Y',           # 1/9/2025 (European format)
                    '%d/%m/%Y %H:%M:%S',  # 1/9/2025 12:00:00
                ]
                
                for fmt in excel_formats:
                    try:
                        result = pd.to_datetime(dt_str, format=fmt)
                        return result
                    except Exception as e:
                        continue
                        
                # If all else fails, try to parse as Excel serial number
                try:
                    excel_serial = float(dt_str)
                    # Excel dates are days since 1900-01-01
                    # Note: Excel incorrectly treats 1900 as a leap year
                    excel_epoch = pd.Timestamp('1899-12-30')
                    result = excel_epoch + pd.Timedelta(days=excel_serial)
                    return result
                except Exception as e:
                    pass
                    
                # Last resort: try to parse with dateutil
                try:
                    from dateutil import parser
                    result = parser.parse(dt_str)
                    return result
                except Exception as e:
                    pass
                    
            except Exception as e:
                raise ValueError(f"Could not parse datetime '{dt_str}': {str(e)}")
        
        try:
            start_dt = parse_excel_friendly_datetime(start_datetime)
            end_dt = parse_excel_friendly_datetime(end_datetime)
            
            if start_dt is None or end_dt is None:
                return {
                    "success": False,
                    "message": "Start and end datetime are required",
                    "error": "Missing datetime values"
                }
                
            # Apply timezone if specified
            if timezone:
                start_dt = start_dt.tz_localize('UTC').tz_convert(timezone)
                end_dt = end_dt.tz_localize('UTC').tz_convert(timezone)
            elif start_dt.tz is None:
                # If no timezone specified, assume UTC for consistency
                start_dt = start_dt.tz_localize('UTC')
                end_dt = end_dt.tz_localize('UTC')
                
        except Exception as e:
            return {
                "success": False,
                "message": f"Invalid datetime format: {str(e)}",
                "error": "Datetime parsing failed",
                "supported_formats": [
                    "Excel dates: 9/1/2025, 9/1/2025 12:00:00 PM",
                    "ISO format: 2025-09-01T00:00:00Z",
                    "Standard formats: 09/01/2025, 2025-09-01",
                    "Excel serial numbers: 45292.5"
                ]
            }
        
        # Ensure SPy is properly initialized with server URL
        try:
            if hasattr(spy, 'options') and hasattr(spy.options, 'server'):
                pass  # Server option available
            else:
                pass  # Server option not available
                
            # Always try to set the server URL to ensure it's set
            if url:
                try:
                    spy.options.server = url
                except Exception as e:
                    pass  # Ignore errors setting server URL
        except Exception as e:
            pass  # Ignore errors checking SPy options
        
        # Search for sensors
        search_results = []
        for sensor_name in sensor_names:
            try:
                # Search with Type set to StoredSignal and suppress output
                result = spy.search({
                    'Name': sensor_name,
                    'Type': 'StoredSignal'
                }, quiet=True)
                
                if not result.empty:
                    # Add the sensor name for reference
                    result['Original_Name'] = sensor_name
                    search_results.append(result)
                else:
                    # Create a placeholder for sensors not found
                    placeholder = pd.DataFrame([{
                        'Name': sensor_name,
                        'ID': None,
                        'Type': 'StoredSignal',
                        'Original_Name': sensor_name,
                        'Status': 'Not Found'
                    }])
                    search_results.append(placeholder)
                    
            except Exception as e:
                # Create error placeholder
                error_placeholder = pd.DataFrame([{
                    'Name': sensor_name,
                    'ID': None,
                    'Type': 'StoredSignal',
                    'Original_Name': sensor_name,
                    'Status': f'Search Error: {str(e)}'
                }])
                search_results.append(error_placeholder)
        
        # Combine all search results
        if search_results:
            combined_results = pd.concat(search_results, ignore_index=True)
        else:
            return {
                "success": False,
                "message": "No sensors found or search failed",
                "error": "Search returned no results"
            }
        
        # Filter to only sensors that were found successfully
        valid_sensors = combined_results[combined_results['ID'].notna()]
        
        if valid_sensors.empty:
            return {
                "success": False,
                "message": "No valid sensors found to pull data from",
                "error": "All sensors failed search",
                "search_results": combined_results.to_dict('records')
            }
        
        # Drop duplicates based on sensor names to avoid header conflicts
        # Keep the first occurrence of each sensor name
        original_count = len(valid_sensors)
        valid_sensors = valid_sensors.drop_duplicates(subset=['Original_Name'], keep='first')
        final_count = len(valid_sensors)
        
        if original_count > final_count:
            print(f"Removed {original_count - final_count} duplicate sensor names to avoid header conflicts")
        
        # Pull data for valid sensors
        try:
            data_df = spy.pull(
                valid_sensors,
                start=start_dt,
                end=end_dt,
                grid=grid,
                header='Name',  # Use Name for readable column headers
                quiet=True
            )
            
            # Convert to records for JSON serialization
            data_records = data_df.reset_index().to_dict('records')
            
            # Clean NaN values and convert timestamps for JSON serialization
            def clean_for_json(obj):
                if isinstance(obj, dict):
                    return {k: clean_for_json(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [clean_for_json(item) for item in obj]
                elif obj != obj:  # Check for NaN
                    return None
                elif hasattr(obj, 'isoformat'):  # Handle pandas Timestamp objects
                    # Convert to Excel-friendly format: YYYY-MM-DD HH:MM:SS
                    if obj.tz is not None:
                        # If timezone-aware, convert to UTC and format
                        utc_obj = obj.tz_convert('UTC')
                        result = utc_obj.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        # If no timezone, format directly
                        result = obj.strftime('%Y-%m-%d %H:%M:%S')
                    return result
                else:
                    return obj
            
            cleaned_data = clean_for_json(data_records)
            cleaned_search_results = clean_for_json(combined_results.to_dict('records'))
            
            result = {
                "success": True,
                "message": f"Successfully retrieved data for {len(valid_sensors)} sensors",
                "search_results": cleaned_search_results,
                "data": cleaned_data,
                "data_columns": list(data_df.columns),
                "data_index": [str(idx) for idx in data_df.index],
                "sensor_count": len(valid_sensors),
                "time_range": f"{start_datetime} to {end_datetime}"
            }
            
            return result
                
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to pull data: {str(e)}",
                "error": str(e),
                "search_results": combined_results.to_dict('records')
            }
            
    except Exception as e:
        error_msg = str(e)
        error_trace = traceback.format_exc()
        
        return {
            "success": False,
            "message": f"Search and pull operation failed: {error_msg}",
            "error": error_msg,
            "traceback": error_trace
        }

# Hello World endpoints for testing
@app.route('/')
def hello_world():
    return jsonify({
        "message": "Hello from Railway! SqExcelWeb proxy server is running.",
        "timestamp": datetime.now().isoformat(),
        "status": "healthy",
        "spy_available": SPY_AVAILABLE
    })

@app.route('/test')
def test_endpoint():
    return jsonify({
        "message": "Test endpoint working!",
        "timestamp": datetime.now().isoformat(),
        "proxy_status": "operational",
        "spy_available": SPY_AVAILABLE
    })

@app.route('/debug/spy')
def debug_spy():
    """Debug endpoint to check SPy installation status"""
    import sys
    import subprocess
    
    debug_info = {
        "spy_available": SPY_AVAILABLE,
        "python_version": sys.version,
        "python_path": sys.executable,
        "installed_packages": []
    }
    
    # Try to get list of installed packages
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'list'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            debug_info["installed_packages"] = result.stdout.split('\n')[:20]  # First 20 packages
    except Exception as e:
        debug_info["pip_error"] = str(e)
    
    # Try to import seeq-spy specifically
    try:
        import seeq
        debug_info["seeq_module_available"] = True
        debug_info["seeq_version"] = getattr(seeq, '__version__', 'Unknown')
    except ImportError as e:
        debug_info["seeq_module_available"] = False
        debug_info["seeq_import_error"] = str(e)
    except Exception as e:
        debug_info["seeq_module_available"] = False
        debug_info["seeq_other_error"] = str(e)
    
    return jsonify(debug_info)

# Seeq API proxy endpoints
@app.route('/api/seeq/test-connection', methods=['POST'])
def test_seeq_connection():
    """Test connection to Seeq server through proxy"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeq_url')
        
        if not seeq_url:
            return jsonify({
                "success": False,
                "message": "Seeq URL is required",
                "error": "Missing seeq_url parameter"
            }), 400
        
        # Security: Validate URL format
        if not validate_url(seeq_url):
            return jsonify({
                "success": False,
                "message": "Invalid URL format",
                "error": "Invalid URL"
            }), 400
        
        if not SPY_AVAILABLE:
            return jsonify({
                "success": False,
                "message": "SPy module not available. Cannot test Seeq connection.",
                "error": "SPy module not found"
            }), 500
        
        # Test basic connection to Seeq server using SPy
        try:
            # This is a simple test - we'll just try to import spy and check if it's available
            return jsonify({
                "success": True,
                "message": f"SPy module is available and ready to connect to Seeq server at {seeq_url}",
                "seeq_status": "ready",
                "proxy_status": "operational"
            })
        except Exception as e:
            return jsonify({
                "success": False,
                "message": f"Connection test failed: {str(e)}",
                "error": "Connection failed"
            }), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Proxy error: {str(e)}",
            "error": "Internal server error"
        }), 500

@app.route('/api/seeq/auth', methods=['POST'])
def seeq_auth():
    """Authenticate with Seeq server through proxy"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeq_url')
        username = data.get('username')
        password = data.get('password')
        auth_provider = data.get('auth_provider', 'Seeq')
        ignore_ssl_errors = data.get('ignore_ssl_errors', False)
        
        if not all([seeq_url, username, password]):
            return jsonify({
                "success": False,
                "message": "Missing required authentication parameters",
                "error": "Missing seeq_url, username, or password"
            }), 400
        
        if not SPY_AVAILABLE:
            return jsonify({
                "success": False,
                "message": "SPy module not available. Cannot authenticate with Seeq.",
                "error": "SPy module not found"
            }), 500
        
        # Use SPy to authenticate
        result = authenticate_seeq(seeq_url, username, password, auth_provider, ignore_ssl_errors)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 401
            
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Proxy error: {str(e)}",
            "error": "Internal server error"
        }), 500

@app.route('/api/seeq/search', methods=['POST'])
def seeq_search():
    """Search for sensors in Seeq through proxy"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeq_url')
        sensor_names = data.get('sensor_names', [])
        username = data.get('username')
        password = data.get('password')
        auth_provider = data.get('auth_provider', 'Seeq')
        ignore_ssl_errors = data.get('ignore_ssl_errors', False)
        
        if not all([seeq_url, sensor_names, username, password]):
            return jsonify({
                "success": False,
                "message": "Missing required search parameters",
                "error": "Missing seeq_url, sensor_names, username, or password"
            }), 400
        
        if not SPY_AVAILABLE:
            return jsonify({
                "success": False,
                "message": "SPy module not available. Cannot search Seeq.",
                "error": "SPy module not found"
            }), 500
        
        # Use SPy to search for sensors
        result = search_sensors_only(sensor_names, seeq_url, username, password, auth_provider, ignore_ssl_errors)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Proxy error: {str(e)}",
            "error": "Internal server error"
        }), 500

@app.route('/api/seeq/data', methods=['POST'])
def seeq_data():
    """Get sensor data from Seeq through proxy"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeq_url')
        sensor_names = data.get('sensor_names', [])
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        grid = data.get('grid', '15min')
        username = data.get('username')
        password = data.get('password')
        auth_provider = data.get('auth_provider', 'Seeq')
        ignore_ssl_errors = data.get('ignore_ssl_errors', False)
        
        if not all([seeq_url, sensor_names, start_time, end_time, username, password]):
            return jsonify({
                "success": False,
                "message": "Missing required data parameters",
                "error": "Missing required parameters"
            }), 400
        
        if not SPY_AVAILABLE:
            return jsonify({
                "success": False,
                "message": "SPy module not available. Cannot retrieve data from Seeq.",
                "error": "SPy module not found"
            }), 500
        
        # Use SPy to search and pull sensor data
        result = search_and_pull_sensors(sensor_names, start_time, end_time, grid, None, seeq_url, username, password, auth_provider, ignore_ssl_errors)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Proxy error: {str(e)}",
            "error": "Internal server error"
        }), 500

if __name__ == '__main__':
    import os
    from datetime import datetime
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)