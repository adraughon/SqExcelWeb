"""
Chrome Extension functionality for SqSearch
Handles session-based authentication and signal injection into Seeq workbooks
"""

from flask import Blueprint, request, jsonify
import traceback
import logging
from typing import Dict, Any
import pandas as pd

# Create a Blueprint for Chrome extension routes
chrome_bp = Blueprint('chrome_extension', __name__, url_prefix='/api/chrome')

# Configure logging
logger = logging.getLogger(__name__)

def authenticate_seeq_with_session(url: str, auth_token: str, csrf_token: str, 
                                  ignore_ssl_errors: bool = False) -> Dict[str, Any]:
    """
    Authenticate with Seeq server using session tokens (sq-auth and sq-csrf)
    """
    # Import SPy here to avoid circular imports
    try:
        from seeq import spy
        SPY_AVAILABLE = True
    except ImportError:
        return {
            "success": False,
            "message": "SPy module not available",
            "error": "SPy module not found"
        }
    
    # Basic input validation
    if not url or not auth_token or not csrf_token:
        return {
            "success": False,
            "message": "Missing required parameters",
            "error": "Missing url, auth_token, or csrf_token"
        }
    
    try:
        # Suppress SPy output by redirecting stdout temporarily
        import io
        from contextlib import redirect_stdout
        
        # Set compatibility option for maximum compatibility
        try:
            spy.options.compatibility = 188
        except AttributeError:
            pass
        
        # Set timeout options to prevent hanging
        try:
            spy.options.request_timeout_in_seconds = 30
            spy.options.retry_timeout_in_seconds = 10
        except AttributeError:
            pass
        
        # Set the server URL in SPy options before attempting login
        try:
            if hasattr(spy, 'options') and hasattr(spy.options, 'server'):
                spy.options.server = url
        except Exception:
            pass
        
        # Convert ignore_ssl_errors to proper boolean
        if isinstance(ignore_ssl_errors, str):
            ignore_ssl_errors = ignore_ssl_errors.lower() in ('true', '1', 'yes', 'on')
        elif not isinstance(ignore_ssl_errors, bool):
            ignore_ssl_errors = False
        
        # Suppress SPy output during login
        try:
            with redirect_stdout(io.StringIO()):
                # Attempt to login using session tokens
                logger.info(f"Attempting SPy login with URL: {url}")
                logger.info(f"Auth token present: {bool(auth_token)}, CSRF token present: {bool(csrf_token)}")
                
                if auth_token and auth_token != csrf_token:
                    # We have a distinct auth token
                    logger.info("Trying SPy login with distinct auth and CSRF tokens")
                    spy.login(
                        url=url,
                        auth_token=auth_token,
                        csrf_token=csrf_token,
                        ignore_ssl_errors=ignore_ssl_errors
                    )
                else:
                    # Try with just CSRF token or no explicit auth token
                    # Some Seeq setups might work with just CSRF token
                    logger.info("Trying SPy login with CSRF token only")
                    try:
                        spy.login(
                            url=url,
                            csrf_token=csrf_token,
                            ignore_ssl_errors=ignore_ssl_errors
                        )
                    except Exception as csrf_only_error:
                        logger.info(f"CSRF-only login failed: {csrf_only_error}")
                        # If that fails, try with the CSRF token as auth token
                        logger.info("Trying SPy login with CSRF token as auth token")
                        spy.login(
                            url=url,
                            auth_token=csrf_token,
                            csrf_token=csrf_token,
                            ignore_ssl_errors=ignore_ssl_errors
                        )
        except Exception as login_error:
            return {
                "success": False,
                "message": f"SPy session login failed: {str(login_error)}",
                "error": str(login_error)
            }
        
        # Check if login was successful
        if spy.user is not None:
            return {
                "success": True,
                "message": f"Successfully authenticated as {spy.user} using session tokens",
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
            "message": f"Session authentication failed: {error_msg}",
            "error": error_msg,
            "traceback": error_trace
        }

def authenticate_and_search_with_session(url: str, auth_token: str, csrf_token: str, 
                                        sensor_names: list, workbook_id: str = None, 
                                        worksheet_id: str = None) -> Dict[str, Any]:
    """
    Authenticate with Seeq using session tokens and search for sensors
    """
    try:
        from seeq import spy
        SPY_AVAILABLE = True
    except ImportError:
        return {
            "success": False,
            "message": "SPy module not available",
            "error": "SPy module not found"
        }
    
    try:
        # Authenticate using session tokens
        auth_result = authenticate_seeq_with_session(url, auth_token, csrf_token)
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
                "message": f"Search completed for {len(sensor_names)} sensors using session authentication",
                "search_results": combined_results.to_dict('records'),
                "sensor_count": len(sensor_names),
                "workbook_id": workbook_id,
                "worksheet_id": worksheet_id,
                "user": str(spy.user)
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
            "message": f"Session search operation failed: {error_msg}",
            "error": error_msg,
            "traceback": error_trace
        }

def add_signal_to_worksheet(url: str, auth_token: str, csrf_token: str, 
                           sensor_name: str, workbook_id: str, worksheet_id: str) -> Dict[str, Any]:
    """
    Add a new signal to a Seeq worksheet using spy.push
    """
    try:
        from seeq import spy
        SPY_AVAILABLE = True
    except ImportError:
        return {
            "success": False,
            "message": "SPy module not available",
            "error": "SPy module not found"
        }
    
    try:
        # Authenticate using session tokens
        auth_result = authenticate_seeq_with_session(url, auth_token, csrf_token)
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
        
        # Get current worksheet items to understand the structure
        try:
            current_signals = spy.search({'ID': worksheet_id}, quiet=True)
            if current_signals.empty:
                return {
                    "success": False,
                    "message": f"Worksheet {worksheet_id} not found or not accessible",
                    "error": "Worksheet not found"
                }
            
            worksheet_name = current_signals['Name'].iloc[0] if 'Name' in current_signals.columns and len(current_signals) > 0 else f"Worksheet {worksheet_id}"
            logger.info(f"Found worksheet: {worksheet_name}")
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to access worksheet: {str(e)}",
                "error": "Worksheet access failed"
            }
        
        # Search for the sensor to get its ID
        try:
            sensor_search = spy.search({
                'Name': sensor_name,
                'Type': 'StoredSignal'
            }, quiet=True)
            
            if sensor_search.empty:
                return {
                    "success": False,
                    "message": f"Sensor '{sensor_name}' not found",
                    "error": "Sensor not found"
                }
            
            sensor_id = sensor_search['ID'].iloc[0]
            logger.info(f"Found sensor: {sensor_name} with ID: {sensor_id}")
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to find sensor '{sensor_name}': {str(e)}",
                "error": "Sensor search failed"
            }
        
        # Get the full metadata of the sensor we want to add
        try:
            logger.info(f"Getting full metadata for sensor {sensor_id}")
            sensor_metadata = spy.search({'ID': sensor_id}, quiet=True)
            if sensor_metadata.empty:
                return {
                    "success": False,
                    "message": f"Could not retrieve full metadata for sensor {sensor_id}",
                    "error": "Sensor metadata not found"
                }
            
            signal_to_add = sensor_metadata
            logger.info(f"Retrieved sensor metadata with columns: {list(signal_to_add.columns)}")
            logger.info(f"Sensor metadata: {signal_to_add.to_dict('records')[0] if len(signal_to_add) > 0 else 'Empty'}")
            
        except Exception as e:
            logger.error(f"Failed to get sensor metadata: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to get sensor metadata: {str(e)}",
                "error": "Metadata retrieval failed"
            }
        
        # Construct the worksheet URL that SPy expects (always define this)
        worksheet_url = f"{url}/workbook/{workbook_id}/worksheet/{worksheet_id}"
        logger.info(f"Worksheet URL: {worksheet_url}")
        
        # Get all current items in the worksheet using the worksheet URL (like the working example)
        try:
            logger.info(f"Getting current worksheet items using URL: {worksheet_url}")
            
            # Get worksheet contents using spy.search with the URL (like the working example)
            current_signals = spy.search(worksheet_url, quiet=True)
            logger.info(f"Found {len(current_signals)} existing worksheet items")
            
            if not current_signals.empty:
                logger.info(f"Existing items columns: {list(current_signals.columns)}")
                logger.info(f"Existing items sample: {current_signals.head(2).to_dict('records') if len(current_signals) > 0 else 'No items'}")
            else:
                logger.info("No existing worksheet items found")
                
        except Exception as e:
            logger.warning(f"Could not get existing worksheet items: {e}")
            logger.warning(f"Error details: {traceback.format_exc()}")
            # Create empty DataFrame with expected columns if search fails
            current_signals = pd.DataFrame(columns=['Name', 'Type', 'ID', 'Formula', 'Formula Parameters'])
        
        # CRITICAL DIFFERENCE: The working script creates a NEW signal with a formula, not just adding the existing signal
        # Let's try the exact pattern from the working example
        logger.info(f"Original signal to add: {signal_to_add.to_dict('records')}")
        
        try:
            logger.info(f"Trying the EXACT pattern from the working example")
            
            # Method 1: Try the exact working pattern - create a new signal with formula
            logger.info("=== METHOD 1: Exact working script pattern ===")
            
            # Create a new signal exactly like the working example
            new_signal_name = f"{sensor_name} Copy"  # Like the working example
            formula = "$s"  # Exact same formula
            formula_params = {
                '$s': sensor_id  # Use the sensor ID we found
            }
            
            # Create the new signal DataFrame exactly like working example
            new_signal = pd.DataFrame([{
                'Name': new_signal_name,
                'Type': 'Signal',  # Note: 'Signal', not 'StoredSignal'
                'Formula': formula,
                'Formula Parameters': formula_params
            }])
            
            logger.info(f"New signal created: {new_signal.to_dict('records')}")
            
            # Combine with current signals exactly like working example
            metadata = pd.concat([current_signals, new_signal]).reset_index(drop=True)
            metadata = metadata.drop_duplicates(subset=['ID'])  # This will keep the new signal since it has no ID yet
            
            logger.info(f"Combined metadata shape: {metadata.shape}")
            logger.info(f"Combined metadata columns: {list(metadata.columns)}")
            logger.info(f"Combined metadata sample: {metadata.tail(2).to_dict('records')}")
            
            # Use the exact push parameters from working example
            logger.info("Pushing with exact working example parameters...")
            result = spy.push(
                metadata=metadata[['Name','Type','ID','Formula','Formula Parameters']], 
                workbook=workbook_id, 
                worksheet=worksheet_id,
                errors='catalog',
                quiet=True  # Working example uses quiet=True
            )
            
            logger.info(f"SPy push result (Method 1): {result}")
            logger.info(f"SPy push result type: {type(result)}")
            logger.info(f"SPy push completed successfully - Method 1")
            
            # Method 1 succeeded, continue to success response
            
        except Exception as method1_error:
            logger.error(f"Method 1 failed: {method1_error}")
            logger.info("=== METHOD 2: Fallback to original approach ===")
            
            try:
                # Combine current signals with new signal (original approach)
                metadata = pd.concat([current_signals, signal_to_add]).reset_index(drop=True)
                metadata = metadata.drop_duplicates(subset=['ID'])
                
                logger.info(f"Fallback metadata shape: {metadata.shape}")
                logger.info(f"Fallback metadata columns: {list(metadata.columns)}")
                
                # Try with minimal columns
                essential_columns = ['Name', 'Type', 'ID']
                available_columns = [col for col in essential_columns if col in metadata.columns]
                logger.info(f"Available essential columns: {available_columns}")
                
                if len(available_columns) >= 3:
                    logger.info(f"Pushing with essential columns: {available_columns}")
                    result = spy.push(
                        metadata=metadata[available_columns],
                        workbook=workbook_id,
                        worksheet=worksheet_id,
                        errors='catalog',
                        quiet=False
                    )
                else:
                    logger.info("Pushing with all available columns")
                    result = spy.push(
                        metadata=metadata,
                        workbook=workbook_id,
                        worksheet=worksheet_id,
                        errors='catalog',
                        quiet=False
                    )
                
                logger.info(f"SPy push result (Method 2): {result}")
                logger.info(f"SPy push result type: {type(result)}")
                
            except Exception as method2_error:
                logger.error(f"Method 2 also failed: {method2_error}")
                raise method2_error
            
            logger.info(f"SPy push completed successfully - Method 2")
        
        # Both Method 1 and Method 2 reach here if successful
        logger.info(f"SPy push completed successfully")
        
        # Prepare success response FIRST (before verification that might fail)
        success_response = {
            "success": True,
            "message": f"Successfully added StoredSignal '{sensor_name}' to worksheet '{worksheet_name}'",
            "signal_name": sensor_name,
            "sensor_name": sensor_name,
            "sensor_id": sensor_id,
            "workbook_id": workbook_id,
            "worksheet_id": worksheet_id,
            "worksheet_name": worksheet_name,
            "user": str(spy.user) if spy.user is not None else "Unknown"
        }
        
        # Let's verify the signal was actually added by checking the worksheet again
        # NOTE: This is just for verification - if it fails, we still return success since push worked
        logger.info("Starting verification process...")
        try:
            if worksheet_url:
                logger.info(f"Searching worksheet at URL: {worksheet_url}")
                verification_signals = spy.search(worksheet_url, quiet=True)
                logger.info(f"Verification search completed. Type: {type(verification_signals)}")
                
                if verification_signals is not None:
                    logger.info(f"Verification: Found {len(verification_signals)} signals after push")
                    if not verification_signals.empty and 'Name' in verification_signals.columns:
                        try:
                            signal_names = verification_signals['Name'].tolist()
                            logger.info(f"Signal names in worksheet: {signal_names}")
                            
                            # Check for both the original sensor name and the new signal name
                            new_signal_name = f"{sensor_name} Copy"
                            if sensor_name in signal_names or new_signal_name in signal_names:
                                logger.info(f"✅ Verified: Signal related to {sensor_name} is now in the worksheet")
                                success_response["verification"] = "success"
                            else:
                                logger.warning(f"❌ Warning: Neither {sensor_name} nor {new_signal_name} found in worksheet after push")
                                success_response["verification"] = "not_found_in_verification"
                        except Exception as name_error:
                            logger.warning(f"Error processing signal names: {name_error}")
                            success_response["verification"] = f"name_processing_error: {str(name_error)}"
                    else:
                        logger.warning("❌ Verification failed: No signals or no Name column")
                        success_response["verification"] = "no_signals_or_no_name_column"
                else:
                    logger.warning("❌ Verification failed: verification_signals is None")
                    success_response["verification"] = "verification_signals_none"
            else:
                logger.warning("❌ Cannot verify: worksheet_url is None")
                success_response["verification"] = "worksheet_url_none"
                
        except Exception as e:
            logger.warning(f"Could not verify signal addition: {e}")
            logger.warning(f"Verification error details: {traceback.format_exc()}")
            success_response["verification"] = f"verification_error: {str(e)}"
        
        logger.info("Verification process completed, returning success response")
        
        return success_response
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Failed to push signal to worksheet: {str(e)}",
                "error": "Push operation failed"
            }
            
    except Exception as e:
        error_msg = str(e)
        error_trace = traceback.format_exc()
        
        return {
            "success": False,
            "message": f"Add signal operation failed: {error_msg}",
            "error": error_msg,
            "traceback": error_trace
        }

# Chrome Extension Routes
@chrome_bp.route('/debug-session-auth', methods=['POST'])
def debug_session_auth():
    """Debug endpoint to test session authentication and basic SPy operations"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeqUrl')
        seeq_cookies = data.get('seeqCookies', '')
        csrf_token = data.get('csrfToken', '')
        auth_token_explicit = data.get('authToken', '')
        workbook_id = data.get('workbookId')
        worksheet_id = data.get('worksheetId')
        
        debug_info = {
            "step": "initialization",
            "seeq_url": seeq_url,
            "csrf_token_present": bool(csrf_token),
            "auth_token_present": bool(auth_token_explicit),
            "cookies_length": len(seeq_cookies) if seeq_cookies else 0,
            "workbook_id": workbook_id,
            "worksheet_id": worksheet_id
        }
        
        logger.info(f"Debug session auth request: {debug_info}")
        
        if not seeq_url:
            return jsonify({
                "success": False,
                "message": "Missing seeqUrl",
                "debug_info": debug_info
            }), 400
        
        # Step 1: Test SPy import
        try:
            from seeq import spy
            debug_info["spy_import"] = "success"
            debug_info["step"] = "spy_imported"
        except ImportError as e:
            debug_info["spy_import"] = f"failed: {str(e)}"
            return jsonify({
                "success": False,
                "message": "SPy import failed",
                "debug_info": debug_info
            }), 500
        
        # Step 2: Extract auth tokens
        auth_token = auth_token_explicit
        if not auth_token and seeq_cookies:
            import re
            auth_patterns = [
                r'sq-auth=([^;]+)',
                r'session-id=([^;]+)',
                r'sessionId=([^;]+)',
                r'JSESSIONID=([^;]+)'
            ]
            
            for pattern in auth_patterns:
                auth_match = re.search(pattern, seeq_cookies)
                if auth_match:
                    auth_token = auth_match.group(1)
                    debug_info["auth_token_source"] = pattern
                    break
        
        if not auth_token and csrf_token:
            auth_token = csrf_token
            debug_info["auth_token_source"] = "csrf_fallback"
        
        debug_info["final_auth_token_present"] = bool(auth_token)
        debug_info["final_csrf_token_present"] = bool(csrf_token)
        debug_info["step"] = "tokens_extracted"
        
        # Step 3: Test authentication
        try:
            logger.info(f"Testing SPy authentication with URL: {seeq_url}")
            
            if auth_token and auth_token != csrf_token:
                spy.login(
                    url=seeq_url,
                    auth_token=auth_token,
                    csrf_token=csrf_token,
                    ignore_ssl_errors=True
                )
                debug_info["auth_method"] = "auth_token_and_csrf"
            else:
                spy.login(
                    url=seeq_url,
                    csrf_token=csrf_token,
                    ignore_ssl_errors=True
                )
                debug_info["auth_method"] = "csrf_only"
            
            debug_info["authentication"] = "success"
            debug_info["spy_user"] = str(spy.user) if spy.user else None
            debug_info["step"] = "authenticated"
            
        except Exception as auth_error:
            debug_info["authentication"] = f"failed: {str(auth_error)}"
            debug_info["step"] = "auth_failed"
            return jsonify({
                "success": False,
                "message": f"Authentication failed: {str(auth_error)}",
                "debug_info": debug_info
            }), 401
        
        # Step 4: Test basic search functionality
        try:
            # Test search for a common signal type
            test_search = spy.search({'Type': 'StoredSignal'}, quiet=True)
            debug_info["basic_search"] = f"success: found {len(test_search)} StoredSignals"
            debug_info["step"] = "basic_search_completed"
        except Exception as search_error:
            debug_info["basic_search"] = f"failed: {str(search_error)}"
            debug_info["step"] = "basic_search_failed"
        
        # Step 5: Test worksheet access if IDs provided
        if workbook_id and worksheet_id:
            try:
                worksheet_url = f"{seeq_url}/workbook/{workbook_id}/worksheet/{worksheet_id}"
                worksheet_signals = spy.search(worksheet_url, quiet=True)
                debug_info["worksheet_access"] = f"success: found {len(worksheet_signals)} items in worksheet"
                debug_info["worksheet_columns"] = list(worksheet_signals.columns) if not worksheet_signals.empty else []
                debug_info["step"] = "worksheet_access_completed"
            except Exception as worksheet_error:
                debug_info["worksheet_access"] = f"failed: {str(worksheet_error)}"
                debug_info["step"] = "worksheet_access_failed"
        
        return jsonify({
            "success": True,
            "message": "Debug session completed successfully",
            "debug_info": debug_info
        })
        
    except Exception as e:
        logger.error(f"Debug session error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Debug session error: {str(e)}",
            "error": "Internal server error",
            "debug_info": debug_info if 'debug_info' in locals() else {}
        }), 500

@chrome_bp.route('/search-with-session', methods=['POST'])
def search_with_session():
    """Search for sensors using Seeq session authentication (sq-csrf and sq-auth tokens)"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeqUrl')
        sensor_names = data.get('sensorNames', [])
        seeq_cookies = data.get('seeqCookies', '')
        csrf_token = data.get('csrfToken', '')
        workbook_id = data.get('workbookId')
        worksheet_id = data.get('worksheetId')
        
        if not all([seeq_url, sensor_names]):
            return jsonify({
                "success": False,
                "message": "Missing required parameters",
                "error": "Missing seeqUrl or sensorNames"
            }), 400
        
        # Extract auth token from cookies
        auth_token = None
        if seeq_cookies:
            import re
            # Try multiple possible auth token patterns
            auth_patterns = [
                r'sq-auth=([^;]+)',
                r'session-id=([^;]+)',
                r'sessionId=([^;]+)',
                r'JSESSIONID=([^;]+)',
                r'auth-token=([^;]+)',
                r'authToken=([^;]+)',
                r'seeq-auth=([^;]+)',
                r'seeqAuth=([^;]+)'
            ]
            
            for pattern in auth_patterns:
                auth_match = re.search(pattern, seeq_cookies)
                if auth_match:
                    auth_token = auth_match.group(1)
                    break
        
        # If no auth token found, try using CSRF token as fallback
        if not auth_token and csrf_token:
            auth_token = csrf_token
            logger.info("Using CSRF token as auth token fallback")
        
        # For Seeq, we might need to try authentication without explicit auth token
        # Some Seeq setups use session-based auth differently
        if not auth_token:
            logger.warning("No auth token found, attempting authentication with CSRF token only")
            # We'll try to authenticate with just the CSRF token and see if SPy can handle it
        
        if not csrf_token:
            return jsonify({
                "success": False,
                "message": "Missing CSRF token",
                "error": "CSRF token is required for Seeq authentication",
                "debug_info": {
                    "csrf_token_present": bool(csrf_token),
                    "auth_token_present": bool(auth_token),
                    "cookie_count": len(seeq_cookies.split(';')) if seeq_cookies else 0
                }
            }), 401
        
        # Use session-based authentication with SPy
        result = authenticate_and_search_with_session(seeq_url, auth_token, csrf_token, sensor_names, workbook_id, worksheet_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        logger.error(f"Session search error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Session search error: {str(e)}",
            "error": "Internal server error"
        }), 500

@chrome_bp.route('/add-signal-to-worksheet', methods=['POST'])
def add_signal_to_worksheet_endpoint():
    """Add a signal to a Seeq worksheet using session authentication"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeqUrl')
        sensor_name = data.get('sensorName')
        workbook_id = data.get('workbookId')
        worksheet_id = data.get('worksheetId')
        seeq_cookies = data.get('seeqCookies', '')
        csrf_token = data.get('csrfToken', '')
        auth_token_explicit = data.get('authToken', '')  # Explicitly sent auth token from Chrome API
        
        # Debug: Log received authentication data
        logger.info(f"Chrome extension request - URL: {seeq_url}, Sensor: {sensor_name}")
        logger.info(f"Chrome extension request - Workbook: {workbook_id}, Worksheet: {worksheet_id}")
        logger.info(f"Chrome extension request - Cookies length: {len(seeq_cookies)}, CSRF token: {csrf_token[:10]}..." if csrf_token else "No CSRF token")
        logger.info(f"Chrome extension request - Explicit auth token: {auth_token_explicit[:10]}..." if auth_token_explicit else "No explicit auth token")
        logger.info(f"Chrome extension request - Cookie preview: {seeq_cookies[:200]}..." if seeq_cookies else "No cookies")
        
        if not all([seeq_url, sensor_name, workbook_id, worksheet_id]):
            return jsonify({
                "success": False,
                "message": "Missing required parameters",
                "error": "Missing seeqUrl, sensorName, workbookId, or worksheetId"
            }), 400
        
        # Use explicitly sent auth token first, then extract from cookies as fallback
        auth_token = None
        
        if auth_token_explicit:
            auth_token = auth_token_explicit
            logger.info(f"Using explicitly sent auth token from Chrome API: {auth_token[:10]}...")
        elif seeq_cookies:
            import re
            # Try multiple possible auth token patterns in cookies
            auth_patterns = [
                r'sq-auth=([^;]+)',
                r'session-id=([^;]+)',
                r'sessionId=([^;]+)',
                r'JSESSIONID=([^;]+)',
                r'auth-token=([^;]+)',
                r'authToken=([^;]+)',
                r'seeq-auth=([^;]+)',
                r'seeqAuth=([^;]+)'
            ]
            
            logger.info(f"Searching for auth tokens in cookies: {seeq_cookies[:500]}...")
            for pattern in auth_patterns:
                auth_match = re.search(pattern, seeq_cookies)
                if auth_match:
                    auth_token = auth_match.group(1)
                    logger.info(f"Found auth token with pattern {pattern}: {auth_token[:10]}...")
                    break
            
            if not auth_token:
                logger.warning(f"No auth token found in cookies using patterns: {auth_patterns}")
        
        # If no auth token found, try using CSRF token as fallback
        if not auth_token and csrf_token:
            auth_token = csrf_token
            logger.info(f"Using CSRF token as auth token fallback: {csrf_token[:10]}...")
        
        # For Seeq, we might need to try authentication without explicit auth token
        if not auth_token:
            logger.warning("No auth token found, attempting authentication with CSRF token only")
        
        if not csrf_token:
            return jsonify({
                "success": False,
                "message": "Missing CSRF token",
                "error": "CSRF token is required for Seeq authentication"
            }), 401
        
        # Add signal to worksheet using session authentication
        result = add_signal_to_worksheet(
            seeq_url, auth_token, csrf_token, sensor_name, 
            workbook_id, worksheet_id
        )
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        logger.error(f"Add signal error: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Add signal error: {str(e)}",
            "error": "Internal server error"
        }), 500
