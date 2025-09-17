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
            spy.options.request_timeout_in_seconds = 15  # Reduced from 30
            spy.options.retry_timeout_in_seconds = 5     # Reduced from 10
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
        
        # Get worksheet info for response (but don't fail if we can't get it)
        try:
            worksheet_info = spy.search({'ID': worksheet_id}, quiet=True)
            if not worksheet_info.empty and 'Name' in worksheet_info.columns:
                worksheet_name = worksheet_info['Name'].iloc[0]
                logger.info(f"Found worksheet: {worksheet_name}")
            else:
                worksheet_name = f"Worksheet {worksheet_id}"
                logger.info(f"Using default worksheet name: {worksheet_name}")
            
        except Exception as e:
            logger.warning(f"Could not get worksheet info: {e}")
            worksheet_name = f"Worksheet {worksheet_id}"
        
        # Search for the sensor to get its ID
        try:
            logger.info(f"Searching for sensor: {sensor_name}")
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
            logger.error(f"Sensor search failed: {str(e)}")
            logger.error(f"Sensor search error details: {traceback.format_exc()}")
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
        
        # CRITICAL: Try to use SPy utility functions to get proper IDs like the working example
        try:
            logger.info("Trying to extract workbook/worksheet IDs using SPy utilities...")
            spy_workbook_id = spy.utils.get_workbook_id_from_url(worksheet_url)
            spy_worksheet_id = spy.utils.get_worksheet_id_from_url(worksheet_url)
            logger.info(f"SPy utility extracted - Workbook ID: {spy_workbook_id}, Worksheet ID: {spy_worksheet_id}")
            logger.info(f"Chrome parsed - Workbook ID: {workbook_id}, Worksheet ID: {worksheet_id}")
            
            # CRITICAL: Always use SPy-extracted IDs if available (like working script)
            if spy_workbook_id and spy_worksheet_id:
                if spy_workbook_id != workbook_id or spy_worksheet_id != worksheet_id:
                    logger.info(f"⚠️ ID MISMATCH DETECTED! Using SPy-extracted IDs instead of Chrome-parsed IDs")
                    logger.info(f"Chrome: wb={workbook_id}, ws={worksheet_id}")
                    logger.info(f"SPy: wb={spy_workbook_id}, ws={spy_worksheet_id}")
                    workbook_id = spy_workbook_id
                    worksheet_id = spy_worksheet_id
                    # Rebuild worksheet URL with correct IDs
                    worksheet_url = f"{url}/workbook/{workbook_id}/worksheet/{worksheet_id}"
                    logger.info(f"Updated worksheet URL: {worksheet_url}")
                else:
                    logger.info("✅ SPy-extracted IDs match Chrome-parsed IDs")
            else:
                logger.warning("⚠️ SPy utilities returned empty IDs, keeping Chrome-parsed IDs")
                
        except Exception as spy_utils_error:
            logger.warning(f"SPy utilities failed: {spy_utils_error}")
            logger.info("Continuing with Chrome-parsed IDs")
        
        # CRITICAL: Follow the EXACT working script pattern
        logger.info("=== FOLLOWING EXACT WORKING SCRIPT PATTERN ===")
        
        # Step 1: Get current worksheet items using worksheet URL (like working script)
        try:
            logger.info(f"Getting current worksheet items using URL: {worksheet_url}")
            current_signals = spy.search(worksheet_url, quiet=True)  # Direct URL search like working script
            logger.info(f"Found {len(current_signals)} existing worksheet items")
            
            if not current_signals.empty:
                logger.info(f"Existing items columns: {list(current_signals.columns)}")
                logger.info(f"Existing items sample: {current_signals.head(2).to_dict('records') if len(current_signals) > 0 else 'No items'}")
                
                # CRITICAL INSIGHT: Maybe we need to filter current_signals to only the essential columns
                # that the working script would have, to avoid column mismatch issues
                essential_columns = ['Name', 'Type', 'ID', 'Formula', 'Formula Parameters']
                available_essential = [col for col in essential_columns if col in current_signals.columns]
                logger.info(f"Available essential columns in current signals: {available_essential}")
                
                # Keep only essential columns for consistency with working script
                if len(available_essential) >= 3:  # Need at least Name, Type, ID
                    current_signals = current_signals[available_essential].copy()
                    logger.info(f"Filtered current_signals to essential columns: {list(current_signals.columns)}")
                
            else:
                logger.info("No existing worksheet items found")
                
        except Exception as e:
            logger.warning(f"Could not get existing worksheet items: {e}")
            logger.warning(f"Error details: {traceback.format_exc()}")
            # Create empty DataFrame with expected columns if search fails
            current_signals = pd.DataFrame(columns=['Name', 'Type', 'ID', 'Formula', 'Formula Parameters'])
        
        # Step 2: Create new signal exactly like working script
        try:
            new_signal_name = f"{sensor_name} Copy"
            
            # Check if signal already exists to avoid conflicts
            logger.info(f"Checking if signal '{new_signal_name}' already exists...")
            try:
                existing_signal_check = spy.search({'Name': new_signal_name}, workbook=workbook_id, quiet=True)
                if not existing_signal_check.empty:
                    logger.warning(f"Signal '{new_signal_name}' already exists. Using unique name.")
                    import time
                    timestamp = int(time.time())
                    new_signal_name = f"{sensor_name} Copy {timestamp}"
                    logger.info(f"Using unique name: {new_signal_name}")
            except Exception as name_check_error:
                logger.warning(f"Could not check for existing signal: {name_check_error}")
            
            # Create new signal DataFrame exactly like working script
            new_signal = pd.DataFrame([{
                'Name': new_signal_name,
                'Type': 'Signal',  # Calculated signal type
                'Formula': '$s',   # Simple formula referencing original signal
                'Formula Parameters': {
                    '$s': sensor_id  # Reference to original signal ID
                }
            }])
            
            logger.info(f"New signal metadata: {new_signal.to_dict('records')}")
            
            # Step 3: Combine exactly like working script
            metadata = pd.concat([current_signals, new_signal]).reset_index(drop=True)
            metadata = metadata.drop_duplicates(subset=['ID'])
            
            logger.info(f"Combined metadata shape: {metadata.shape}")
            logger.info(f"Combined metadata columns: {list(metadata.columns)}")
            
            # Step 4: Push using EXACT working script pattern with EXACT columns
            logger.info("Pushing using exact working script pattern...")
            logger.info(f"Target workbook: {workbook_id}")
            logger.info(f"Target worksheet: {worksheet_id}")
            
            # CRITICAL: Use exact same columns as working script
            push_columns = ['Name','Type','ID','Formula','Formula Parameters']
            available_columns = [col for col in push_columns if col in metadata.columns]
            logger.info(f"Available push columns: {available_columns}")
            
            if len(available_columns) >= 3:  # Need at least Name, Type, ID
                push_metadata = metadata[available_columns]
                logger.info(f"Pushing metadata with columns: {available_columns}")
                logger.info(f"Push metadata sample: {push_metadata.tail(1).to_dict('records')}")  # Show the new signal
                
                result = spy.push(
                    metadata=push_metadata, 
                    workbook=workbook_id, 
                    worksheet=worksheet_id,
                    errors='catalog',
                    quiet=True
                )
            else:
                logger.warning(f"Not enough required columns available. Using all columns.")
                result = spy.push(
                    metadata=metadata, 
                    workbook=workbook_id, 
                    worksheet=worksheet_id,
                    errors='catalog',
                    quiet=True
                )
            
            # Check if the result indicates any issues
            if 'Push Result' in result.columns:
                push_results = result['Push Result'].tolist()
                logger.info(f"Push results: {push_results}")
                failed_pushes = [r for r in push_results if r != 'Success']
                if failed_pushes:
                    logger.warning(f"Some pushes failed: {failed_pushes}")
            
            # Check for error messages in result
            if 'Error' in result.columns:
                errors = result['Error'].dropna().tolist()
                if errors:
                    logger.warning(f"Push errors detected: {errors}")
            
            if 'Result' in result.columns:
                results = result['Result'].dropna().tolist()
                if results:
                    logger.info(f"Push results details: {results}")
            
            logger.info(f"SPy push result shape: {result.shape}")
            logger.info(f"SPy push result columns: {list(result.columns)}")
            
            # Log the new signal details from push result
            if len(result) >= 2:
                new_signal_result = result.iloc[-1]  # Last row should be our new signal
                logger.info(f"New signal from push result: Name={new_signal_result.get('Name', 'N/A')}, ID={new_signal_result.get('ID', 'N/A')}, Type={new_signal_result.get('Type', 'N/A')}")
            
            logger.info(f"Working script pattern push completed successfully")
            
            # CRITICAL: Add the new signal to worksheet display items (missing step!)
            logger.info("=== ADDING SIGNAL TO WORKSHEET DISPLAY ITEMS ===")
            try:
                # Get the new signal ID from push result
                if len(result) >= 2:
                    new_signal_result = result.iloc[-1]  # Last row should be our new signal
                    new_signal_id = new_signal_result.get('ID')
                    new_signal_name_from_result = new_signal_result.get('Name')
                    
                    if new_signal_id:
                        logger.info(f"Adding signal {new_signal_name_from_result} (ID: {new_signal_id}) to worksheet display items")
                        
                        # Pull the workbook and access the worksheet (new API)
                        logger.info(f"Pulling workbook {workbook_id}")
                        workbook_list = spy.workbooks.pull(workbook_id)
                        logger.info(f"Pulled workbook: {type(workbook_list)}")
                        
                        # Extract the actual workbook from the WorkbookList
                        if hasattr(workbook_list, '__iter__') and len(workbook_list) > 0:
                            workbook = workbook_list[0]  # Get first (and should be only) workbook
                            logger.info(f"Extracted workbook from list: {type(workbook)}")
                        else:
                            workbook = workbook_list  # Maybe it's already the workbook
                        
                        # Find the worksheet in the workbook
                        logger.info(f"Looking for worksheet {worksheet_id} in workbook")
                        worksheet = None
                        
                        # Debug: log workbook attributes
                        logger.info(f"Workbook attributes: {[attr for attr in dir(workbook) if not attr.startswith('_')]}")
                        
                        if hasattr(workbook, 'worksheets'):
                            worksheets = workbook.worksheets
                            logger.info(f"Worksheets type: {type(worksheets)}")
                            
                            if hasattr(worksheets, 'keys'):
                                # It's a dict-like object
                                worksheet_names = list(worksheets.keys())
                                logger.info(f"Available worksheets: {worksheet_names}")
                                
                                # Try to find worksheet by ID or name
                                for ws_name, ws_obj in worksheets.items():
                                    logger.info(f"Checking worksheet '{ws_name}': {type(ws_obj)}")
                                    if hasattr(ws_obj, 'id'):
                                        logger.info(f"Worksheet '{ws_name}' ID: {ws_obj.id}")
                                        if ws_obj.id == worksheet_id:
                                            worksheet = ws_obj
                                            logger.info(f"✅ Found worksheet by ID: {ws_name}")
                                            break
                                
                                # If not found by ID, try first worksheet as fallback
                                if worksheet is None and worksheets:
                                    worksheet = list(worksheets.values())[0]
                                    logger.info(f"⚠️ Using first available worksheet as fallback: {worksheet_names[0]}")
                            else:
                                logger.warning(f"Worksheets object doesn't have keys() method: {type(worksheets)}")
                        else:
                            logger.error("Workbook doesn't have 'worksheets' attribute")
                        
                        if worksheet is None:
                            logger.error("Could not find worksheet in workbook")
                            raise Exception(f"Worksheet {worksheet_id} not found in workbook {workbook_id}")
                        
                        logger.info(f"Using worksheet: {type(worksheet)}")
                        
                        # STEP 1: Pull current workstep to sync with UI (following docs exactly)
                        logger.info("Pulling current workstep to sync with UI...")
                        worksheet.pull_current_workstep(quiet=True)
                        logger.info("Current workstep pulled successfully")
                        
                        # STEP 2: Add the new signal to the worksheet's display items (following docs pattern)
                        new_display_item = pd.DataFrame([{
                            'ID': new_signal_id,
                            'Type': 'Signal'  # Add Type as required by API
                        }])
                        logger.info(f"Created new display item: {new_display_item.to_dict('records')}")
                        
                        # Get current display items
                        current_display_items = worksheet.display_items
                        logger.info(f"Current display items: {len(current_display_items) if current_display_items is not None and not current_display_items.empty else 0}")
                        
                        # Add new signal to display items (following docs pattern)
                        if current_display_items is not None and not current_display_items.empty:
                            worksheet.display_items = pd.concat([current_display_items, new_display_item], ignore_index=True)
                        else:
                            worksheet.display_items = new_display_item
                        
                        logger.info(f"Updated display items: {len(worksheet.display_items)}")
                        
                        # STEP 3: Push the workstep back to Seeq (following docs exactly)
                        logger.info("Pushing current workstep back to Seeq...")
                        worksheet_push_result = worksheet.push_current_workstep(quiet=True)
                        logger.info(f"Worksheet push result: {worksheet_push_result}")
                        
                        logger.info("✅ Successfully added signal to worksheet display items")
                        
                    else:
                        logger.warning("Could not get new signal ID from push result")
                        
                else:
                    logger.warning("Push result doesn't contain expected signal data")
                    
            except Exception as display_error:
                logger.error(f"Failed to add signal to worksheet display items: {display_error}")
                logger.error(f"Display error details: {traceback.format_exc()}")
                # Don't fail the entire operation - signal was still created successfully
                logger.info("Signal was created successfully, but may not appear in worksheet display")
            
            # Success - continue to response
            
        except Exception as working_script_error:
            logger.error(f"Working script pattern failed: {working_script_error}")
            logger.error(f"Error details: {traceback.format_exc()}")
            raise working_script_error
        
        logger.info(f"Working script pattern completed successfully")
        
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
        
        # Let's verify the signal was actually added by checking multiple ways
        # NOTE: This is just for verification - if it fails, we still return success since push worked
        logger.info("Starting comprehensive verification process...")
        try:
            # Method 1: Check worksheet URL
            if worksheet_url:
                logger.info(f"Verification Method 1: Searching worksheet at URL: {worksheet_url}")
                verification_signals = spy.search(worksheet_url, quiet=True)
                logger.info(f"Worksheet verification completed. Found {len(verification_signals)} items")
                
                if not verification_signals.empty and 'Name' in verification_signals.columns:
                    signal_names = verification_signals['Name'].tolist()
                    logger.info(f"Signal names in worksheet: {signal_names}")
                    
                    # Check for both the original sensor name and the new signal name
                    new_signal_name = f"{sensor_name} Copy"
                    if sensor_name in signal_names or new_signal_name in signal_names:
                        logger.info(f"✅ Method 1 Verified: Signal found in worksheet")
                        success_response["verification"] = "worksheet_success"
                    else:
                        logger.warning(f"❌ Method 1: Neither {sensor_name} nor {new_signal_name} found in worksheet")
                        success_response["verification"] = "not_found_in_worksheet"
                else:
                    logger.warning("❌ Method 1: No signals found in worksheet")
                    success_response["verification"] = "no_worksheet_signals"
            
            # Method 2: Check workbook level
            logger.info(f"Verification Method 2: Searching entire workbook")
            try:
                workbook_url = f"{url}/workbook/{workbook_id}"
                workbook_signals = spy.search(workbook_url, quiet=True)
                logger.info(f"Workbook verification completed. Found {len(workbook_signals)} items")
                
                if not workbook_signals.empty and 'Name' in workbook_signals.columns:
                    workbook_signal_names = workbook_signals['Name'].tolist()
                    logger.info(f"All signal names in workbook: {workbook_signal_names}")
                    
                    new_signal_name = f"{sensor_name} Copy"
                    if sensor_name in workbook_signal_names or new_signal_name in workbook_signal_names:
                        logger.info(f"✅ Method 2 Verified: Signal found in workbook")
                        success_response["verification"] = "workbook_success"
                    else:
                        logger.warning(f"❌ Method 2: Signal not found in workbook either")
                        
            except Exception as workbook_error:
                logger.warning(f"Method 2 workbook search failed: {workbook_error}")
            
            # Method 3: Search for workbook-scoped signal using workbook parameter
            logger.info(f"Verification Method 3: Workbook-scoped search")
            try:
                new_signal_name = f"{sensor_name} Copy"
                workbook_scoped_search = spy.search({'Name': new_signal_name}, workbook=workbook_id, quiet=True)
                logger.info(f"Workbook-scoped search completed. Found {len(workbook_scoped_search)} items")
                
                if not workbook_scoped_search.empty:
                    logger.info(f"✅ Method 3 Verified: Signal found in workbook scope")
                    logger.info(f"Workbook-scoped result: {workbook_scoped_search[['Name', 'Type', 'ID']].to_dict('records')}")
                    success_response["verification"] = "workbook_scoped_success"
                else:
                    logger.warning(f"❌ Method 3: Signal not found in workbook-scoped search")
                    
            except Exception as workbook_scoped_error:
                logger.warning(f"Method 3 workbook-scoped search failed: {workbook_scoped_error}")
                
        except Exception as e:
            logger.warning(f"Verification process failed: {e}")
            logger.warning(f"Verification error details: {traceback.format_exc()}")
            success_response["verification"] = f"verification_error: {str(e)}"
        
        logger.info("Verification process completed, returning success response")
        
        return success_response
            
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
