#!/usr/bin/env python3
"""
Test script for session-based authentication with Seeq
This script tests the new session authentication endpoint
"""

import requests
import json

# Test configuration
RAILWAY_URL = "https://sqexcelweb-production.up.railway.app"
TEST_SEEQ_URL = "https://your-seeq-server.seeq.tech"  # Replace with your actual Seeq URL

def test_health_endpoint():
    """Test if the Railway app is running"""
    print("🔍 Testing Railway app health...")
    try:
        response = requests.get(f"{RAILWAY_URL}/")
        print(f"✅ Health check: {response.status_code}")
        print(f"Response: {response.json()}")
        return True
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_session_auth_endpoint():
    """Test the session authentication endpoint"""
    print("\n🔍 Testing session authentication endpoint...")
    
    # Test payload with mock tokens
    payload = {
        "seeqUrl": TEST_SEEQ_URL,
        "sensorNames": ["TEST-SENSOR-001"],
        "seeqCookies": "sq-auth=mock-auth-token; other=value",
        "csrfToken": "mock-csrf-token",
        "workbookId": "test-workbook-id",
        "worksheetId": "test-worksheet-id"
    }
    
    try:
        response = requests.post(
            f"{RAILWAY_URL}/api/chrome/search-with-session",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        print(f"✅ Session auth endpoint: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"❌ Session auth test failed: {e}")
        return False

def test_add_signal_endpoint():
    """Test the add signal to worksheet endpoint"""
    print("\n🔍 Testing add signal to worksheet endpoint...")
    
    # Test payload with mock tokens
    payload = {
        "seeqUrl": TEST_SEEQ_URL,
        "sensorName": "TEST-SENSOR-001",
        "workbookId": "test-workbook-id",
        "worksheetId": "test-worksheet-id",
        "seeqCookies": "sq-auth=mock-auth-token; other=value",
        "csrfToken": "mock-csrf-token",
        "formula": "$s",
        "formulaParams": {}
    }
    
    try:
        response = requests.post(
            f"{RAILWAY_URL}/api/chrome/add-signal-to-worksheet",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        print(f"✅ Add signal endpoint: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"❌ Add signal test failed: {e}")
        return False

def test_debug_endpoint():
    """Test the debug endpoint to check SPy availability"""
    print("\n🔍 Testing debug endpoint...")
    try:
        response = requests.get(f"{RAILWAY_URL}/debug/spy")
        print(f"✅ Debug endpoint: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return True
    except Exception as e:
        print(f"❌ Debug test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing SqExcelWeb Railway App")
    print("=" * 50)
    
    # Run tests
    health_ok = test_health_endpoint()
    debug_ok = test_debug_endpoint()
    session_ok = test_session_auth_endpoint()
    add_signal_ok = test_add_signal_endpoint()
    
    print("\n📊 Test Results:")
    print(f"Health Check: {'✅ PASS' if health_ok else '❌ FAIL'}")
    print(f"Debug Endpoint: {'✅ PASS' if debug_ok else '❌ FAIL'}")
    print(f"Session Auth: {'✅ PASS' if session_ok else '❌ FAIL'}")
    print(f"Add Signal: {'✅ PASS' if add_signal_ok else '❌ FAIL'}")
    
    if all([health_ok, debug_ok, session_ok, add_signal_ok]):
        print("\n🎉 All tests passed! The Railway app is ready for signal injection.")
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")
