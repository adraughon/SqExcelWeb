#!/usr/bin/env python3
"""
Test script to verify the debug endpoint and SPy functionality
Run this locally to test without the Chrome extension
"""

import requests
import json

# Configuration
RAILWAY_URL = "https://sqexcel.up.railway.app"
SEEQ_URL = "https://talosenergy.seeq.tech"  # Replace with your actual Seeq URL

# Mock session data (you'll need to get real values from your browser)
mock_payload = {
    "seeqUrl": SEEQ_URL,
    "seeqCookies": "sq-csrf=mock-csrf-token; sq-auth=mock-auth-token",  # Replace with real cookies
    "csrfToken": "mock-csrf-token",  # Replace with real CSRF token
    "authToken": "mock-auth-token",  # Replace with real auth token
    "workbookId": "12345678-1234-1234-1234-123456789abc",  # Replace with real workbook ID
    "worksheetId": "87654321-4321-4321-4321-cba987654321"  # Replace with real worksheet ID
}

def test_debug_endpoint():
    """Test the debug session authentication endpoint"""
    print("🧪 Testing debug session authentication endpoint...")
    print(f"🌐 Railway URL: {RAILWAY_URL}")
    print(f"🔗 Seeq URL: {SEEQ_URL}")
    
    try:
        response = requests.post(
            f"{RAILWAY_URL}/api/chrome/debug-session-auth",
            headers={'Content-Type': 'application/json'},
            json=mock_payload,
            timeout=30
        )
        
        print(f"📡 Response Status: {response.status_code}")
        print(f"📡 Response Headers: {dict(response.headers)}")
        
        if response.ok:
            result = response.json()
            print("✅ Debug endpoint successful!")
            print("📊 Debug Results:")
            print(json.dumps(result, indent=2))
        else:
            print("❌ Debug endpoint failed!")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def test_add_signal_endpoint():
    """Test the add signal endpoint"""
    print("\n🧪 Testing add signal to worksheet endpoint...")
    
    add_signal_payload = {
        **mock_payload,
        "sensorName": "GAL-NAK-TT-357501A-ENG-PV"  # Replace with a real sensor name
    }
    
    try:
        response = requests.post(
            f"{RAILWAY_URL}/api/chrome/add-signal-to-worksheet",
            headers={'Content-Type': 'application/json'},
            json=add_signal_payload,
            timeout=30
        )
        
        print(f"📡 Response Status: {response.status_code}")
        
        if response.ok:
            result = response.json()
            print("✅ Add signal endpoint successful!")
            print("📊 Add Signal Results:")
            print(json.dumps(result, indent=2))
        else:
            print("❌ Add signal endpoint failed!")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def get_real_session_data_instructions():
    """Print instructions for getting real session data"""
    print("\n📋 To get real session data for testing:")
    print("1. Open your Seeq workbook in Chrome")
    print("2. Open Chrome DevTools (F12)")
    print("3. Go to Application tab > Cookies")
    print("4. Copy the values for 'sq-auth' and 'sq-csrf' cookies")
    print("5. Go to Network tab, refresh the page")
    print("6. Look for requests with 'x-sq-csrf' header")
    print("7. Update the mock_payload in this script with real values")
    print("8. Get workbook/worksheet IDs from the URL:")
    print("   Format: /workbook/{workbook-id}/worksheet/{worksheet-id}")

if __name__ == "__main__":
    print("🚀 SqExcelWeb Debug Test Script")
    print("=" * 50)
    
    # Check if using mock data
    if "mock" in mock_payload["csrfToken"]:
        print("⚠️  Using mock session data - this will likely fail authentication")
        get_real_session_data_instructions()
        print("\nContinuing with mock data for connection testing...\n")
    
    # Test debug endpoint
    test_debug_endpoint()
    
    # Test add signal endpoint
    test_add_signal_endpoint()
    
    print("\n✅ Test script completed!")
    print("Check the Railway logs for detailed server-side information:")
    print("https://railway.app/dashboard")
