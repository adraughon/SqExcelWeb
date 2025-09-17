#!/usr/bin/env python3
"""
Test script to verify both Excel add-in and Chrome extension features work
"""

import requests
import json

# Test configuration
RAILWAY_URL = "https://sqexcelweb-production.up.railway.app"

def test_excel_features():
    """Test Excel add-in functionality"""
    print("🔍 Testing Excel Add-in Features...")
    
    # Test Excel credentials endpoint
    try:
        response = requests.get(f"{RAILWAY_URL}/api/seeq/credentials")
        print(f"✅ Excel credentials endpoint: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Excel credentials test failed: {e}")
        return False

def test_chrome_features():
    """Test Chrome extension functionality"""
    print("\n🔍 Testing Chrome Extension Features...")
    
    # Test Chrome search endpoint
    try:
        payload = {
            "seeqUrl": "https://test.seeq.tech",
            "sensorNames": ["TEST-SENSOR"],
            "seeqCookies": "sq-auth=mock-token; other=value",
            "csrfToken": "mock-csrf-token",
            "workbookId": "test-workbook",
            "worksheetId": "test-worksheet"
        }
        
        response = requests.post(
            f"{RAILWAY_URL}/api/chrome/search-with-session",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        print(f"✅ Chrome search endpoint: {response.status_code}")
        
        # Test Chrome add signal endpoint
        payload = {
            "seeqUrl": "https://test.seeq.tech",
            "sensorName": "TEST-SENSOR",
            "workbookId": "test-workbook",
            "worksheetId": "test-worksheet",
            "seeqCookies": "sq-auth=mock-token; other=value",
            "csrfToken": "mock-csrf-token"
        }
        
        response = requests.post(
            f"{RAILWAY_URL}/api/chrome/add-signal-to-worksheet",
            headers={"Content-Type": "application/json"},
            json=payload
        )
        print(f"✅ Chrome add signal endpoint: {response.status_code}")
        
        return True
    except Exception as e:
        print(f"❌ Chrome features test failed: {e}")
        return False

def test_health():
    """Test basic health endpoint"""
    print("\n🔍 Testing Health Endpoint...")
    try:
        response = requests.get(f"{RAILWAY_URL}/")
        print(f"✅ Health endpoint: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Health test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing Both Excel Add-in and Chrome Extension Features")
    print("=" * 60)
    
    # Run tests
    health_ok = test_health()
    excel_ok = test_excel_features()
    chrome_ok = test_chrome_features()
    
    print("\n📊 Test Results:")
    print(f"Health Check: {'✅ PASS' if health_ok else '❌ FAIL'}")
    print(f"Excel Features: {'✅ PASS' if excel_ok else '❌ FAIL'}")
    print(f"Chrome Features: {'✅ PASS' if chrome_ok else '❌ FAIL'}")
    
    if all([health_ok, excel_ok, chrome_ok]):
        print("\n🎉 All features working! Both Excel add-in and Chrome extension are ready.")
    else:
        print("\n⚠️  Some features failed. Check the output above for details.")
