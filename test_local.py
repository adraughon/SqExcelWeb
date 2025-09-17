#!/usr/bin/env python3
"""
Test script to verify the Flask app works locally before deploying to Railway
"""

import requests
import json

def test_endpoint(base_url, endpoint, method='GET', data=None):
    """Test a single endpoint"""
    url = f"{base_url}{endpoint}"
    print(f"\nTesting {method} {url}")
    
    try:
        if method == 'GET':
            response = requests.get(url, timeout=10)
        elif method == 'POST':
            response = requests.post(url, json=data, timeout=10)
        
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    base_url = "http://localhost:5000"
    
    print("Testing SqExcelWeb Flask app locally...")
    print("Make sure to run 'python app.py' in another terminal first!")
    
    # Test basic endpoints
    tests = [
        ('/', 'GET'),
        ('/test', 'GET'),
    ]
    
    # Test Seeq proxy endpoints
    seeq_tests = [
        ('/api/seeq/test-connection', 'POST', {
            'seeq_url': 'https://example-seeq-server.com'
        }),
        ('/api/seeq/auth', 'POST', {
            'seeq_url': 'https://example-seeq-server.com',
            'username': 'test_user',
            'password': 'test_password'
        }),
        ('/api/seeq/search', 'POST', {
            'seeq_url': 'https://example-seeq-server.com',
            'sensor_names': ['sensor1', 'sensor2'],
            'username': 'test_user',
            'password': 'test_password'
        }),
        ('/api/seeq/data', 'POST', {
            'seeq_url': 'https://example-seeq-server.com',
            'sensor_names': ['sensor1', 'sensor2'],
            'start_time': '2024-01-01T00:00:00Z',
            'end_time': '2024-01-01T23:59:59Z',
            'username': 'test_user',
            'password': 'test_password'
        })
    ]
    
    # Test Excel compatibility endpoints
    excel_tests = [
        ('/api/seeq/credentials', 'GET'),
        ('/api/seeq/credentials', 'POST', {
            'url': 'https://example-seeq-server.com',
            'accessKey': 'test_user',
            'password': 'test_password',
            'authProvider': 'Seeq',
            'ignoreSslErrors': False
        }),
        ('/api/seeq/auth/status', 'GET'),
        ('/api/seeq/auth/python-status', 'GET'),
        ('/api/seeq/search-sensors', 'POST', {
            'sensorNames': ['sensor1', 'sensor2'],
            'url': 'https://example-seeq-server.com',
            'accessKey': 'test_user',
            'password': 'test_password'
        }),
        ('/api/seeq/sensor-data', 'POST', {
            'sensorNames': ['sensor1', 'sensor2'],
            'startDatetime': '2024-01-01T00:00:00Z',
            'endDatetime': '2024-01-01T23:59:59Z',
            'url': 'https://example-seeq-server.com',
            'accessKey': 'test_user',
            'password': 'test_password'
        })
    ]
    
    success_count = 0
    total_tests = len(tests) + len(seeq_tests) + len(excel_tests)
    
    # Test basic endpoints
    for endpoint, method in tests:
        if test_endpoint(base_url, endpoint, method):
            success_count += 1
    
    # Test Seeq proxy endpoints
    for test in seeq_tests:
        if len(test) == 2:
            endpoint, method = test
            data = None
        else:
            endpoint, method, data = test
        
        if test_endpoint(base_url, endpoint, method, data):
            success_count += 1
    
    # Test Excel compatibility endpoints
    for test in excel_tests:
        if len(test) == 2:
            endpoint, method = test
            data = None
        else:
            endpoint, method, data = test
        
        if test_endpoint(base_url, endpoint, method, data):
            success_count += 1
    
    print(f"\n{'='*50}")
    print(f"Test Results: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("✅ All tests passed! Ready for Railway deployment.")
    else:
        print("❌ Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()
