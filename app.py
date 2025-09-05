from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Hello World endpoints for testing
@app.route('/')
def hello_world():
    return jsonify({
        "message": "Hello from Railway! SqExcelWeb proxy server is running.",
        "timestamp": datetime.now().isoformat(),
        "status": "healthy"
    })

@app.route('/test')
def test_endpoint():
    return jsonify({
        "message": "Test endpoint working!",
        "timestamp": datetime.now().isoformat(),
        "proxy_status": "operational"
    })

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
        
        # Test basic connection to Seeq server
        try:
            response = requests.get(f"{seeq_url}/api/status", timeout=10)
            if response.status_code == 200:
                return jsonify({
                    "success": True,
                    "message": f"Successfully connected to Seeq server at {seeq_url}",
                    "seeq_status": "reachable",
                    "proxy_status": "operational"
                })
            else:
                return jsonify({
                    "success": False,
                    "message": f"Seeq server responded with status {response.status_code}",
                    "error": f"HTTP {response.status_code}"
                }), response.status_code
        except requests.exceptions.RequestException as e:
            return jsonify({
                "success": False,
                "message": f"Failed to connect to Seeq server: {str(e)}",
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
        
        if not all([seeq_url, username, password]):
            return jsonify({
                "success": False,
                "message": "Missing required authentication parameters",
                "error": "Missing seeq_url, username, or password"
            }), 400
        
        # Authenticate with Seeq server
        auth_url = f"{seeq_url}/api/auth"
        auth_data = {
            "username": username,
            "password": password,
            "authProvider": auth_provider
        }
        
        try:
            response = requests.post(auth_url, json=auth_data, timeout=30)
            if response.status_code == 200:
                auth_response = response.json()
                return jsonify({
                    "success": True,
                    "message": f"Successfully authenticated as {username}",
                    "user": username,
                    "server_url": seeq_url,
                    "token": auth_response.get('token', 'authenticated')
                })
            else:
                return jsonify({
                    "success": False,
                    "message": f"Authentication failed with status {response.status_code}",
                    "error": f"HTTP {response.status_code}"
                }), response.status_code
        except requests.exceptions.RequestException as e:
            return jsonify({
                "success": False,
                "message": f"Failed to authenticate with Seeq server: {str(e)}",
                "error": "Authentication failed"
            }), 500
            
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
        
        if not all([seeq_url, sensor_names, username, password]):
            return jsonify({
                "success": False,
                "message": "Missing required search parameters",
                "error": "Missing seeq_url, sensor_names, username, or password"
            }), 400
        
        # For now, return a mock response to test the connection
        # TODO: Implement actual Seeq search functionality
        return jsonify({
            "success": True,
            "message": f"Mock search completed for {len(sensor_names)} sensors",
            "search_results": [
                {
                    "ID": f"mock_{i}",
                    "Name": name,
                    "Type": "Signal",
                    "Original_Name": name,
                    "Status": "Found"
                }
                for i, name in enumerate(sensor_names)
            ],
            "sensor_count": len(sensor_names)
        })
            
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
        
        if not all([seeq_url, sensor_names, start_time, end_time, username, password]):
            return jsonify({
                "success": False,
                "message": "Missing required data parameters",
                "error": "Missing required parameters"
            }), 400
        
        # For now, return a mock response to test the connection
        # TODO: Implement actual Seeq data retrieval functionality
        mock_data = []
        for i in range(10):  # Mock 10 data points
            row = {"Timestamp": f"2024-01-01T{i:02d}:00:00Z"}
            for name in sensor_names:
                row[name] = round(100 + i * 10 + hash(name) % 50, 2)
            mock_data.append(row)
        
        return jsonify({
            "success": True,
            "message": f"Mock data retrieved for {len(sensor_names)} sensors",
            "search_results": [
                {
                    "ID": f"mock_{i}",
                    "Name": name,
                    "Type": "Signal",
                    "Original_Name": name,
                    "Status": "Found"
                }
                for i, name in enumerate(sensor_names)
            ],
            "data": mock_data,
            "data_columns": sensor_names,
            "data_index": ["Timestamp"] + sensor_names,
            "sensor_count": len(sensor_names),
            "time_range": {
                "start": start_time,
                "end": end_time,
                "grid": grid
            }
        })
            
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Proxy error: {str(e)}",
            "error": "Internal server error"
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
