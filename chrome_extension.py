"""
Chrome Extension functionality for SqSearch - Simplified
"""

from flask import Blueprint, request, jsonify
import pandas as pd

chrome_bp = Blueprint('chrome_extension', __name__, url_prefix='/api/chrome')

@chrome_bp.route('/add-signal-to-worksheet', methods=['POST'])
def add_signal_to_worksheet_endpoint():
    """Add a signal to a Seeq worksheet"""
    try:
        data = request.get_json()
        seeq_url = data.get('seeqUrl')
        sensor_name = data.get('sensorName')
        workbook_id = data.get('workbookId')
        worksheet_id = data.get('worksheetId')
        csrf_token = data.get('csrfToken')
        auth_token = data.get('authToken')
        
        if not all([seeq_url, sensor_name, workbook_id, worksheet_id, csrf_token]):
            return jsonify({
                "success": False,
                "message": "Missing required parameters"
            }), 400

        # Import and login to SPy
        from seeq import spy
        spy.login(
            url=seeq_url,
            auth_token=auth_token or csrf_token,
            csrf_token=csrf_token,
            ignore_ssl_errors=True
        )

        # Search for sensor
        sensor_search = spy.search({
            'Name': sensor_name,
            'Type': 'StoredSignal'
        }, quiet=True)
        
        if sensor_search.empty:
            return jsonify({
                "success": False,
                "message": f"Sensor '{sensor_name}' not found"
            }), 404

        sensor_id = sensor_search['ID'].iloc[0]

        # Get current worksheet
        workbook_list = spy.workbooks.pull(workbook_id)
        workbook = workbook_list[0] if len(workbook_list) > 0 else workbook_list
        
        # Find worksheet
        worksheet = None
        for ws_obj in workbook.worksheets:
            if hasattr(ws_obj, 'id') and ws_obj.id == worksheet_id:
                worksheet = ws_obj
                break
        
        if not worksheet:
            worksheet = list(workbook.worksheets.values())[0] if hasattr(workbook.worksheets, 'values') else workbook.worksheets[0]

        # Pull current workstep
        worksheet.pull_current_workstep(quiet=True)
        
        # Add new signal to display items
        new_display_item = pd.DataFrame([{
            'ID': sensor_id,
            'Type': 'Signal'
        }])
        
        current_display_items = worksheet.display_items
        if current_display_items is not None and not current_display_items.empty:
            worksheet.display_items = pd.concat([current_display_items, new_display_item], ignore_index=True)
        else:
            worksheet.display_items = new_display_item
        
        # Push workstep back
        worksheet.push_current_workstep(quiet=True)

        return jsonify({
            "success": True,
            "message": f"Successfully added '{sensor_name}' to worksheet"
        })
            
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500