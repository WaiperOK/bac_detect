#!/usr/bin/env python3
"""
REST API for bac_detect integration with other security tools
"""
import os
import json
import tempfile
import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from datetime import datetime

from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

from .backdoor_detector import BackdoorDetector, load_patterns, SEVERITY_ORDER

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure upload settings
UPLOAD_FOLDER = tempfile.mkdtemp()
ALLOWED_EXTENSIONS = {'.py', '.js', '.php', '.ts'}

# Initialize detector
detector = BackdoorDetector()

def allowed_file(filename: str) -> bool:
    """Check if file has an allowed extension"""
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

@app.route('/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({'status': 'ok', 'version': '1.3.0'})

@app.route('/scan', methods=['POST'])
def scan_file():
    """
    Endpoint to scan a single file for backdoors
    
    Accepts multipart/form-data with file upload
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        
        # Get scan parameters
        min_severity = request.form.get('min_severity', 'low')
        use_pylint = request.form.get('use_pylint', 'false').lower() == 'true'
        
        # Run scan
        try:
            issues = detector.scan(file_path, use_pylint=use_pylint)
            
            # Filter by severity
            min_sev_level = SEVERITY_ORDER.get(min_severity.lower(), 1)
            filtered_issues = [
                iss for iss in issues
                if SEVERITY_ORDER.get(str(iss['severity']).lower(), 0) >= min_sev_level
            ]
            
            # Prepare response
            scan_result = {
                'scan_time': datetime.now().isoformat(),
                'file': file.filename,
                'issues_count': len(filtered_issues),
                'issues_by_severity': {
                    'critical': len([i for i in filtered_issues if i.get('severity') == 'critical']),
                    'high': len([i for i in filtered_issues if i.get('severity') == 'high']),
                    'medium': len([i for i in filtered_issues if i.get('severity') == 'medium']),
                    'low': len([i for i in filtered_issues if i.get('severity') == 'low'])
                },
                'issues': filtered_issues
            }
            
            # Clean up temp file
            os.unlink(file_path)
            
            return jsonify(scan_result)
            
        except Exception as e:
            logger.error(f"Error scanning file {filename}: {str(e)}")
            return jsonify({'error': f"Scan failed: {str(e)}"}), 500
    else:
        return jsonify({'error': f"File type not supported. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

@app.route('/scan-project', methods=['POST'])
def scan_project():
    """
    Endpoint to scan a project (zip archive) for backdoors
    
    Accepts multipart/form-data with zip archive upload
    """
    if 'project' not in request.files:
        return jsonify({'error': 'No project archive provided'}), 400
        
    file = request.files['project']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if file and file.filename.lower().endswith('.zip'):
        # Create temp directory for project
        project_dir = tempfile.mkdtemp()
        zip_path = os.path.join(project_dir, secure_filename(file.filename))
        file.save(zip_path)
        
        # Extract zip
        import zipfile
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(project_dir)
                
            # Get scan parameters
            min_severity = request.form.get('min_severity', 'low')
            use_pylint = request.form.get('use_pylint', 'false').lower() == 'true'
            check_deps = request.form.get('check_dependencies', 'true').lower() == 'true'
            use_multiprocessing = request.form.get('use_multiprocessing', 'true').lower() == 'true'
            
            # Run scan
            issues = detector.scan(
                project_dir, 
                use_pylint=use_pylint,
                use_multiprocessing=use_multiprocessing,
                check_dependencies=check_deps
            )
            
            # Filter by severity
            min_sev_level = SEVERITY_ORDER.get(min_severity.lower(), 1)
            filtered_issues = [
                iss for iss in issues
                if SEVERITY_ORDER.get(str(iss['severity']).lower(), 0) >= min_sev_level
            ]
            
            # Prepare response
            scan_result = {
                'scan_time': datetime.now().isoformat(),
                'project': file.filename,
                'issues_count': len(filtered_issues),
                'issues_by_severity': {
                    'critical': len([i for i in filtered_issues if i.get('severity') == 'critical']),
                    'high': len([i for i in filtered_issues if i.get('severity') == 'high']),
                    'medium': len([i for i in filtered_issues if i.get('severity') == 'medium']),
                    'low': len([i for i in filtered_issues if i.get('severity') == 'low'])
                },
                'issues': filtered_issues
            }
            
            # Clean up temp files
            import shutil
            shutil.rmtree(project_dir)
            
            return jsonify(scan_result)
            
        except zipfile.BadZipFile:
            return jsonify({'error': 'Invalid ZIP file'}), 400
        except Exception as e:
            logger.error(f"Error scanning project {file.filename}: {str(e)}")
            return jsonify({'error': f"Scan failed: {str(e)}"}), 500
    else:
        return jsonify({'error': 'Only ZIP archives are supported for project scanning'}), 400

def main():
    """Run the API server"""
    parser = argparse.ArgumentParser(description="bac_detect REST API server")
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server to')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind the server to')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    # Check if patterns loaded correctly
    if not detector.patterns or not any(detector.patterns.values()):
        logger.critical("No patterns were loaded. Ensure 'patterns.json' is correctly placed and readable.")
        sys.exit(1)
    
    # Start server
    logger.info(f"Starting bac_detect API server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main() 