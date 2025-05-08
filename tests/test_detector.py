import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add path to source files
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from bac_detect.backdoor_detector import BackdoorDetector, Colors, load_patterns


class TestBackdoorDetector(unittest.TestCase):
    def setUp(self):
        self.detector = BackdoorDetector()
        
    def test_analyze_with_regex(self):
        # Test pattern detection in Python code
        content = """
def dangerous_function():
    user_input = input("Enter command: ")
    eval(user_input)  # This is dangerous
    
    # Another dangerous pattern
    exec(f"print({user_input})")
"""
        
        # Mock patterns for test
        test_patterns = {
            "eval_usage": r"eval\s*\(",
            "exec_usage": r"exec\s*\("
        }
        
        with patch.object(self.detector, 'patterns', {'python': test_patterns}):
            issues = self.detector._analyze_with_regex('test.py', content, 'python')
            
            # Check that both issues are detected
            self.assertEqual(len(issues), 2)
            self.assertIn('eval_usage', issues[0]['message'])
            self.assertIn('exec_usage', issues[1]['message'])
    
    def test_detect_obfuscation(self):
        # Test detection of obfuscated code
        obfuscated_js = """
var _0x1a2b = ['value', 'fromCharCode', 'createElement', 'appendChild'];
function deobfuscate() {
    eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41));
}
"""
        issues = self.detector._detect_obfuscation(obfuscated_js, 'javascript')
        
        # Check detection of obfuscation
        self.assertGreater(len(issues), 0)
        
        # Check types of detected issues
        for issue in issues:
            self.assertEqual(issue['type'], 'obfuscation')
    
    def test_analyze_dependencies(self):
        # Create temporary requirements.txt file with malicious package
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp:
            temp.write("""
# Test requirements file
requests>=2.25.0
crypt==1.0.0  # Malicious package
flask==2.0.0
""")
            temp_path = temp.name
        
        try:
            # Analyze file
            issues = self.detector._analyze_dependencies(temp_path, 'requirements')
            
            # Check if malicious package is found
            self.assertEqual(len(issues), 1)
            self.assertIn('crypt', issues[0]['message'])
            self.assertEqual(issues[0]['severity'], 'high')
        finally:
            # Delete temporary file
            os.unlink(temp_path)
    
    def test_export_to_json(self):
        # Test JSON export
        issues = [
            {
                'file': 'test.py',
                'line': 10,
                'type': 'bandit',
                'message': 'Test issue 1',
                'severity': 'high'
            },
            {
                'file': 'test.js',
                'line': 5,
                'type': 'esprima-ast',
                'message': 'Test issue 2',
                'severity': 'medium'
            }
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp:
            temp_path = temp.name
        
        try:
            # Export issues to JSON
            result = self.detector.export_to_json(issues, temp_path)
            self.assertTrue(result)
            
            # Check contents of exported file
            with open(temp_path, 'r') as f:
                exported_data = json.load(f)
            
            self.assertEqual(exported_data['issues_count'], 2)
            self.assertEqual(exported_data['issues_by_severity']['high'], 1)
            self.assertEqual(exported_data['issues_by_severity']['medium'], 1)
            self.assertEqual(len(exported_data['issues']), 2)
        finally:
            # Delete temporary file
            os.unlink(temp_path)
    
    def test_ignore_file(self):
        # Create temporary .bac_detectignore file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
            temp.write("""
# Test ignore file
pattern:eval_usage
test_ignored_file.py
*.min.js
""")
            temp_path = temp.name
        
        try:
            # Load ignore rules
            detector = BackdoorDetector()
            detector.load_ignore_file(temp_path)
            
            # Check pattern ignoring
            self.assertTrue(detector.should_ignore_pattern('eval_usage'))
            self.assertFalse(detector.should_ignore_pattern('exec_usage'))
            
            # Check file ignoring
            self.assertTrue(detector.should_ignore_file('test_ignored_file.py'))
            self.assertTrue(detector.should_ignore_file('jquery.min.js'))
            self.assertFalse(detector.should_ignore_file('normal_file.py'))
        finally:
            # Delete temporary file
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
