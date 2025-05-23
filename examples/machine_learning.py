#!/usr/bin/env python3
"""
Example implementation of machine learning for anomaly detection in code
Uses simple statistical models to detect unusual patterns.
"""
import os
import re
import sys
import numpy as np
from collections import Counter
from pathlib import Path
from typing import List, Dict, Set, Tuple, Any

# Add bac_detect to path for direct imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.bac_detect.backdoor_detector import BackdoorDetector

class CodeFeatureExtractor:
    """Extract features from code files for machine learning"""
    
    def __init__(self):
        """Initialize feature extractor"""
        self.suspicious_imports = {
            'python': {'os', 'subprocess', 'base64', 'socket', 'urllib', 'requests', 
                      'pickle', 'marshal', 'ctypes', 'tempfile', 'shutil'},
            'javascript': {'exec', 'child_process', 'fs', 'net', 'http', 'https', 
                          'crypto', 'vm', 'process'},
            'php': {'system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open',
                   'pcntl_exec', 'eval', 'assert', 'file_get_contents'}
        }
        
        # Regex patterns for various suspicious constructs
        self.patterns = {
            'eval_exec': r'(eval|exec)\s*\(',
            'encoded_strings': r'(fromCharCode|String\.fromCharCode|atob|btoa|encodeURI|decodeURI|'
                              r'base64_encode|base64_decode|\\x[0-9a-f]{2})',
            'obfuscation': r'(chr\(\d+\)|\\u[0-9a-f]{4}|0x[0-9a-f]+|\\[0-7]{3})',
            'networking': r'(urllib\.request|urllib\.urlopen|requests\.get|'
                         r'new XMLHttpRequest|fetch\(|\.open\(|http\.get|file_get_contents)',
            'comments': r'(#|\/{2}|\/\*|\*\/)',
            'control_flow': r'(if|for|while|switch|case|try|catch|break|continue)',
            'function_defs': r'(function|def)\s+\w+\s*\('
        }
        
    def extract_features(self, content: str, lang: str) -> Dict[str, float]:
        """
        Extract numerical features from code content
        
        Args:
            content: Source code content
            lang: Programming language ('python', 'javascript', 'php')
            
        Returns:
            Dict of features and their values
        """
        lines = content.strip().split('\n')
        total_lines = len(lines)
        
        # Basic metrics
        avg_line_length = sum(len(line) for line in lines) / max(total_lines, 1)
        indentation_variance = np.var([len(line) - len(line.lstrip()) for line in lines]) if total_lines > 0 else 0
        
        # Character distribution
        char_distribution = Counter(content)
        total_chars = len(content)
        entropy = self._calculate_entropy(content)
        special_char_ratio = sum(char_distribution.get(c, 0) for c in '!@#$%^&*()_+{}[]|\\;:\'",.<>?/') / max(total_chars, 1)
        
        # Pattern-based features
        feature_dict = {
            'total_lines': total_lines,
            'avg_line_length': avg_line_length,
            'indentation_variance': indentation_variance,
            'character_entropy': entropy,
            'special_char_ratio': special_char_ratio,
            'suspicious_import_count': 0
        }
        
        # Add regex pattern matches
        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            feature_dict[f'{pattern_name}_count'] = len(matches)
            feature_dict[f'{pattern_name}_density'] = len(matches) / max(total_lines, 1)
        
        # Count suspicious imports
        if lang in self.suspicious_imports:
            suspicious_imports = self.suspicious_imports[lang]
            import_lines = self._extract_import_lines(content, lang)
            imported_modules = self._extract_imported_modules(import_lines, lang)
            suspicious_count = sum(1 for mod in imported_modules if mod in suspicious_imports)
            feature_dict['suspicious_import_count'] = suspicious_count
            feature_dict['suspicious_import_ratio'] = suspicious_count / max(len(imported_modules), 1)
        
        return feature_dict
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
            
        char_count = Counter(text)
        probs = [count / len(text) for count in char_count.values()]
        return -sum(p * np.log2(p) for p in probs)
    
    def _extract_import_lines(self, content: str, lang: str) -> List[str]:
        """Extract import statements from code based on language"""
        if lang == 'python':
            import_regex = r'^(?:import|from)\s+.+$'
        elif lang == 'javascript':
            import_regex = r'^(?:import|require)\s*\(.+$'
        elif lang == 'php':
            import_regex = r'^(?:include|require|include_once|require_once)\s*\(.+$'
        else:
            return []
            
        return [line.strip() for line in content.split('\n') 
                if re.match(import_regex, line.strip())]
    
    def _extract_imported_modules(self, import_lines: List[str], lang: str) -> Set[str]:
        """Extract module names from import statements"""
        modules = set()
        
        for line in import_lines:
            if lang == 'python':
                if line.startswith('import '):
                    mods = line[7:].split(',')
                    for mod in mods:
                        mod = mod.strip().split(' as ')[0]
                        modules.add(mod.split('.')[0])
                elif line.startswith('from '):
                    parts = line.split(' import ')
                    if len(parts) >= 2:
                        mod = parts[0][5:].strip()
                        modules.add(mod.split('.')[0])
            elif lang == 'javascript':
                if 'require(' in line:
                    match = re.search(r'require\s*\(\s*[\'"](.+?)[\'"]', line)
                    if match:
                        modules.add(match.group(1))
                elif 'import ' in line:
                    match = re.search(r'from\s+[\'"](.+?)[\'"]', line)
                    if match:
                        modules.add(match.group(1))
            elif lang == 'php':
                match = re.search(r'(?:include|require|include_once|require_once)\s*\(\s*[\'"](.+?)[\'"]', line)
                if match:
                    modules.add(match.group(1))
                    
        return modules

class AnomalyDetector:
    """Detect code anomalies using statistical analysis"""
    
    def __init__(self):
        """Initialize anomaly detector"""
        self.feature_extractor = CodeFeatureExtractor()
        self.training_data = {
            'python': [],
            'javascript': [],
            'php': []
        }
        self.thresholds = {}
        
    def train(self, file_paths: List[str]) -> None:
        """
        Train anomaly detector on normal code files
        
        Args:
            file_paths: Paths to normal code files for training
        """
        for file_path in file_paths:
            extension = Path(file_path).suffix.lower()
            if extension == '.py':
                lang = 'python'
            elif extension == '.js':
                lang = 'javascript'
            elif extension == '.php':
                lang = 'php'
            else:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                features = self.feature_extractor.extract_features(content, lang)
                self.training_data[lang].append(features)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
        
        # Calculate thresholds for each language and feature
        self._calculate_thresholds()
    
    def _calculate_thresholds(self) -> None:
        """Calculate statistical thresholds for anomaly detection"""
        self.thresholds = {}
        
        for lang, features_list in self.training_data.items():
            if not features_list:
                continue
                
            # Initialize thresholds dictionary for this language
            self.thresholds[lang] = {}
            
            # Get all feature names from the first sample
            feature_names = features_list[0].keys()
            
            # Calculate mean and standard deviation for each feature
            for feature in feature_names:
                values = [sample.get(feature, 0) for sample in features_list]
                mean = np.mean(values)
                std = np.std(values)
                # Set threshold at mean + 2*std for upper bound
                self.thresholds[lang][feature] = mean + 2 * std
    
    def detect_anomalies(self, file_path: str) -> List[Dict]:
        """
        Detect anomalies in a file based on learned thresholds
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        extension = Path(file_path).suffix.lower()
        
        if extension == '.py':
            lang = 'python'
        elif extension == '.js':
            lang = 'javascript'
        elif extension == '.php':
            lang = 'php'
        else:
            return [{'file': file_path, 'message': 'Unsupported file type', 'severity': 'low'}]
            
        if lang not in self.thresholds or not self.thresholds[lang]:
            return [{'file': file_path, 'message': f'No training data for {lang}', 'severity': 'low'}]
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract features
            features = self.feature_extractor.extract_features(content, lang)
            
            # Check against thresholds
            feature_thresholds = self.thresholds[lang]
            
            # High risk features - more concerned with these
            high_risk_features = {
                'eval_exec_count', 'eval_exec_density', 'encoded_strings_count',
                'suspicious_import_count', 'character_entropy'
            }
            
            for feature, value in features.items():
                if feature in feature_thresholds:
                    threshold = feature_thresholds[feature]
                    
                    # Check if value exceeds threshold
                    if value > threshold:
                        severity = 'high' if feature in high_risk_features else 'medium'
                        anomalies.append({
                            'file': file_path,
                            'type': 'ml-anomaly',
                            'message': f"Anomalous {feature}: {value:.2f} exceeds normal threshold {threshold:.2f}",
                            'severity': severity
                        })
        
        except Exception as e:
            anomalies.append({
                'file': file_path,
                'type': 'ml-error',
                'message': f"Error analyzing file: {str(e)}",
                'severity': 'low'
            })
        
        return anomalies

def main():
    """Example usage of anomaly detector"""
    # Create and train detector
    detector = AnomalyDetector()
    
    # Find some normal code files for training
    training_dirs = [
        'examples',
        'src',
        'tests',
    ]
    
    training_files = []
    for train_dir in training_dirs:
        if os.path.exists(train_dir):
            for root, _, files in os.walk(train_dir):
                for file in files:
                    if file.endswith(('.py', '.js', '.php')):
                        training_files.append(os.path.join(root, file))
    
    print(f"Training on {len(training_files)} normal files...")
    detector.train(training_files)
    
    # Scan suspicious files
    suspicious_files = [
        'examples/test_backdoor.py',
        'examples/test_backdoor.js',
        'examples/test_backdoor.php'
    ]
    
    for file_path in suspicious_files:
        if os.path.exists(file_path):
            print(f"\nAnalyzing {file_path}:")
            anomalies = detector.detect_anomalies(file_path)
            
            if anomalies:
                print(f"  {len(anomalies)} anomalies detected:")
                for anomaly in anomalies:
                    print(f"  - [{anomaly['severity'].upper()}] {anomaly['message']}")
            else:
                print("  No anomalies detected")
    
    # Compare with standard detection
    print("\nComparing with standard backdoor detection:")
    standard_detector = BackdoorDetector()
    
    for file_path in suspicious_files:
        if os.path.exists(file_path):
            print(f"\nStandard analysis of {file_path}:")
            
            if file_path.endswith('.py'):
                issues = standard_detector.analyze_python_file(file_path, use_pylint=False)
            elif file_path.endswith('.js'):
                issues = standard_detector.analyze_js_file(file_path)
            elif file_path.endswith('.php'):
                issues = standard_detector.analyze_php_file(file_path)
            else:
                issues = []
                
            high_issues = [issue for issue in issues if issue.get('severity') == 'high']
            print(f"  {len(issues)} issues detected ({len(high_issues)} high severity)")

if __name__ == '__main__':
    main() 