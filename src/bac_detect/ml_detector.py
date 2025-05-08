#!/usr/bin/env python3
"""
Machine learning module for anomaly detection in code
"""
import re
import os
import logging
import pickle
import numpy as np
import joblib
from collections import Counter
from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Tuple, Union
from sklearn.ensemble import IsolationForest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CodeFeatureExtractor:
    """Extract features from code files for machine learning analysis"""
    
    def __init__(self):
        """Initialize feature extractor"""
        self.suspicious_imports = {
            'python': {'os', 'subprocess', 'base64', 'socket', 'urllib', 'requests', 
                      'pickle', 'marshal', 'ctypes', 'tempfile', 'shutil'},
            'javascript': {'exec', 'child_process', 'fs', 'net', 'http', 'https', 
                          'crypto', 'vm', 'process'},
            'php': {'system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open',
                   'pcntl_exec', 'eval', 'assert', 'file_get_contents'},
            'typescript': {'exec', 'child_process', 'fs', 'net', 'http', 'https',
                          'crypto', 'vm', 'process'}
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
            'function_defs': r'(function|def)\s+\w+\s*\(',
            'dynamic_code': r'(setTimeout|setInterval|new Function|constructor\s*\()',
            'binary_manipulation': r'(ArrayBuffer|Int8Array|Uint8Array|Buffer\.from)'
        }
        
    def extract_features(self, content: str, lang: str) -> Dict[str, float]:
        """
        Extract numerical features from code content
        
        Args:
            content: Source code content
            lang: Programming language ('python', 'javascript', 'php', 'typescript')
            
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
        
        # Complexity metrics
        max_line_length = max((len(line) for line in lines), default=0)
        blank_line_ratio = sum(1 for line in lines if not line.strip()) / max(total_lines, 1)
        ascii_ratio = sum(1 for c in content if ord(c) < 128) / max(total_chars, 1)
        
        # Pattern-based features
        feature_dict = {
            'total_lines': total_lines,
            'avg_line_length': avg_line_length,
            'max_line_length': max_line_length,
            'indentation_variance': indentation_variance,
            'character_entropy': entropy,
            'special_char_ratio': special_char_ratio,
            'blank_line_ratio': blank_line_ratio,
            'ascii_ratio': ascii_ratio,
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
        elif lang == 'javascript' or lang == 'typescript':
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
            elif lang == 'javascript' or lang == 'typescript':
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
            'php': [],
            'typescript': []
        }
        self.thresholds = {}
        self.models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        os.makedirs(self.models_dir, exist_ok=True)
        
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
            elif extension == '.ts':
                lang = 'typescript'
            else:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                features = self.feature_extractor.extract_features(content, lang)
                self.training_data[lang].append(features)
            except Exception as e:
                logger.debug(f"Error processing file {file_path}: {e}")
        
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
        elif extension == '.ts':
            lang = 'typescript'
        else:
            return []
            
        if lang not in self.thresholds or not self.thresholds[lang]:
            return []
            
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
                'suspicious_import_count', 'character_entropy', 'dynamic_code_count',
                'binary_manipulation_count'
            }
            
            for feature, value in features.items():
                if feature in feature_thresholds:
                    threshold = feature_thresholds[feature]
                    
                    # Check if value exceeds threshold
                    if value > threshold:
                        severity = 'high' if feature in high_risk_features else 'medium'
                        anomalies.append({
                            'file': file_path,
                            'line': 0,  # No specific line for ML anomalies
                            'type': 'ml-anomaly',
                            'message': f"Anomalous {feature}: {value:.2f} exceeds normal threshold {threshold:.2f}",
                            'severity': severity
                        })
        
        except Exception as e:
            logger.debug(f"Error analyzing file {file_path}: {str(e)}")
        
        return anomalies
        
    def save_model(self, model_name: str = "statistical_model") -> str:
        """
        Save the trained statistical model to a file
        
        Args:
            model_name: Name for the saved model
            
        Returns:
            Path to the saved model
        """
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        model_data = {
            'thresholds': self.thresholds,
            'training_data': self.training_data
        }
        
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)
            
        logger.info(f"Statistical model saved to {model_path}")
        return model_path
    
    def load_model(self, model_path: str) -> bool:
        """
        Load a previously trained statistical model
        
        Args:
            model_path: Path to the saved model
            
        Returns:
            True if loading was successful, False otherwise
        """
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                
            self.thresholds = model_data['thresholds']
            self.training_data = model_data['training_data']
            
            logger.info(f"Statistical model loaded from {model_path}")
            return True
        except Exception as e:
            logger.error(f"Error loading model from {model_path}: {str(e)}")
            return False

class IsolationForestDetector:
    """Detect code anomalies using Isolation Forest algorithm"""
    
    def __init__(self, n_estimators: int = 100, contamination: float = 0.1):
        """
        Initialize Isolation Forest detector
        
        Args:
            n_estimators: Number of trees in the forest
            contamination: Expected proportion of anomalies
        """
        self.feature_extractor = CodeFeatureExtractor()
        self.models = {}  # One model per language
        self.feature_names = {}  # Feature names per language
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        os.makedirs(self.models_dir, exist_ok=True)
    
    def _features_to_vector(self, features: Dict[str, float], lang: str) -> np.ndarray:
        """Convert feature dictionary to vector for ML model input"""
        if lang not in self.feature_names:
            return np.array([])
            
        return np.array([features.get(feat, 0.0) for feat in self.feature_names[lang]]).reshape(1, -1)
    
    def train(self, file_paths: List[str]) -> None:
        """
        Train Isolation Forest model on normal code files
        
        Args:
            file_paths: Paths to normal code files for training
        """
        # Group files by language
        training_data = {
            'python': [],
            'javascript': [],
            'php': [],
            'typescript': []
        }
        
        # Extract features from each file
        for file_path in file_paths:
            extension = Path(file_path).suffix.lower()
            
            if extension == '.py':
                lang = 'python'
            elif extension == '.js':
                lang = 'javascript'
            elif extension == '.php':
                lang = 'php'
            elif extension == '.ts':
                lang = 'typescript'
            else:
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                features = self.feature_extractor.extract_features(content, lang)
                training_data[lang].append(features)
            except Exception as e:
                logger.debug(f"Error processing file {file_path}: {e}")
        
        # Train a model for each language with enough samples
        for lang, features_list in training_data.items():
            if len(features_list) < 10:  # Need minimum samples for training
                logger.warning(f"Not enough samples ({len(features_list)}) for language {lang}")
                continue
                
            # Extract feature names from first sample
            self.feature_names[lang] = list(features_list[0].keys())
            
            # Convert dictionaries to numpy array
            X = np.array([[sample.get(feat, 0.0) for feat in self.feature_names[lang]] 
                         for sample in features_list])
            
            # Train Isolation Forest model
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42
            )
            model.fit(X)
            
            self.models[lang] = model
            logger.info(f"Trained Isolation Forest model for {lang} with {len(features_list)} samples")
    
    def detect_anomalies(self, file_path: str) -> List[Dict]:
        """
        Detect anomalies in a file using Isolation Forest
        
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
        elif extension == '.ts':
            lang = 'typescript'
        else:
            return []
            
        if lang not in self.models:
            logger.warning(f"No trained model for language {lang}")
            return []
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract features
            features = self.feature_extractor.extract_features(content, lang)
            
            # Convert to feature vector
            X = self._features_to_vector(features, lang)
            
            # Get anomaly score (-1 for anomalies, 1 for normal samples)
            # Lower (more negative) scores indicate stronger anomalies
            score = self.models[lang].decision_function(X)[0]
            prediction = self.models[lang].predict(X)[0]
            
            # If predicted as anomaly
            if prediction == -1:
                anomalies.append({
                    'file': file_path,
                    'line': 0,  # No specific line for ML anomalies
                    'type': 'ml-anomaly-iforest',
                    'message': f"Anomaly detected by Isolation Forest (score: {score:.3f})",
                    'severity': 'high' if score < -0.2 else 'medium',
                    'score': score
                })
        
        except Exception as e:
            logger.debug(f"Error analyzing file {file_path}: {str(e)}")
        
        return anomalies
    
    def save_model(self, model_name: str = "isolation_forest") -> str:
        """
        Save the trained Isolation Forest models to a file
        
        Args:
            model_name: Base name for the saved model
            
        Returns:
            Directory path where models are saved
        """
        if not self.models:
            logger.warning("No trained models to save")
            return ""
        
        model_dir = os.path.join(self.models_dir, model_name)
        os.makedirs(model_dir, exist_ok=True)
        
        # Save models for each language
        for lang, model in self.models.items():
            model_path = os.path.join(model_dir, f"{lang}_model.joblib")
            joblib.dump(model, model_path)
            
            # Save feature names
            if lang in self.feature_names:
                features_path = os.path.join(model_dir, f"{lang}_features.pkl")
                with open(features_path, 'wb') as f:
                    pickle.dump(self.feature_names[lang], f)
        
        logger.info(f"Isolation Forest models saved to {model_dir}")
        return model_dir
    
    def load_model(self, model_dir: str) -> bool:
        """
        Load previously trained Isolation Forest models
        
        Args:
            model_dir: Directory with saved models
            
        Returns:
            True if loading was successful, False otherwise
        """
        if not os.path.isdir(model_dir):
            logger.error(f"Model directory {model_dir} not found")
            return False
            
        try:
            languages = ['python', 'javascript', 'php', 'typescript']
            
            for lang in languages:
                model_path = os.path.join(model_dir, f"{lang}_model.joblib")
                features_path = os.path.join(model_dir, f"{lang}_features.pkl")
                
                if os.path.exists(model_path) and os.path.exists(features_path):
                    # Load model
                    self.models[lang] = joblib.load(model_path)
                    
                    # Load feature names
                    with open(features_path, 'rb') as f:
                        self.feature_names[lang] = pickle.load(f)
            
            if not self.models:
                logger.warning("No models were found in the directory")
                return False
                
            logger.info(f"Loaded Isolation Forest models from {model_dir}")
            return True
        except Exception as e:
            logger.error(f"Error loading models from {model_dir}: {str(e)}")
            return False 