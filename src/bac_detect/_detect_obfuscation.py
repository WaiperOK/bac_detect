#!/usr/bin/env python3
"""
Advanced code obfuscation detection module for bac_detect
Uses AST (Abstract Syntax Tree) analysis for better detection accuracy
"""
import re
import ast
import logging
from typing import List, Dict, Optional, Any, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Maximum length of matching text to display
MAX_MATCH_LENGTH = 80

class Colors:
    """ANSI color codes for terminal output"""
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @classmethod
    def format(cls, text: str, style: str) -> str:
        """Format text with specified style"""
        colors = {
            'purple': cls.PURPLE,
            'blue': cls.BLUE,
            'green': cls.GREEN,
            'yellow': cls.YELLOW,
            'red': cls.RED,
            'bold': cls.BOLD,
            'dim': cls.DIM,
            'underline': cls.UNDERLINE
        }
        return f"{colors.get(style.lower(), '')}{text}{cls.END}"

class ObfuscationDetector:
    """Detects code obfuscation using AST analysis and regex patterns"""
    
    def __init__(self):
        """Initialize obfuscation detector"""
        # Common indicators of obfuscated code (regex-based)
        self.obfuscation_indicators = {
            'base64_decode': (
                r'base64_decode\s*\(', 
                'Base64 decode function detected, commonly used to hide code',
                'high'
            ),
            'hex_decode': (
                r'(fromCharCode|unhexlify|parseInt.*0x|"\\x|\'\\x|\\u00[0-9a-f]{2})',
                'Hex-encoded characters detected, may be used for obfuscation',
                'medium'
            ),
            'long_string': (
                r'["\'](\\.|[^"\'\\]){200,}["\']',
                'Suspiciously long string detected, possibly obfuscated code',
                'medium'
            ),
            'unusual_names': (
                r'\b[OI0l]{5,}\b',
                'Variables with hard-to-distinguish names detected (only I, O, 0, l)',
                'medium'
            ),
            'excessive_escaping': (
                r'\\\\\\\\[^"\'\\\\]{2,}',
                'Excessive string escaping detected, often used for obfuscation',
                'medium'
            ),
            'eval_with_encoded_content': (
                r'(eval|Function)\s*\(\s*["\'](\\.|[^"\'\\]){20,}["\']\s*\)',
                'Eval/Function call with encoded string detected, possibly obfuscated code',
                'high'
            ),
        }
        
        # Language-specific indicators
        self.language_indicators = {
            'python': {
                'exec_with_encoded_content': (
                    r'exec\s*\(\s*["\'](\\.|[^"\'\\]){20,}["\']\s*\)',
                    'Exec call with encoded string detected, possibly obfuscated code',
                    'high'
                ),
                'chr_sequence': (
                    r'((\(\s*chr\s*\(\s*\d+\s*\)\s*\+\s*)+|(\s*\+\s*chr\s*\(\s*\d+\s*\))+)',
                    'String creation from chr() sequence detected, commonly used for obfuscation',
                    'medium'
                ),
                'encoded_attribute_access': (
                    r'getattr\s*\(\s*\w+\s*,\s*["\'](\\.|[^"\'\\]){1,}["\']\s*\)',
                    'Potentially hidden attribute access detected',
                    'low'
                )
            },
            'javascript': {
                'js_obfuscator_patterns': (
                    r'var _0x[a-f0-9]+=',
                    'Pattern characteristic of JavaScript obfuscators detected',
                    'high'
                ),
                'js_string_concatenation': (
                    r'(["\']\s*\+\s*["\']){10,}',
                    'Excessive string concatenation detected, commonly used in obfuscated code',
                    'medium'
                ),
                'js_eval_with_function': (
                    r'eval\s*\(\s*function\s*\(.*\)\s*{.*return.*}\s*\(\s*\)\s*\)',
                    'Eval with function returning code detected, classic sign of obfuscation',
                    'high'
                ),
                'js_string_array_access': (
                    r'\[["\'][^"\']*["\']\]\s*\[["\'][^"\']*["\']\]',
                    'Array access via string indices detected, commonly used in obfuscated code',
                    'medium'
                )
            },
            'php': {
                'php_encoded_functions': (
                    r'(\$\{.{1,10}\}|\$[a-zA-Z0-9_]+)\s*\(\s*[\'"](\\.|[^\'"]){20,}[\'"]\s*\)',
                    'Dynamically defined function call with encoded string detected',
                    'high'
                ),
                'php_complex_variable_vars': (
                    r'\$\$\{.{1,30}\}|\$\$\$.{1,20}',
                    'Complex variable variables usage detected, often used for obfuscation',
                    'medium'
                ),
                'php_create_function': (
                    r'create_function\s*\(\s*[\'"].*[\'"]\s*,\s*[\'"].*[\'"]\s*\)',
                    'Use of create_function with encoded strings detected',
                    'high'
                )
            }
        }
    
    def detect_with_regex(self, content: str, lang: str) -> List[Dict]:
        """
        Detects obfuscation with regex patterns
        
        Args:
            content: Code content to analyze
            lang: Programming language ('python', 'javascript', 'php')
            
        Returns:
            List of detected issues
        """
        issues = []
        
        # Get language-specific indicators or empty dict if language not supported
        specific_indicators = self.language_indicators.get(lang, {})
        
        # Combine common and language-specific indicators
        all_indicators = {**self.obfuscation_indicators, **specific_indicators}
        
        # Check all indicators
        for name, (pattern, message, severity) in all_indicators.items():
            matches = list(re.finditer(pattern, content, re.IGNORECASE | re.DOTALL))
            if matches:
                for match in matches:
                    # Calculate line number
                    line_number = content[:match.start()].count('\n') + 1
                    match_text = match.group()
                    display_match = match_text[:MAX_MATCH_LENGTH] + ('...' if len(match_text) > MAX_MATCH_LENGTH else '')
                    
                    issues.append({
                        'line': line_number,
                        'type': 'obfuscation',
                        'message': f"{message}: {Colors.format(display_match, 'dim')}",
                        'severity': severity
                    })
        
        return issues
        
    def analyze_python_ast(self, content: str) -> List[Dict]:
        """
        Analyzes Python code using AST to detect obfuscation
        
        Args:
            content: Python code content
            
        Returns:
            List of detected issues
        """
        issues = []
        
        try:
            tree = ast.parse(content)
            visitor = PythonObfuscationVisitor()
            visitor.visit(tree)
            
            for issue in visitor.issues:
                issues.append(issue)
                
        except SyntaxError as e:
            logger.debug(f"Python AST parsing failed: {str(e)}")
            # We don't add an issue here, as the main scanner will catch syntax errors
        
        return issues

class PythonObfuscationVisitor(ast.NodeVisitor):
    """
    AST visitor to detect obfuscation in Python code
    """
    
    def __init__(self):
        self.issues = []
        self.variable_names = set()
        self.string_literals = []
        self.suspicious_nodes = []
        
    def visit_Name(self, node):
        """Visit variable/function name node"""
        self.variable_names.add(node.id)
        self.generic_visit(node)
        
    def visit_Constant(self, node):
        """Visit constant node (string literals)"""
        if isinstance(node.value, str) and len(node.value) > 50:
            self.string_literals.append((node, node.value))
        self.generic_visit(node)
        
    def visit_Call(self, node):
        """Visit function call node"""
        # Check for eval/exec with complex expression
        if isinstance(node.func, ast.Name) and node.func.id in ('eval', 'exec'):
            if len(node.args) > 0:
                arg = node.args[0]
                # Check if argument is complex (not a simple Name or Constant)
                if not isinstance(arg, (ast.Name, ast.Constant)):
                    self.issues.append({
                        'line': node.lineno,
                        'type': 'ast-obfuscation',
                        'message': f"Complex expression in {node.func.id}() detected, potential obfuscation technique",
                        'severity': 'high'
                    })
        
        # Check for getattr with computed attribute name
        if isinstance(node.func, ast.Name) and node.func.id == 'getattr':
            if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                self.issues.append({
                    'line': node.lineno,
                    'type': 'ast-obfuscation',
                    'message': f"Dynamic attribute access detected, often used for hidden code execution",
                    'severity': 'medium'
                })
        
        # Check for ord/chr sequences in complex expressions
        if isinstance(node.func, ast.Name) and node.func.id in ('chr', 'ord'):
            # If parent is a BinOp, it might be a string composition
            if hasattr(node, 'parent') and isinstance(node.parent, ast.BinOp):
                self.issues.append({
                    'line': node.lineno,
                    'type': 'ast-obfuscation',
                    'message': f"Character code manipulation detected, potential string obfuscation",
                    'severity': 'medium'
                })
        
        self.generic_visit(node)
        
    def visit_BinOp(self, node):
        """Visit binary operation node (for string composition detection)"""
        # Save parent reference for child nodes
        for child_node in ast.iter_child_nodes(node):
            setattr(child_node, 'parent', node)
        self.generic_visit(node)
        
    def visit_Import(self, node):
        """Visit import statement"""
        for name in node.names:
            if name.name in ('base64', 'marshal', 'pickle', 'importlib', 'ctypes'):
                self.issues.append({
                    'line': node.lineno,
                    'type': 'ast-obfuscation',
                    'message': f"Import of {name.name} detected, commonly used in obfuscated code or backdoors",
                    'severity': 'medium'
                })
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        """Visit from-import statement"""
        if node.module in ('base64', 'marshal', 'pickle', 'importlib', 'ctypes'):
            self.issues.append({
                'line': node.lineno,
                'type': 'ast-obfuscation',
                'message': f"Import from {node.module} detected, commonly used in obfuscated code or backdoors",
                'severity': 'medium'
            })
        self.generic_visit(node)
        
    def finalize(self):
        """Analyze collected data for additional patterns"""
        # Check for unusual variable naming patterns
        if self._check_unusual_naming_patterns():
            self.issues.append({
                'line': 0,  # No specific line
                'type': 'ast-obfuscation',
                'message': "Unusual variable naming pattern detected, potential obfuscation attempt",
                'severity': 'medium'
            })
            
    def _check_unusual_naming_patterns(self) -> bool:
        """Check for unusual variable naming patterns"""
        similar_names = set()
        for name in self.variable_names:
            if len(name) >= 5:
                # Check for names with only easily confused characters
                if all(c in 'Il1O0' for c in name):
                    similar_names.add(name)
                # Check for names with very similar patterns (e.g., xxxx1, xxxx2)
                for other in self.variable_names:
                    if name != other and len(other) >= 5:
                        if self._similarity_score(name, other) > 0.8:
                            similar_names.add(name)
                            similar_names.add(other)
        
        return len(similar_names) >= 3  # At least 3 suspicious names
    
    def _similarity_score(self, s1: str, s2: str) -> float:
        """Calculate similarity between two strings"""
        if len(s1) != len(s2):
            return 0.0
        
        same_chars = sum(1 for a, b in zip(s1, s2) if a == b)
        return same_chars / len(s1)

def detect_obfuscation(content: str, lang: str) -> List[Dict]:
    """
    Main function to detect code obfuscation
    
    Args:
        content: Code content to analyze
        lang: Programming language ('python', 'javascript', 'php')
        
    Returns:
        List of detected issues
    """
    detector = ObfuscationDetector()
    issues = detector.detect_with_regex(content, lang)
    
    # Add AST-based analysis for Python
    if lang == 'python':
        try:
            ast_issues = detector.analyze_python_ast(content)
            issues.extend(ast_issues)
        except Exception as e:
            logger.debug(f"AST analysis error: {str(e)}")
    
    return issues 