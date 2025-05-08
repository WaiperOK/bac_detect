import argparse
import bandit
from bandit.core import manager, config
import esprima
import re
import os
import sys
import subprocess
import traceback
import json
import logging
from typing import List, Dict, Tuple, Generator, Optional
from contextlib import contextmanager
from pathlib import Path

MAX_DISPLAY_LENGTH = 65
MAX_MATCH_LENGTH = 80
TIMEOUT_SECONDS = 60
SUPPORTED_EXTENSIONS = ('.py', '.js', '.php')
SEVERITY_ORDER = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

PATTERNS = {}
PATTERNS_JSON_PATH = Path(__file__).parent / 'patterns.json'
PATTERNS_PY_PATH_MESSAGE = "internal patterns.py (package structure or local)"

@contextmanager
def suppress_stdout():
    original_stdout = sys.stdout
    try:
        sys.stdout = open(os.devnull, 'w')
        yield
    finally:
        if sys.stdout != original_stdout:
            sys.stdout.close()
        sys.stdout = original_stdout

def load_patterns() -> Dict:
    patterns = {}
    
    if PATTERNS_JSON_PATH.exists():
        try:
            with open(PATTERNS_JSON_PATH, 'r', encoding='utf-8') as f_patterns:
                patterns = json.load(f_patterns)
            if not isinstance(patterns, dict) or not any(isinstance(v, dict) for v in patterns.values()):
                logger.warning(f"patterns.json seems to be empty or malformed. Loaded: {str(patterns)[:100]}")
                patterns = {}
            else:
                logger.info(f"Patterns loaded successfully from {PATTERNS_JSON_PATH}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode patterns.json: {str(e)}. Check JSON validity.")
            patterns = {}
        except Exception as e:
            logger.error(f"Error loading patterns.json: {str(e)}.")
            patterns = {}

    if not patterns or not any(patterns.values()):
        patterns_py_loaded = False
        try:
            from .patterns import PATTERNS as PY_PATTERNS_PKG
            patterns = PY_PATTERNS_PKG
            patterns_py_loaded = True
            PATTERNS_PY_PATH_MESSAGE = "internal patterns.py (package structure)"
        except ImportError:
            try:
                from patterns import PATTERNS as PY_PATTERNS_SCRIPT
                patterns = PY_PATTERNS_SCRIPT
                patterns_py_loaded = True
                PATTERNS_PY_PATH_MESSAGE = "local patterns.py (script structure)"
            except ImportError:
                pass

        if patterns_py_loaded:
            if not isinstance(patterns, dict) or not any(isinstance(v, dict) for v in patterns.values()):
                logger.warning(f"Patterns from {PATTERNS_PY_PATH_MESSAGE} seem to be empty or malformed.")
                patterns = {}
            else:
                logger.info(f"Patterns loaded successfully from {PATTERNS_PY_PATH_MESSAGE}.")

    if not patterns or not any(patterns.values()):
        if PATTERNS_JSON_PATH.exists() or patterns_py_loaded:
            logger.critical("Failed to load valid patterns from available sources. Detection capability will be severely limited.")
        patterns = {"python": {}, "javascript": {}, "php": {}}
    
    return patterns

PATTERNS = load_patterns()

class Colors:
    CRITICAL = '\033[95m'
    HIGH = '\033[91m'
    MEDIUM = '\033[93m'
    LOW = '\033[94m'
    INFO = '\033[92m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    @staticmethod
    def format(text: str, style_key_or_direct_code: str) -> str:
        if style_key_or_direct_code.startswith('\033['):
            return f"{style_key_or_direct_code}{text}{Colors.RESET}"

        style_map = {
            'critical': Colors.CRITICAL, 'high': Colors.HIGH, 'medium': Colors.MEDIUM,
            'low': Colors.LOW, 'info': Colors.INFO, 'bold': Colors.BOLD, 'dim': Colors.DIM,
        }
        color_code = style_map.get(style_key_or_direct_code.lower(), "")
        return f"{color_code}{text}{Colors.RESET}" if color_code else text

    @staticmethod
    def is_supported() -> bool:
        return sys.platform != "win32" or (sys.platform == "win32" and os.environ.get('TERM') == 'xterm-256color')

class BackdoorDetector:
    
    def __init__(self):
        self.patterns = PATTERNS
        if not self.patterns or not any(self.patterns.values()):
            logger.warning("No patterns loaded. Detection capability will be limited.")

    def _analyze_with_regex(self, file_path: str, content: str, lang: str) -> List[Dict]:
        issues = []
        lang_patterns = self.patterns.get(lang, {})
        if not lang_patterns:
            return issues

        for pattern_name, pattern_regex in lang_patterns.items():
            try:
                for match in re.finditer(pattern_regex, content):
                    severity = self._determine_severity(lang, pattern_name)
                    match_text = match.group()
                    display_match = match_text[:MAX_MATCH_LENGTH] + ('...' if len(match_text) > MAX_MATCH_LENGTH else '')

                    issues.append({
                        'file': file_path,
                        'line': content[:match.start()].count('\n') + 1,
                        'type': f'regex-{lang}',
                        'message': f"Pattern '{Colors.format(pattern_name, 'bold')}' : {Colors.format(display_match, 'dim')}",
                        'severity': severity
                    })
            except re.error as re_e:
                logger.warning(f"Regex Error: Pattern '{pattern_name}' for {lang} on {file_path}: {re_e}")
            except Exception as e:
                logger.error(f"Error processing regex pattern {pattern_name} for {lang}: {e}")
        return issues

    def _determine_severity(self, lang: str, pattern_name: str) -> str:
        severity = 'medium'
        if lang == 'php':
            if any(k in pattern_name for k in ['backdoor', 'eval', 'exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open']):
                severity = 'high'
            elif any(k in pattern_name for k in ['file_access_006', 'file_access_007', 'file_access_008', 'file_access_009', 'sql_injection']):
                severity = 'high'
        elif lang == 'python':
            if any(k in pattern_name for k in ['eval', 'exec', 'pickle', 'marshal', 'os_system', 'subprocess_shell']):
                severity = 'high'
        elif lang == 'javascript':
            if any(k in pattern_name for k in ['eval', 'Function', 'constructor_call', 'innerHTML', 'document_write']):
                severity = 'high'
        return severity

    def _safe_read_file(self, file_path: str) -> Optional[str]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except IOError as e:
            logger.error(f"Could not read file {file_path}: {e}")
            return None

    def analyze_python_file(self, file_path: str, use_pylint: bool = False) -> List[Dict]:
        issues = []
        content = self._safe_read_file(file_path)
        if content is None:
            return [{'file': file_path, 'line': 0, 'type': 'file-error', 
                    'message': f"Could not read file: {file_path}", 'severity': 'low'}]

        try:
            with suppress_stdout():
                b_config = config.BanditConfig()
                b_mgr = manager.BanditManager(config=b_config, agg_type='file')
                b_mgr.discover_files([file_path], recursive=False)
                b_mgr.run_tests()

                for issue_raw in b_mgr.get_issue_list():
                    issues.append({
                        'file': file_path,
                        'line': issue_raw.lineno,
                        'type': 'bandit',
                        'message': issue_raw.text,
                        'severity': str(issue_raw.severity).lower()
                    })
        except Exception as e:
            logger.error(f"Bandit analysis failed for {file_path}: {e}")
            issues.append({
                'file': file_path,
                'line': 0,
                'type': 'bandit-error',
                'message': f"Bandit analysis failed: {str(e)[:100]}",
                'severity': 'low'
            })

        if use_pylint:
            issues.extend(self._run_pylint_analysis(file_path))

        issues.extend(self._analyze_with_regex(file_path, content, 'python'))
        return issues

    def _run_pylint_analysis(self, file_path: str) -> List[Dict]:
        issues = []
        try:
            cmd = [
                sys.executable, "-m", "pylint",
                file_path,
                "--disable=all",
                "--enable=exec-used,eval-used",
                "--output-format=json",
                "--msg-template={line}:{column}:{C}:{msg_id}:{msg}"
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                encoding='utf-8',
                errors='ignore'
            )

            if result.stdout:
                try:
                    pylint_data = json.loads(result.stdout) if result.stdout.startswith('[') else \
                        [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
                    
                    for msg in pylint_data:
                        msg_text, symbol = msg.get('message', '').lower(), msg.get('symbol', '').lower()
                        if 'exec' in msg_text or 'eval' in msg_text or 'exec-used' in symbol or 'eval-used' in symbol:
                            issues.append({
                                'file': file_path,
                                'line': msg.get('line', 0),
                                'type': 'pylint',
                                'message': f"Pylint ({msg.get('symbol', 'N/A')}): {msg.get('message', 'Error')}",
                                'severity': 'high'
                            })
                except json.JSONDecodeError:
                    if "Your code has been rated at" not in result.stdout:
                        logger.error(f"Pylint JSON decode error. Output: {result.stdout[:80]}...")

            if result.returncode != 0 and result.stderr and "Your code has been rated at" not in result.stderr:
                logger.error(f"Pylint failed (code {result.returncode}): {result.stderr[:80]}...")

        except subprocess.TimeoutExpired:
            logger.warning(f"Pylint timed out for {file_path}")
            issues.append({
                'file': file_path,
                'line': 0,
                'type': 'pylint-error',
                'message': "Pylint timed out (60s).",
                'severity': 'low'
            })
        except Exception as e:
            logger.error(f"Pylint run error for {file_path}: {e}")
            issues.append({
                'file': file_path,
                'line': 0,
                'type': 'pylint-error',
                'message': f"Pylint run error: {str(e)[:100]}",
                'severity': 'low'
            })
        return issues

    def analyze_js_file(self, file_path: str) -> List[Dict]:
        issues = []
        content = self._safe_read_file(file_path)
        if content is None:
            return [{'file': file_path, 'line': 0, 'type': 'file-error', 
                    'message': f"Could not read file: {file_path}", 'severity': 'low'}]

        try:
            ast = esprima.parseScript(content, options={'loc': True})
            if hasattr(ast, 'body'):
                for node in ast.body:
                    if (hasattr(node, 'type') and node.type == 'CallExpression' and
                            hasattr(node, 'callee') and hasattr(node.callee, 'name') and
                            node.callee.name in ['eval', 'Function']):
                        line = node.loc.start.line if node.loc and hasattr(node.loc, 'start') else 0
                        issues.append({
                            'file': file_path,
                            'line': line,
                            'type': 'esprima-ast',
                            'message': f"Suspicious call to {Colors.format(node.callee.name, 'bold')}",
                            'severity': 'high'
                        })
        except esprima.Error as e:
            logger.error(f"JS parsing failed for {file_path}: {e}")
            issues.append({
                'file': file_path,
                'line': getattr(e, 'lineNumber', 0),
                'type': 'esprima-error',
                'message': f"JS parsing failed: {getattr(e, 'description', str(e))}",
                'severity': 'low'
            })
        except Exception as e:
            logger.error(f"Esprima analysis error for {file_path}: {e}")
            issues.append({
                'file': file_path,
                'line': 0,
                'type': 'esprima-error',
                'message': f"Esprima analysis error: {str(e)[:100]}",
                'severity': 'low'
            })

        issues.extend(self._analyze_with_regex(file_path, content, 'javascript'))
        return issues

    def analyze_php_file(self, file_path: str) -> List[Dict]:
        issues = []
        content = self._safe_read_file(file_path)
        if content is None:
            return [{'file': file_path, 'line': 0, 'type': 'file-error', 
                    'message': f"Could not read file: {file_path}", 'severity': 'low'}]
        
        issues.extend(self._analyze_with_regex(file_path, content, 'php'))
        return issues

    def _collect_files_to_scan(self, path_to_scan: str) -> List[str]:
        files = []
        path = Path(path_to_scan)
        
        if path.is_file():
            if path.suffix in SUPPORTED_EXTENSIONS:
                files.append(str(path))
            else:
                logger.info(f"File {path_to_scan} is not a supported type. Skipping.")
        elif path.is_dir():
            for file_path in path.rglob('*'):
                if file_path.is_file() and file_path.suffix in SUPPORTED_EXTENSIONS:
                    files.append(str(file_path))
        else:
            logger.error(f"Path {path_to_scan} does not exist or is invalid.")
        
        return files

    def scan(self, path_to_scan: str, use_pylint: bool = False) -> List[Dict]:
        logger.info(f"Starting scan for: {path_to_scan}")
        all_issues = []
        files_to_process = self._collect_files_to_scan(path_to_scan)

        if not files_to_process:
            if Path(path_to_scan).is_dir():
                logger.info(f"No supported files found in {path_to_scan}")
            return all_issues

        try:
            from tqdm import tqdm
        except ImportError:
            logger.warning("tqdm library not found. Progress bar will be basic.")
            tqdm = lambda x, **kwargs: x

        for file_path in tqdm(files_to_process, desc="Scanning", unit="file"):
            display_name = Path(file_path).name
            if len(display_name) > MAX_DISPLAY_LENGTH:
                display_name = "..." + display_name[-(MAX_DISPLAY_LENGTH - 3):]
            logger.info(f"Scanning {display_name}")

            current_issues = []
            if file_path.endswith('.py'):
                current_issues = self.analyze_python_file(file_path, use_pylint)
            elif file_path.endswith('.js'):
                current_issues = self.analyze_js_file(file_path)
            elif file_path.endswith('.php'):
                current_issues = self.analyze_php_file(file_path)

            all_issues.extend(current_issues)

        seen = set()
        final_issues = []
        for issue in all_issues:
            raw_message = re.sub(r'\033\[[0-9;]*m', '', issue['message'])
            key = (issue['file'], issue['line'], issue['type'].split('-')[0], raw_message[:30].lower())
            if key not in seen:
                seen.add(key)
                final_issues.append(issue)

        return final_issues

def main():
    if sys.platform == "win32" and sys.stdout.isatty():
        os.system("")

    if not PATTERNS or not any(PATTERNS.values()):
        logger.critical("No patterns were loaded. Ensure 'patterns.json' or 'patterns.py' is correctly placed and readable.")
        sys.exit(3)

    logger.info("--- Backdoor Detector ---")

    parser = argparse.ArgumentParser(
        description="Scans for potential backdoors in Python, JS, and PHP code."
    )
    parser.add_argument('path', help="File or directory path to scan.")
    parser.add_argument('--use-pylint', action='store_true', help="Enable Pylint for Python files (can be slow).")
    parser.add_argument('--min-severity', type=str, default='low',
                       choices=['low', 'medium', 'high', 'critical'],
                       help="Minimum issue severity to display (default: low).")
    args = parser.parse_args()

    try:
        detector = BackdoorDetector()
        issues = detector.scan(args.path, use_pylint=args.use_pylint)

        min_sev_level = SEVERITY_ORDER.get(args.min_severity.lower(), 1)
        filtered_issues = [
            iss for iss in issues
            if SEVERITY_ORDER.get(str(iss['severity']).lower(), 0) >= min_sev_level
        ]
        
        filtered_issues.sort(
            key=lambda x: (
                SEVERITY_ORDER.get(str(x['severity']).lower(), 0),
                x['file'],
                x['line']
            ),
            reverse=True
        )

        if not filtered_issues:
            logger.info(f"No issues found (or above severity: {args.min_severity}).")
        else:
            logger.info(f"Scan Results ({len(filtered_issues)} issues):")
            for issue in filtered_issues:
                sev = str(issue['severity'])
                colored_sev = Colors.format(f"[{sev.upper()}]", sev)

                file_disp = issue['file']
                if len(file_disp) > MAX_DISPLAY_LENGTH:
                    file_disp = "..." + file_disp[-(MAX_DISPLAY_LENGTH - 3):]

                type_str_raw = f"({issue['type']})"
                colored_type = Colors.format(type_str_raw, 'dim')
                file_line_str = f"{Colors.format(file_disp, 'bold')}:{Colors.format(str(issue['line']), 'bold')}"

                print(f"{colored_sev} {file_line_str} {colored_type}: {issue['message']}")

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected critical error occurred: {str(e)}")
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()