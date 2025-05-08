python
import tempfile
import os
import json
import pytest
from bac_detect.backdoor_detector import BackdoorDetector

SAMPLE_PY = """
# harmless
x = 1
"""

SAMPLE_PY_BAD = """
user_input = input("cmd: ")
eval(user_input)
"""

def test_load_patterns(tmp_path, monkeypatch):
    custom_patterns = {"python": {"eval_001": "\\beval\\s*\\("}}
    p = tmp_path / "patterns.json"
    p.write_text(json.dumps(custom_patterns), encoding="utf-8")
    monkeypatch.setenv("PYPROJECT_ROOT", str(tmp_path))  
    detector = BackdoorDetector()
    assert "python" in detector.patterns
    assert "eval_001" in detector.patterns["python"]

def test_clean_code(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text(SAMPLE_PY, encoding="utf-8")
    detector = BackdoorDetector()
    issues = detector.scan(str(tmp_path))
    
    assert all(i["severity"] == "low" for i in issues)

def test_backdoor_in_python(tmp_path):
    f = tmp_path / "bad.py"
    f.write_text(SAMPLE_PY_BAD, encoding="utf-8")
    detector = BackdoorDetector()
    issues = detector.scan(str(tmp_path))
    
    assert any(i["type"].startswith("regex-python") for i in issues)

def test_js_eval(tmp_path):
    js = tmp_path / "bad.js"
    js.write_text("eval('alert(1)')", encoding="utf-8")
    detector = BackdoorDetector()
    issues = detector.scan(str(tmp_path))
    assert any(i["type"] == "regex-javascript" for i in issues)

def test_php_shell(tmp_path):
    php = tmp_path / "bad.php"
    php.write_text("<?php system('ls'); ?>", encoding="utf-8")
    detector = BackdoorDetector()
    issues = detector.scan(str(tmp_path))
    assert any(i["type"] == "regex-php" for i in issues)