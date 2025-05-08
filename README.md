# 🛡️ bac_detect

<div align="center">

[![PyPI version](https://img.shields.io/pypi/v/bac_detect?label=PyPI)](https://pypi.org/project/bac_detect/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Versions](https://img.shields.io/pypi/pyversions/bac_detect)](https://pypi.org/project/bac_detect/)
[![Build Status](https://github.com/WaiperOK/bac_detect/actions/workflows/ci.yml/badge.svg)](https://github.com/WaiperOK/bac_detect/actions)

**A powerful tool for detecting potential backdoors and vulnerabilities in Python, JavaScript, and PHP source code**

[🚀 Installation](#-installation) • 
[🔍 Features](#-features) • 
[📊 Usage Examples](#-usage-examples) • 
[⚙️ Configuration](#%EF%B8%8F-configuration) • 
[👥 Contributing](#-contributing)

</div>

---

## 📦 Installation

```bash
pip install bac_detect
```

## 🚀 Quick Start

```bash
# Scan a directory or single file
bac_detect path/to/your/code

# Enable extra Python checks via Pylint
bac_detect --use-pylint path/to/your/code

# Show only HIGH severity issues
bac_detect --min-severity high path/to/your/code
```

## 🔍 Features

- **Multi-language scanning**: Analysis of `.py`, `.js`, and `.php` files
- **Combined approach**: 
  - Abstract Syntax Tree (AST) analysis using Bandit for Python and Esprima for JavaScript
  - Advanced regex-based scanning
  - Detection of suspicious constructs and potential backdoors
- **Smart classification**: All found issues are categorized by severity levels (**HIGH**, **MEDIUM**, **LOW**)
- **Customizability**: All detection rules can be configured in the `patterns.json` file
- **Flexible reporting**: Export results to JSON and SARIF formats (coming soon)
- **CI/CD integration**: Returns non-zero exit status when issues are detected

## 📊 Usage Examples

### Basic Scanning

```bash
# Scan a directory recursively through all subdirectories
bac_detect /path/to/project

# Scan only specific file types
bac_detect --include "*.py,*.js" /path/to/project

# Exclude specific directories
bac_detect --exclude "tests/,vendor/" /path/to/project
```

### Advanced Options

```bash
# Output results to JSON
bac_detect --output-format json --output-file results.json /path/to/project

# Set minimum severity level to display
bac_detect --min-severity medium /path/to/project

# Scan using a custom patterns file
bac_detect --patterns custom_patterns.json /path/to/project
```

### Output Example

```
[HIGH] Potential backdoor found: eval with dynamic content
        File: backend/utils.py, Line: 42
        Code: eval(request.params.get('cmd'))
        
[MEDIUM] Unsafe SQL query handling
        File: backend/models.py, Line: 78
        Code: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
        
[LOW] Deprecated security function usage
        File: backend/auth.py, Line: 156
        Code: md5(password).hexdigest()
```

## ⚙️ Configuration

### Detection Pattern Setup

All regex rules are located in the file:

```
bac_detect/patterns.json
```

You can edit existing or add new patterns:

```json
{
  "python": {
    "high": [
      {
        "pattern": "eval\\s*\\(.*\\)",
        "description": "Dangerous use of eval()"
      },
      {
        "pattern": "os\\.system\\s*\\(.*\\$.*\\)",
        "description": "Shell command execution with external variables"
      }
    ],
    "medium": [
      ...
    ]
  },
  "javascript": {
    ...
  }
}
```

### Configuration File

You can also create a `.bac_detectrc` configuration file in your project root:

```ini
[DEFAULT]
exclude = tests/,docs/,vendor/
include = *.py,*.js,*.php
min-severity = medium
use-pylint = true
```

## 👥 Contributing

1. Fork this repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/my-new-feature
   ```
3. Make your changes and commit:
   ```bash
   git add .
   git commit -m "Add support for XYZ"
   ```
4. Push to your fork and open a Pull Request against the `main` branch

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## 📍 Repository

👉 [https://github.com/WaiperOK/bac_detect](https://github.com/WaiperOK/bac_detect)