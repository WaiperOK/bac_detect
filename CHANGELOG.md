# Changelog

All significant changes to the project are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.3.0] - 2025-05-15

### Added
- TypeScript/Node.js support with specific detection patterns
- Deep AST analysis for PHP code
- REST API for integration with other security tools
- Initial implementation of machine learning for anomaly detection
- TypeScript-specific code analysis patterns

### Improved
- Performance optimizations for faster scanning of large codebases
- Reduced false positives in JavaScript analysis
- Enhanced AST analysis for better detection accuracy
- Improved documentation with more usage examples

### Fixed
- Issue with Unicode handling in file paths
- Several regex pattern bugs causing false positives
- Dependency scanning error handling

## [1.2.0] - 2025-05-09

### Added
- JSON results export
- File and pattern ignoring mechanism via `.bac_detectignore`
- Multi-threaded scanning for faster processing
- Obfuscated code detection
- Dependency checking (package.json, requirements.txt, composer.json) for malicious packages

### Improved
- Progress bar now shows progress during multi-threaded scanning
- Added new command line options to control new features

### Fixed
- Improved error handling when reading files
- Fixed false positives for certain patterns

## [1.1.1] - 2025-05-08

### Added
- First public version on PyPI
- Support for Python, JavaScript and PHP
- Basic AST analysis for Python and JavaScript
- Regex-based analysis
- Issue categorization by severity level
- Terminal color highlighting 