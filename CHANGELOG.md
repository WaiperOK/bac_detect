# Changelog

All notable changes to the `bac_detect` project will be documented in this file.

## [1.4.0] - 2025-05-08

### Added
- Advanced ML detection with Isolation Forest algorithm
- Ability to save and load trained ML models
- Enhanced feature extraction for improved ML detection
- Additional code metrics for more accurate anomaly detection
- Caching mechanism for faster rescans
- Support for incremental scanning of changed files
- Improved command-line options for ML model management

### Changed
- Improved ML detection performance
- Better feature extraction for TypeScript files
- Enhanced output formatting for better readability
- Upgraded dependencies to latest versions

### Fixed
- Fixed handling of large files in ML analysis
- Fixed potential memory leaks in multiprocessing mode
- Improved error handling and logging

## [1.3.0] - 2025-05-01

### Added
- TypeScript/Node.js support with specialized detection
- REST API for integration with other security systems
- Enhanced AST-based analysis for better obfuscation detection
- Machine learning capabilities for anomaly detection
- Command line flag `--use-ml` for machine learning detection

### Changed
- Improved Russian to English translation for error messages
- Updated dependency versions
- Improved performance for multi-file scans

### Fixed
- Fixed issues with PHP analysis on Windows systems
- Fixed false positives in JavaScript analysis

## [1.2.0] - 2025-04-15

### Added
- JSON export capability for scan results
- File/pattern ignore functionality via `.bac_detectignore`
- Multithreaded processing for faster scans
- Obfuscated code detection
- Dependency checking for malicious packages

### Changed
- Improved pattern detection for PHP backdoors
- Better handling of large files
- Enhanced documentation

### Fixed
- Fixed scan progress reporting
- Fixed memory usage issues

## [1.1.0] - 2025-04-01

### Added
- PHP support with specialized backdoor patterns
- Command line arguments for more customization
- Colored console output

### Changed
- Improved JavaScript analysis
- Better error handling

### Fixed
- Fixed regex patterns that caused false positives
- Fixed path handling on Windows systems

## [1.0.0] - 2025-03-15

### Added
- Initial release
- Support for Python and JavaScript detection
- Regular expression based pattern matching
- Basic static code analysis 