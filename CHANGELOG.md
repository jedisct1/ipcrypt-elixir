# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2025-09-10

### Added
- Implementation of ipcrypt-pfx mode for prefix-preserving encryption
- New `IPCrypt.Pfx` module with encrypt/decrypt functions
- Support for ipcrypt-pfx in the main `IPCrypt` module
- Updated documentation and examples for the new mode
- Comprehensive test coverage for all ipcrypt-pfx test vectors

### Changed
- Updated IPv6 address formatting to use standard `:inet.ntoa` function
- Fixed test vectors to use canonical IPv6 format
- Improved code quality and removed unnecessary fallback code
- Updated version to 0.3.0 to reflect the new major feature

## [0.2.0] - 2025-08-30

### Added
- Initial implementation with ipcrypt-deterministic, ipcrypt-nd, and ipcrypt-ndx modes
- Full test coverage for all existing modes
- Documentation and examples

## [0.1.0] - 2025-08-30

### Added
- Initial release with basic functionality
