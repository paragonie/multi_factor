# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]
### Added
- Support for PHP 8.
- Native property type declarations.
- `GoogleAuth::getQRCode()` and `GoogleAuth::makeQRCodeMessage()` methods.
- HiddenString support for secret key.
- `GoogleAuth->defaultQRCodeSize` property (replaces the removed width and height properties).

### Changed
- PHP 7.4+ is now required.
- Renamed `FIDOU2F` class to `OneTime`.
- Updated [BaconQrCode](https://github.com/Bacon/BaconQrCode) dependency to v2.
  This version has a slightly different API for rendering QR code images.
- Test files are now excluded from Composer package.
- Unified internal code for HOTP value generation.

### Removed
- `GoogleAuth->defaultQRCodeWidth` and `GoogleAuth->defaultQRCodeHeight` properties.
- Unused internal `rawOutput` option.


## [0.2.2] - 2016-06-17
### Changed
- Appended HTTP query string in QR code.


## [0.2.1] - 2016-06-17
### Changed
- `TOTP` and `HOTP` classes now implement `OTPInterface`.


## [0.2.0] - 2016-06-16
### Added
- Support for HOTP and Google Authenticator.
- Range check to ensure that code length is between 1 and 10.

### Changed
- Replaced giant switch statement with `**` operator.
- Improved readme.


## [0.1.0] - 2016-06-13
- Initial pre-release


[Unreleased]: https://github.com/paragonie/multi_factor/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/paragonie/multi_factor/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/paragonie/multi_factor/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/paragonie/multi_factor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/paragonie/multi_factor/tree/v0.1.0
