# swift-one-time-password

[![CI](https://github.com/swift-foundations/swift-time-based-one-time-password/workflows/CI/badge.svg)](https://github.com/swift-foundations/swift-time-based-one-time-password/actions/workflows/ci.yml)
![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

Swift implementation of One-Time Password algorithms (TOTP and HOTP) based on [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html) and [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226.html).

## Overview

This package provides APIs for generating and validating One-Time Passwords for two-factor authentication (2FA) in Swift applications:

- **TOTP** (Time-Based One-Time Password) - RFC 6238 implementation for time-based codes (30-second windows)
- **HOTP** (HMAC-Based One-Time Password) - RFC 4226 implementation for counter-based codes

### Package Structure

The package is organized into three targets:
- `OneTimePasswordShared` - Core cryptographic functionality using swift-crypto
- `TOTP` - Time-based OTP implementation with convenience extensions
- `HOTP` - Counter-based OTP implementation

## Installation

### Swift Package Manager

Add this package to your Swift project:

```swift
dependencies: [
    .package(url: "https://github.com/swift-foundations/swift-time-based-one-time-password.git", from: "0.0.1")
]
```

Then add the specific product you need to your target:
```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "TOTP", package: "swift-one-time-password"),
        // or
        .product(name: "HOTP", package: "swift-one-time-password")
    ]
)
```

## TOTP Usage

### Basic TOTP Generation

```swift
import TOTP

// Create TOTP from base32 secret (most common format)
let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")

// Generate current OTP
let code = totp.generate()
print("Current OTP: \(code)")

// Or use the convenience property
let currentCode = totp.currentOTP

// Validate an OTP
if totp.validate("123456") {
    print("Valid OTP!")
}

// Check time remaining for current code
let remaining = totp.timeRemaining()
print("Code expires in: \(Int(remaining)) seconds")
```

### Generate Secure Secrets

```swift
// Generate a random base32 secret
let secret = TOTP.generateSecret() // Default 20 bytes for SHA1

// Create TOTP with newly generated secret
let totp = try TOTP.generateNew(algorithm: .sha256, digits: 6)
let code = totp.generate()

// Get the base32 secret for sharing
let base32Secret = totp.base32Secret
print("Secret to share: \(base32Secret)")
```

### Different Hash Algorithms

```swift
// SHA1 (default, most compatible with authenticator apps)
let sha1TOTP = try TOTP.sha1(base32Secret: secret)

// SHA256 (more secure)
let sha256TOTP = try TOTP.sha256(base32Secret: secret, digits: 8)

// SHA512 (maximum security)
let sha512TOTP = try TOTP.sha512(base32Secret: secret)
```

### Provisioning URI for QR Codes

```swift
let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
let uri = totp.provisioningURI(
    label: "user@example.com",
    issuer: "My App"
)
// otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20App&algorithm=SHA1&digits=6&period=30

// Generate QR code from URI (using your preferred QR library)
// Users can scan this with Google Authenticator, Authy, etc.
```

### Time Window Validation

```swift
// Validate with time window (allows codes from adjacent time steps)
// Useful for handling clock skew between client and server
if totp.validate(userInput, window: 1) {
    // Valid within ±1 time step (usually ±30 seconds)
    print("Authentication successful!")
}

// Stricter validation (exact time step only)
if totp.validate(userInput, window: 0) {
    // Valid only for current 30-second window
}
```

### Migration Support

```swift
// Export for migration (e.g., to backup or transfer to another device)
let params = totp.exportMigration(
    issuer: "My Service",
    accountName: "user@example.com"
)

// Import from migration parameters
let imported = try TOTP.from(migration: params)
let code = imported.generate()

// This is useful for importing/exporting from authenticator apps
```

## HOTP Usage

### Basic HOTP Generation

```swift
import HOTP

// Create HOTP with secret
let secret = "12345678901234567890".data(using: .ascii)!
let hotp = try HOTP(secret: secret, digits: 6)

// Generate OTP for counter value
let code = hotp.generate(counter: 1)
print("OTP for counter 1: \(code)")

// Increment counter for next code
let nextCode = hotp.generate(counter: 2)

// Validate a code for a specific counter
if hotp.validate("123456", counter: 3) {
    print("Valid HOTP!")
}
```

### Different Algorithms

```swift
// SHA256 (more secure than SHA1)
let hotp256 = try HOTP(secret: secret, digits: 6, algorithm: .sha256)
let code256 = hotp256.generate(counter: 1)

// SHA512 (maximum security)
let hotp512 = try HOTP(secret: secret, digits: 8, algorithm: .sha512)
let code512 = hotp512.generate(counter: 1)

// From base32 secret
let hotpBase32 = try HOTP(base32Secret: "JBSWY3DPEHPK3PXP", algorithm: .sha256)
```

## Features

- RFC 6238 & RFC 4226 Compliant - Full implementation of TOTP and HOTP standards
- Multiple Hash Algorithms - SHA1, SHA256, and SHA512 support
- Secure Key Generation - Cryptographically secure random key generation using swift-crypto
- Base32 Encoding - Automatic base32 encoding/decoding for secrets (RFC 4648)
- QR Code URIs - Generate otpauth:// URIs for authenticator apps
- Time Window Validation - Handle clock skew with configurable time windows
- Migration Support - Import/export parameters for authenticator app migration
- Swift Crypto Integration - Built on swift-crypto for HMAC operations
- Modular Design - Separate TOTP and HOTP targets
- Type-Safe - Throwing initializers with error handling
- Dependency Injection - Time-based testing support via swift-dependencies
- Test Coverage - RFC test vectors included

## Requirements

- Swift 6.0+
- macOS 13.0+ / iOS 16.0+
- Dependencies:
  - [swift-crypto](https://github.com/apple/swift-crypto) 3.0+
  - [swift-rfc-6238](https://github.com/swift-web-standards/swift-rfc-6238) 0.0.2+
  - [swift-dependencies](https://github.com/pointfreeco/swift-dependencies) 1.9.2+

## Testing

The package includes comprehensive test coverage using Swift Testing framework:

### Test Coverage
- RFC 6238 test vectors (TOTP)
- RFC 4226 test vectors (HOTP)
- Secret generation and validation
- Time window validation
- Migration parameters
- Factory methods
- Edge cases and error handling
- Base32 encoding/decoding
- Provisioning URI generation

### Running Tests
```bash
swift test
```

### Testing with Dependency Injection
```swift
import Testing
import Dependencies
@testable import TOTP

@Test func testTOTPWithFixedTime() async throws {
    await withDependencies {
        $0.date = .constant(Date(timeIntervalSince1970: 1234567890))
    } operation: {
        let totp = try TOTP.sha1(base32Secret: "JBSWY3DPEHPK3PXP")
        let code = totp.generate()
        #expect(code == "expected_code")
    }
}
```

## Architecture

### Design Principles
- **Separation of Concerns**: RFC implementation separate from convenience APIs
- **Protocol-Oriented**: Uses protocols for cryptographic operations
- **Dependency Injection**: Testable time dependencies
- **Type Safety**: Throwing initializers instead of runtime crashes
- **Modularity**: Separate targets for different use cases

### Project Structure
```
swift-one-time-password/
├── Sources/
│   ├── OneTimePasswordShared/    # Shared crypto functionality
│   │   └── CryptoHMACProvider.swift
│   ├── TOTP/                     # Time-based OTP
│   │   ├── TOTP.swift
│   │   ├── TOTP+Generation.swift
│   │   └── TOTP+Migration.swift
│   └── HOTP/                     # Counter-based OTP
│       └── HOTP.swift
└── Tests/
    ├── TOTP Tests/
    └── HOTP Tests/
```

## Related Packages

### Used By

- [swift-identities](https://github.com/coenttb/swift-identities): The Swift library for identity authentication and management.

### Third-Party Dependencies

- [pointfreeco/swift-dependencies](https://github.com/pointfreeco/swift-dependencies): A dependency management library for controlling dependencies in Swift.
- [apple/swift-crypto](https://github.com/apple/swift-crypto): Open-source implementation of a substantial portion of the API of Apple CryptoKit.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - See LICENSE file for details