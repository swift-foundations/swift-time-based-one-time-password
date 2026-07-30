//
//  TOTP+Generation.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Crypto
import Foundation
import OneTimePasswordShared

/// Convenience factory methods for creating TOTP instances
extension TOTP {
  /// Creates a TOTP instance with SHA1 (default for most authenticator apps)
  /// - Parameters:
  ///   - secret: Base32 encoded secret
  ///   - digits: Number of digits (default: 6)
  /// - Returns: TOTP instance
  /// - Throws: RFC_6238.Error if validation fails
  public static func sha1(base32Secret: String, digits: Int = 6) throws(RFC_6238.Error) -> TOTP {
    try TOTP(base32Secret: base32Secret, digits: digits, algorithm: .sha1)
  }

  /// Creates a TOTP instance with SHA256
  /// - Parameters:
  ///   - secret: Base32 encoded secret
  ///   - digits: Number of digits (default: 6)
  /// - Returns: TOTP instance
  /// - Throws: RFC_6238.Error if validation fails
  public static func sha256(base32Secret: String, digits: Int = 6) throws(RFC_6238.Error) -> TOTP {
    try TOTP(base32Secret: base32Secret, digits: digits, algorithm: .sha256)
  }

  /// Creates a TOTP instance with SHA512
  /// - Parameters:
  ///   - secret: Base32 encoded secret
  ///   - digits: Number of digits (default: 6)
  /// - Returns: TOTP instance
  /// - Throws: RFC_6238.Error if validation fails
  public static func sha512(base32Secret: String, digits: Int = 6) throws(RFC_6238.Error) -> TOTP {
    try TOTP(base32Secret: base32Secret, digits: digits, algorithm: .sha512)
  }

  /// Generates a random secret key suitable for TOTP
  /// - Parameter length: The length of the secret in bytes (default: 20 for SHA1 compatibility)
  /// - Returns: Base32 encoded secret string
  public static func generateSecret(length: Int = 20) -> String {
    let key = SymmetricKey(size: .init(bitCount: length * 8))
    let bytes = key.withUnsafeBytes { Array($0) }
    return RFC_6238.Base32.encode(bytes)
  }

  /// Creates a TOTP instance with a newly generated secure secret
  /// - Parameters:
  ///   - algorithm: The HMAC algorithm to use (affects recommended key length)
  ///   - digits: Number of digits in the OTP (default: 6)
  ///   - timeStep: Time step in seconds (default: 30)
  /// - Returns: A new TOTP instance with a securely generated secret
  public static func generateNew(
    algorithm: RFC_6238.Algorithm = .sha1,
    digits: Int = 6,
    timeStep: TimeInterval = 30
  ) throws(RFC_6238.Error) -> TOTP {
    // Recommended key lengths based on RFC 4226 and RFC 6238
    let keyLength: Int
    switch algorithm {
    case .sha1:
      keyLength = 20  // 160 bits

    case .sha256:
      keyLength = 32  // 256 bits

    case .sha512:
      keyLength = 64  // 512 bits
    }

    let key = SymmetricKey(size: .init(bitCount: keyLength * 8))
    let keyData = key.withUnsafeBytes { Array($0) }

    return try TOTP(
      secret: keyData,
      timeStep: timeStep,
      digits: digits,
      algorithm: algorithm
    )
  }

  /// Creates a TOTP instance from a secure symmetric key
  /// - Parameters:
  ///   - key: The symmetric key
  ///   - algorithm: The HMAC algorithm
  ///   - digits: Number of digits (default: 6)
  ///   - timeStep: Time step in seconds (default: 30)
  /// - Returns: A TOTP instance
  public init(
    symmetricKey: SymmetricKey,
    algorithm: RFC_6238.Algorithm = .sha1,
    digits: Int = 6,
    timeStep: TimeInterval = 30
  ) throws(RFC_6238.Error) {
    let keyData = symmetricKey.withUnsafeBytes { Array($0) }
    try self.init(
      secret: keyData,
      timeStep: timeStep,
      digits: digits,
      algorithm: algorithm
    )
  }
}
