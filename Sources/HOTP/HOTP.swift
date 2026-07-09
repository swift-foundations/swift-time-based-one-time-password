//
//  HOTP.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Foundation
import OneTimePasswordShared

public typealias HOTP = RFC_6238.HOTP

extension HOTP {
  public typealias Algorithm = RFC_6238.Algorithm
  public typealias Error = RFC_6238.Error
}

extension HOTP {
  /// Creates an HOTP configuration from a base32 encoded secret
  /// - Parameters:
  ///   - base32Secret: The base32 encoded secret
  ///   - digits: The number of digits in the OTP (default: 6)
  ///   - algorithm: The HMAC algorithm (default: SHA1)
  /// - Throws: `Error.invalidBase32String` if base32 decoding fails, or other validation errors
  public init(base32Secret: String, digits: Int = 6, algorithm: RFC_6238.Algorithm = .sha1) throws {
    guard let secret = RFC_6238.Base32.decode(base32Secret) else {
      throw RFC_6238.Error.invalidBase32String
    }
    try self.init(secret: secret, digits: digits, algorithm: algorithm)
  }

  /// Validates an OTP for a given counter, using the batteries-included
  /// swift-crypto HMAC provider.
  ///
  /// The bare `generate(counter:)` convenience now lives upstream in
  /// `RFC_6238` (dependency-resolved); this package routes its own crypto-backed
  /// generation explicitly through ``CryptoHMACProvider`` to keep determinism
  /// without requiring a registered dependency scope.
  /// - Parameters:
  ///   - otp: The OTP to validate
  ///   - counter: The counter value to validate against
  /// - Returns: True if the OTP is valid for the counter
  public func validate(_ otp: String, counter: UInt64) -> Bool {
    let expected = generate(counter: counter, using: CryptoHMACProvider())
    return constantTimeCompare(otp, expected)
  }
}

// Helper function for constant-time comparison
private func constantTimeCompare(_ a: String, _ b: String) -> Bool {
  guard a.count == b.count else { return false }

  var result = 0
  for (charA, charB) in zip(a, b) {
    result |= Int(charA.asciiValue ?? 0) ^ Int(charB.asciiValue ?? 0)
  }

  return result == 0
}
