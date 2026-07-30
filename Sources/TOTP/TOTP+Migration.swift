//
//  TOTP+Migration.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Foundation
import OneTimePasswordShared

/// Migration support for Google Authenticator and other apps
extension TOTP {
  /// Migration parameters for various authenticator apps
  public struct MigrationParameters {
    public let secret: String
    public let issuer: String
    public let accountName: String
    public let algorithm: RFC_6238.Algorithm
    public let digits: Int
    public let period: Int

    public init(
      secret: String,
      issuer: String,
      accountName: String,
      algorithm: RFC_6238.Algorithm = .sha1,
      digits: Int = 6,
      period: Int = 30
    ) {
      self.secret = secret
      self.issuer = issuer
      self.accountName = accountName
      self.algorithm = algorithm
      self.digits = digits
      self.period = period
    }
  }

  /// Creates a TOTP from migration parameters
  /// - Parameter params: Migration parameters
  /// - Returns: TOTP instance
  /// - Throws: RFC_6238.Error if validation fails
  public static func from(migration params: MigrationParameters) throws(RFC_6238.Error) -> TOTP {
    try TOTP(
      base32Secret: params.secret,
      timeStep: TimeInterval(params.period),
      digits: params.digits,
      algorithm: params.algorithm
    )
  }

  /// Exports TOTP configuration as migration parameters
  /// - Parameters:
  ///   - issuer: The service issuer
  ///   - accountName: The account name
  /// - Returns: Migration parameters
  public func exportMigration(issuer: String, accountName: String) -> MigrationParameters {
    MigrationParameters(
      secret: RFC_6238.Base32.encode(secret),
      issuer: issuer,
      accountName: accountName,
      algorithm: algorithm,
      digits: digits,
      period: Int(timeStep)
    )
  }
}
