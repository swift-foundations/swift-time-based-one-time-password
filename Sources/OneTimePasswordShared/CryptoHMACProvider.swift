//
//  CryptoHMACProvider.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2025-08-20.
//

import Crypto
import Foundation
import RFC_6238

/// HMAC provider implementation using swift-crypto
public struct CryptoHMACProvider: RFC_6238.HMACProvider {

  public init() {}
}

extension CryptoHMACProvider {
  public func hmac(algorithm: RFC_6238.Algorithm, key: [UInt8], data: [UInt8]) -> [UInt8] {
    let symmetricKey = SymmetricKey(data: key)

    switch algorithm {
    case .sha1:
      return Array(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: symmetricKey))

    case .sha256:
      return Array(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))

    case .sha512:
      return Array(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
    }
  }
}
