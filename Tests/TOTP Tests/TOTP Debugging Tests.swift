import Dependencies
import Foundation
import OneTimePasswordShared
import TOTP
import Testing

@Suite(
  .dependency(\.date, .init { Date() })
)
struct `TOTP Debugging Tests` {

  @Test
  func `Verify Date and Unix Timestamp`() throws {
    // Check what Date() returns
    let now = Date()
    let timestamp = now.timeIntervalSince1970

    print("=== Date and Timestamp Debug ===")
    print("Current Date: \(now)")
    print("Unix Timestamp: \(timestamp)")
    print("TimeZone: \(TimeZone.current)")
    print("TimeZone abbreviation: \(TimeZone.current.abbreviation() ?? "none")")
    print("Seconds from GMT: \(TimeZone.current.secondsFromGMT(for: now))")

    // Calculate what the timestamp should be for a known date
    let knownDate = Date(timeIntervalSince1970: 1_755_775_836)  // From your logs
    print("\nKnown date (1755775836): \(knownDate)")
    print("Should be: 2025-08-21 11:30:36 UTC")

    // Check if dependency date matches regular Date
    @Dependency(\.date) var dependencyDate
    let depDate = dependencyDate()
    let depTimestamp = depDate.timeIntervalSince1970

    print("\nDependency Date: \(depDate)")
    print("Dependency Timestamp: \(depTimestamp)")
    print("Difference from Date(): \(depTimestamp - timestamp) seconds")

    #expect(abs(depTimestamp - timestamp) < 1.0, "Dependency date should match regular Date()")
  }

  @Test
  func `Test TOTP with Known Secret and Timestamp`() throws {
    // Use the exact secret and timestamp from your logs
    let secret = "KIWV65ISTT4U34ME"
    let testTimestamp: TimeInterval = 1_755_775_836  // 2025-08-21 11:30:36 UTC
    let testDate = Date(timeIntervalSince1970: testTimestamp)

    print("=== TOTP Generation Test ===")
    print("Secret: \(secret)")
    print("Test Date: \(testDate)")
    print("Test Timestamp: \(testTimestamp)")

    // Create TOTP instance
    let totp = try TOTP(
      base32Secret: secret,
      timeStep: 30,
      digits: 6,
      algorithm: .sha1
    )

    // Generate code at the exact test time
    let code = totp.generate(at: testDate)
    print("Generated code at test time: \(code)")
    print("Your logs showed server generated: 338176")
    print("Authenticator apps showed: 415730")

    // Check what code would be generated at different time offsets
    print("\n=== Codes at different time offsets ===")
    for hoursOffset in [-2, -1, 0, 1, 2] {
      let offsetDate = testDate.addingTimeInterval(Double(hoursOffset * 3600))
      let offsetCode = totp.generate(at: offsetDate)
      let offsetTimestamp = offsetDate.timeIntervalSince1970
      print("\(hoursOffset) hours: \(offsetCode) (timestamp: \(offsetTimestamp))")
    }

    // Try to find where code 415730 might come from
    print("\n=== Searching for authenticator code 415730 ===")
    var found = false
    for dayOffset in -30...30 {
      for hourOffset in 0..<24 {
        let searchDate = testDate.addingTimeInterval(Double(dayOffset * 86400 + hourOffset * 3600))
        let searchCode = totp.generate(at: searchDate)
        if searchCode == "415730" {
          print("FOUND! Code 415730 at: \(searchDate)")
          print("That's \(dayOffset) days and \(hourOffset) hours from test time")
          print("Timestamp: \(searchDate.timeIntervalSince1970)")
          found = true
          break
        }
      }
      if found { break }
    }

    if !found {
      print("Code 415730 not found in ±30 days range")
    }
  }

  @Test
  func `Test Base32 Encoding/Decoding`() throws {
    let secret = "KIWV65ISTT4U34ME"

    print("=== Base32 Encoding Test ===")
    print("Original secret: \(secret)")

    // Decode the secret
    guard let decodedData = RFC_6238.Base32.decode(secret) else {
      Issue.record("Failed to decode Base32 secret")
      return
    }

    print("Decoded bytes: \(decodedData.map { String(format: "%02x", $0) }.joined())")
    print("Decoded length: \(decodedData.count) bytes")

    // Re-encode and check if it matches
    let reencoded = RFC_6238.Base32.encode(decodedData)
    print("Re-encoded: \(reencoded)")

    // Remove padding for comparison
    let reencodedNoPadding = reencoded.replacingOccurrences(of: "=", with: "")
    print("Re-encoded (no padding): \(reencodedNoPadding)")

    #expect(reencodedNoPadding == secret, "Re-encoded secret should match original")

    // Test with variations
    print("\n=== Testing secret variations ===")
    let variations = [
      secret,
      secret + "====",  // With padding
      secret.lowercased(),
      "JBSWY3DPEHPK3PXP",  // Known test vector
    ]

    for variant in variations {
      if let variantData = RFC_6238.Base32.decode(variant) {
        let variantHex = variantData.map { String(format: "%02x", $0) }.joined()
        print("\(variant): \(variantHex)")

        // Generate TOTP for this variant
        if let variantTOTP = try? TOTP(base32Secret: variant) {
          let variantCode = variantTOTP.generate(at: Date(timeIntervalSince1970: 1_755_775_836))
          print("  -> TOTP: \(variantCode)")
        }
      } else {
        print("\(variant): Failed to decode")
      }
    }
  }

  @Test
  func `Compare TOTP Implementations`() throws {
    let secret = "KIWV65ISTT4U34ME"
    let testDate = Date(timeIntervalSince1970: 1_755_775_836)

    print("=== TOTP Implementation Comparison ===")

    // Test with our TOTP
    let totp = try TOTP(base32Secret: secret)
    let ourCode = totp.generate(at: testDate)
    print("Our implementation: \(ourCode)")

    // Test time step calculation
    let timeStep = Int(testDate.timeIntervalSince1970 / 30)
    print("Time step: \(timeStep)")
    print("Expected: 58525861 (from logs)")

    #expect(timeStep == 58_525_861, "Time step should match logs")

    // Test with different configurations
    print("\n=== Testing different TOTP parameters ===")

    // Standard config (what we use)
    let standardTOTP = try TOTP(base32Secret: secret, digits: 6, algorithm: .sha1)
    print("SHA1, 6 digits, 30s: \(standardTOTP.generate(at: testDate))")

    // Try SHA256
    let sha256TOTP = try TOTP(base32Secret: secret, digits: 6, algorithm: .sha256)
    print("SHA256, 6 digits, 30s: \(sha256TOTP.generate(at: testDate))")

    // Try 8 digits
    let eightDigitTOTP = try TOTP(base32Secret: secret, digits: 8, algorithm: .sha1)
    print("SHA1, 8 digits, 30s: \(eightDigitTOTP.generate(at: testDate))")
  }

  @Test
  func `Test with Dependency Date`() throws {
    @Dependency(\.date) var date

    let secret = "KIWV65ISTT4U34ME"
    let totp = try TOTP(base32Secret: secret)

    print("=== Testing with Dependency Date ===")

    // Get current date from dependency
    let depDate = date()
    print("Dependency date: \(depDate)")
    print("Dependency timestamp: \(depDate.timeIntervalSince1970)")

    // Generate code using dependency date
    let codeWithDep = totp.generate(at: depDate)
    print("Code with dependency date: \(codeWithDep)")

    // Generate code using regular Date()
    let regularDate = Date()
    let codeWithRegular = totp.generate(at: regularDate)
    print("Code with regular Date(): \(codeWithRegular)")

    // They should be very close (within same 30-second window)
    if abs(depDate.timeIntervalSince(regularDate)) < 30 {
      #expect(codeWithDep == codeWithRegular, "Codes should match within same time window")
    }

    // Test what happens when we manipulate the dependency
    withDependencies {
      // Set date to a fixed time (from your logs)
      $0.date = .init { Date(timeIntervalSince1970: 1_755_775_836) }
    } operation: {
      @Dependency(\.date) var fixedDate
      let fixed = fixedDate()
      let fixedCode = totp.generate(at: fixed)
      print("\nWith fixed dependency date: \(fixed)")
      print("Fixed dependency code: \(fixedCode)")
      print("Should be: 338176 (from logs)")
    }
  }

  @Test
  func `Timezone Impact on TOTP`() throws {
    let secret = "KIWV65ISTT4U34ME"
    let totp = try TOTP(base32Secret: secret)

    print("=== Timezone Impact Test ===")

    // Create a date
    let now = Date()
    let timestamp = now.timeIntervalSince1970

    print("Current date: \(now)")
    print("Current timestamp: \(timestamp)")
    print("Current timezone: \(TimeZone.current)")
    print("GMT offset: \(TimeZone.current.secondsFromGMT(for: now)) seconds")

    // Generate TOTP with current time
    let currentCode = totp.generate(at: now)
    print("TOTP at current time: \(currentCode)")

    // Simulate what would happen if timestamp included timezone offset
    let offsetTimestamp = timestamp + Double(TimeZone.current.secondsFromGMT(for: now))
    let offsetDate = Date(timeIntervalSince1970: offsetTimestamp)
    let offsetCode = totp.generate(at: offsetDate)
    print("\nIf timestamp included TZ offset:")
    print("Offset timestamp: \(offsetTimestamp)")
    print("Offset date: \(offsetDate)")
    print("TOTP with offset: \(offsetCode)")

    // Calculate how many time steps difference
    let timeStepDifference = Int(TimeZone.current.secondsFromGMT(for: now) / 30)
    print("Time steps difference: \(timeStepDifference)")

    // This would explain the mismatch if the server is somehow using offset timestamps
    if TimeZone.current.secondsFromGMT(for: now) == 7200 {  // CEST is UTC+2
      print("\n⚠️ You're in CEST (UTC+2). If timestamps include this offset,")
      print("   TOTP codes would be 240 time steps (7200/30) ahead!")
    }
  }

  @Test
  func `RFC 6238 Test Vectors`() throws {
    print("=== RFC 6238 Appendix B Test Vectors ===")

    // Test secret from RFC 6238: ASCII "12345678901234567890"
    // Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    let testSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    // RFC 6238 test vectors (8 digits, SHA1)
    let testVectors: [(TimeInterval, String)] = [
      (59, "94287082"),
      (1_111_111_109, "07081804"),
      (1_111_111_111, "14050471"),
      (1_234_567_890, "89005924"),
      (2_000_000_000, "69279037"),
      (20_000_000_000, "65353130"),
    ]

    let totp = try TOTP(
      base32Secret: testSecret,
      timeStep: 30,
      digits: 8,
      algorithm: .sha1
    )

    print("\nTesting SHA1 with 8 digits:")
    var allPassed = true
    for (timestamp, expected) in testVectors {
      let date = Date(timeIntervalSince1970: timestamp)
      let generated = totp.generate(at: date)
      let passed = generated == expected
      allPassed = allPassed && passed
      print("  Time \(timestamp): \(generated) | Expected: \(expected) | \(passed ? "✓" : "✗")")
      #expect(generated == expected, "RFC test vector failed at timestamp \(timestamp)")
    }

    print("\nRFC 6238 compliance: \(allPassed ? "PASSED ✓" : "FAILED ✗")")

    // Now test with 6 digits (standard for authenticator apps)
    print("\n=== Testing with 6 digits (standard) ===")
    let totp6 = try TOTP(
      base32Secret: testSecret,
      timeStep: 30,
      digits: 6,
      algorithm: .sha1
    )

    // The 6-digit codes are the last 6 digits of the 8-digit codes
    let testVectors6: [(TimeInterval, String)] = [
      (59, "287082"),
      (1_111_111_109, "081804"),
      (1_111_111_111, "050471"),
      (1_234_567_890, "005924"),
      (2_000_000_000, "279037"),
      (20_000_000_000, "353130"),
    ]

    for (timestamp, expected) in testVectors6 {
      let date = Date(timeIntervalSince1970: timestamp)
      let generated = totp6.generate(at: date)
      let passed = generated == expected
      print("  Time \(timestamp): \(generated) | Expected: \(expected) | \(passed ? "✓" : "✗")")
      #expect(generated == expected, "6-digit test failed at timestamp \(timestamp)")
    }
  }

  @Test
  func `Test with User's Failed Secret`() throws {
    print("=== Testing with User's Failed Secret ===")

    // Secret from user logs: P7NRHIDDIJUWSJKI
    let secret = "P7NRHIDDIJUWSJKI"
    let totp = try TOTP(base32Secret: secret)

    // User's timestamp: 1755777940 (2025-08-21 12:05:40 UTC)
    let userTimestamp: TimeInterval = 1_755_777_940
    let userDate = Date(timeIntervalSince1970: userTimestamp)

    print("Secret: \(secret)")
    print("Secret length: \(secret.count) characters")
    print("Date: \(userDate)")
    print("Timestamp: \(userTimestamp)")

    // Generate code at exact user time
    let ourCode = totp.generate(at: userDate)
    print("\nOur code: \(ourCode)")
    print("Server generated: 707951 (from logs)")
    print("Apple/Microsoft showed: 691641")

    // Check if our code matches server
    #expect(ourCode == "707951", "Our code should match server logs")

    // Try to find where 691641 might come from
    print("\n=== Searching for authenticator code 691641 ===")

    // The issue might be that authenticator apps are misinterpreting the unpadded secret
    // Let's check what happens if we decode the secret differently

    // Check if it's a padding issue
    print("\n=== Testing padding variations ===")

    // 16 characters of Base32 = 10 bytes, needs 4 '=' padding to reach multiple of 8
    let paddedSecret = secret + "===="
    print("Testing with padded secret: \(paddedSecret)")
    if let paddedTOTP = try? TOTP(base32Secret: paddedSecret) {
      let paddedCode = paddedTOTP.generate(at: userDate)
      print("With padding (====): \(paddedCode)")
      if paddedCode == "691641" {
        print("⚠️ FOUND! Authenticators might be interpreting padded secret!")
      }
    }

    // Try with wrong padding amounts
    for padCount in 1...8 {
      let padding = String(repeating: "=", count: padCount)
      let testSecret = secret + padding
      if let testTOTP = try? TOTP(base32Secret: testSecret) {
        let testCode = testTOTP.generate(at: userDate)
        print("With \(padCount) padding chars: \(testCode)")
        if testCode == "691641" {
          print("⚠️ FOUND with \(padCount) padding chars!")
        }
      }
    }

    // Test if authenticators might be truncating the secret
    for length in stride(from: secret.count - 1, to: max(8, secret.count - 8), by: -1) {
      let truncated = String(secret.prefix(length))
      if let truncatedTOTP = try? TOTP(base32Secret: truncated) {
        let truncatedCode = truncatedTOTP.generate(at: userDate)
        if truncatedCode == "691641" {
          print("⚠️ FOUND with truncated secret at length \(length): \(truncated)")
        }
      }
    }
  }

  @Test
  func `Test Base32 Alphabet Issue`() throws {
    print("=== Testing Base32 Alphabet Issue ===")

    // The problematic secret from logs
    let secret = "PD5DXF62G3JOEOYP"

    print("Secret: \(secret)")
    print("Characters in secret:")
    for char in secret {
      print("  \(char) - ASCII: \(char.asciiValue ?? 0)")
    }

    // Check if all characters are valid Base32
    let validBase32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    for char in secret {
      if !validBase32.contains(char) {
        print("⚠️ Invalid Base32 character found: \(char)")
      }
    }

    // Try decoding manually
    if let data = RFC_6238.Base32.decode(secret) {
      print("\nDecoded to \(data.count) bytes:")
      print("Hex: \(data.map { String(format: "%02x", $0) }.joined())")

      // Generate TOTP with this
      let totp = try TOTP(
        secret: data,
        timeStep: 30,
        digits: 6,
        algorithm: .sha1
      )

      let testDate = Date(timeIntervalSince1970: 1_755_779_047)
      let code = totp.generate(at: testDate)
      print("Generated code: \(code)")
      print("Apple showed: 225918")

      // What if Apple is interpreting some characters differently?
      // Try replacing potentially problematic characters
      let variants = [
        secret,  // Original
        secret.replacingOccurrences(of: "O", with: "0"),  // O -> 0
        secret.replacingOccurrences(of: "I", with: "1"),  // I -> 1
        secret.replacingOccurrences(of: "O", with: "0").replacingOccurrences(of: "I", with: "1"),  // Both
      ]

      print("\n=== Testing character substitutions ===")
      for variant in variants {
        print("Variant: \(variant)")
        if let variantData = RFC_6238.Base32.decode(variant) {
          let variantTOTP = try TOTP(
            secret: variantData,
            timeStep: 30,
            digits: 6,
            algorithm: .sha1
          )
          let variantCode = variantTOTP.generate(at: testDate)
          print("  -> Code: \(variantCode)")
          if variantCode == "225918" {
            print("  ⚠️ FOUND! This variant matches Apple's code!")
          }
        } else {
          print("  -> Failed to decode")
        }
      }
    }
  }
}
