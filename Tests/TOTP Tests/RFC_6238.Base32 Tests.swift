import OneTimePasswordShared
import Testing

/// RFC 4648 Section 10 base32 test vectors: (ASCII input, base32 encoding).
private let rfc4648Vectors: [(ascii: String, base32: String)] = [
  ("", ""),
  ("f", "MY======"),
  ("fo", "MZXQ===="),
  ("foo", "MZXW6==="),
  ("foob", "MZXW6YQ="),
  ("fooba", "MZXW6YTB"),
  ("foobar", "MZXW6YTBOI======"),
]

/// The RFC 6238 Appendix B SHA-1 secret — ASCII "12345678901234567890" — in base32.
private let rfc6238SecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

/// The well-known public example secret used across TOTP documentation.
private let exampleSecretBase32 = "JBSWY3DPEHPK3PXP"

@Suite
struct `RFC_6238.Base32 Tests` {

  @Suite
  struct Unit {

    @Test
    func `RFC 4648 test vectors encode`() {
      for vector in rfc4648Vectors {
        let encoded = RFC_6238.Base32.encode(Array(vector.ascii.utf8))
        #expect(encoded == vector.base32, "encode(\(vector.ascii)) should be \(vector.base32)")
      }
    }

    @Test
    func `RFC 4648 test vectors decode`() {
      for vector in rfc4648Vectors {
        let decoded = RFC_6238.Base32.decode(vector.base32)
        #expect(decoded == Array(vector.ascii.utf8), "decode(\(vector.base32)) should be \(vector.ascii)")
      }
    }

    @Test
    func `Round-trip preserves canonical secrets`() throws {
      for secret in [rfc6238SecretBase32, exampleSecretBase32] {
        let decoded = try #require(RFC_6238.Base32.decode(secret))
        #expect(RFC_6238.Base32.encode(decoded) == secret)
      }
    }
  }

  @Suite
  struct `Edge Case` {

    @Test
    func `Decode tolerates padding, case, spaces, and dashes`() throws {
      let canonical = try #require(RFC_6238.Base32.decode(exampleSecretBase32))
      let variants = [
        exampleSecretBase32.lowercased(),
        exampleSecretBase32 + "====",
        "JBSW Y3DP EHPK 3PXP",
        "JBSW-Y3DP-EHPK-3PXP",
      ]
      for variant in variants {
        #expect(RFC_6238.Base32.decode(variant) == canonical, "\(variant) should decode like the canonical form")
      }
    }

    @Test
    func `Decode rejects characters outside the RFC 4648 alphabet`() {
      // O and I are valid base32; 0, 1, 8, and 9 are not.
      #expect(RFC_6238.Base32.decode("OOOOOOOO") != nil)
      #expect(RFC_6238.Base32.decode("IIIIIIII") != nil)
      #expect(RFC_6238.Base32.decode("00000000") == nil)
      #expect(RFC_6238.Base32.decode("11111111") == nil)
      #expect(RFC_6238.Base32.decode("88888888") == nil)
      #expect(RFC_6238.Base32.decode("99999999") == nil)
      #expect(RFC_6238.Base32.decode("MZXW6YQ!") == nil)
    }
  }

  @Suite
  struct Integration {

    @Test
    func `Canonical RFC 6238 secret decodes to the published ASCII key`() {
      let asciiKey = Array("12345678901234567890".utf8)
      #expect(RFC_6238.Base32.decode(rfc6238SecretBase32) == asciiKey)
      #expect(RFC_6238.Base32.encode(asciiKey) == rfc6238SecretBase32)
    }
  }
}
