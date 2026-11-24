import CryptoKit
import Foundation

/// Pure helpers shared by the app and the CI self-check (ios/WireCheck).
enum Wire {
    static let signingPrefix = "guardian-registry/v1:"

    /// DER SubjectPublicKeyInfo header for an EC P-256 public key, followed by the 65-byte
    /// uncompressed point (what SecKeyCopyExternalRepresentation returns).
    static let p256SpkiHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    static func spki(fromX963 point: Data) -> Data { p256SpkiHeader + point }

    static func signingInput(_ challenge: String) -> Data { Data((signingPrefix + challenge).utf8) }

    /// SHA256(prefix + challenge + device key DER): binds Apple's attestation to this key
    /// and this sign-in (the server recomputes it in attestation.apple_client_data_hash).
    static func clientDataHash(challenge: String, spki: Data) -> Data {
        Data(SHA256.hash(data: signingInput(challenge) + spki))
    }

    /// keyId is already base64 (DCAppAttestService returns it that way).
    static func appleAttestation(keyId: String, object: Data) -> String {
        let doc: [String: String] = ["format": "apple-appattest", "key_id": keyId,
                                     "object": object.base64EncodedString()]
        let data = try! JSONSerialization.data(withJSONObject: doc, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    /// The registry's device key id: SHA-256 of the public key (SPKI DER), in hex.
    static func keyId(spki: Data) -> String {
        SHA256.hash(data: spki).map { String(format: "%02x", $0) }.joined()
    }

    /// Server times are ISO 8601 with microseconds ("2026-11-24T15:22:11.619516+00:00").
    static func date(_ iso: String) -> Date? {
        var s = iso.trimmingCharacters(in: .whitespaces)
        if s.isEmpty { return nil }
        if let r = s.range(of: #"\.\d+"#, options: .regularExpression) {   // to milliseconds
            let digits = String(s[r].dropFirst().prefix(3))
            s.replaceSubrange(r, with: "." + digits.padding(toLength: 3, withPad: "0", startingAt: 0))
        }
        if s.range(of: #"(Z|[+-]\d{2}:\d{2})$"#, options: .regularExpression) == nil { s += "Z" }   // no offset: UTC
        let f = ISO8601DateFormatter()
        f.formatOptions = s.contains(".") ? [.withInternetDateTime, .withFractionalSeconds] : [.withInternetDateTime]
        return f.date(from: s)
    }

    /// "24 Nov 2026, 12:08 PM" in the phone's language and time zone, like the web app.
    static func time(_ iso: String, locale: Locale = .current, zone: TimeZone = .current) -> String {
        guard let d = date(iso) else { return iso }
        let f = DateFormatter()
        f.locale = locale
        f.timeZone = zone
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: d)
    }

    static func isFuture(_ iso: String, now: Date = Date()) -> Bool { (date(iso) ?? .distantPast) > now }

    /// Server reasons carry ISO times ("restricted until 2026-11-25T15:23:36+00:00"): show them readably.
    static func readableTimes(_ text: String, locale: Locale = .current, zone: TimeZone = .current) -> String {
        guard let re = try? NSRegularExpression(pattern: #"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"#)
        else { return text }
        var out = text
        for m in re.matches(in: text, range: NSRange(text.startIndex..., in: text)).reversed() {
            guard let r = Range(m.range, in: out) else { continue }
            out.replaceSubrange(r, with: time(String(out[r]), locale: locale, zone: zone))
        }
        return out
    }

    static func rupees(paise: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .currency
        f.currencyCode = "INR"
        f.locale = Locale(identifier: "en_IN")
        f.maximumFractionDigits = 0
        return f.string(from: NSNumber(value: Double(paise) / 100)) ?? "₹\(paise / 100)"
    }
}
