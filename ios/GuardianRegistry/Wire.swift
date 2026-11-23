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

    static func rupees(paise: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .currency
        f.currencyCode = "INR"
        f.locale = Locale(identifier: "en_IN")
        f.maximumFractionDigits = 0
        return f.string(from: NSNumber(value: Double(paise) / 100)) ?? "₹\(paise / 100)"
    }
}
