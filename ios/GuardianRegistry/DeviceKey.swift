import DeviceCheck
import Foundation
import Security

enum DeviceKeyError: LocalizedError {
    case failed(String)
    var errorDescription: String? { if case let .failed(m) = self { return m }; return nil }
}

/// The device key: EC P-256 in the Secure Enclave. The private key can't leave the chip;
/// the app only ever asks it to sign "guardian-registry/v1:" + challenge.
enum DeviceKey {
    private static let tag = Data("in.guardianregistry.app.devicekey".utf8)

    static func existing() -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else { return nil }
        return (item as! SecKey)  // swiftlint:disable:this force_cast
    }

    static func create() throws -> SecKey {
        var error: Unmanaged<CFError>?
        #if targetEnvironment(simulator)
        let flags: SecAccessControlCreateFlags = []           // no Secure Enclave in the simulator
        #else
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        #endif
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           flags, &error) else {
            throw DeviceKeyError.failed("access control: \(String(describing: error?.takeRetainedValue()))")
        }
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        #if !targetEnvironment(simulator)
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        #endif
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw DeviceKeyError.failed("key: \(String(describing: error?.takeRetainedValue()))")
        }
        return key
    }

    static func spki(_ key: SecKey) throws -> Data {
        guard let pub = SecKeyCopyPublicKey(key),
              let raw = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
            throw DeviceKeyError.failed("can't read the public key")
        }
        return Wire.spki(fromX963: raw)
    }

    static func sign(_ key: SecKey, challenge: String) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                              Wire.signingInput(challenge) as CFData, &error) as Data? else {
            throw DeviceKeyError.failed("sign: \(String(describing: error?.takeRetainedValue()))")
        }
        return sig
    }

    static func delete() {
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag] as CFDictionary)
    }
}

/// App Attest: Apple vouches that a genuine copy of this app on a genuine device asked to
/// bind THIS device key to THIS challenge. Returns nil where App Attest isn't available
/// (simulator, old devices); the registry then records the key as not attested.
enum AppAttest {
    static func evidence(challenge: String, spki: Data) async -> String? {
        let service = DCAppAttestService.shared
        guard service.isSupported else { return nil }
        do {
            let keyId = try await service.generateKey()
            let object = try await service.attestKey(keyId, clientDataHash: Wire.clientDataHash(challenge: challenge,
                                                                                               spki: spki))
            return Wire.appleAttestation(keyId: keyId, object: object)
        } catch {
            return nil
        }
    }
}
