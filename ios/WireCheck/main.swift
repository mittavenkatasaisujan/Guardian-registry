// CI self-check for Wire.swift: `swiftc ios/GuardianRegistry/Wire.swift ios/WireCheck/main.swift -o wc && ./wc`
// Prints the values the Python suite compares against (tests/test_native_contract.py).
import CryptoKit
import Foundation

func check(_ ok: Bool, _ what: String) {
    if !ok { print("FAIL: \(what)"); exit(1) }
}

let point = Data([0x04] + [UInt8](repeating: 0x11, count: 32) + [UInt8](repeating: 0x22, count: 32))
let spki = Wire.spki(fromX963: point)
check(spki.count == 91, "SPKI is 91 bytes")
check(String(decoding: Wire.signingInput("chl_x"), as: UTF8.self) == "guardian-registry/v1:chl_x", "signing input")
let json = Wire.appleAttestation(keyId: "a2V5", object: Data([1, 2, 3]))
check(json == #"{"format":"apple-appattest","key_id":"a2V5","object":"AQID"}"#, "attestation JSON: \(json)")
print("spki=\(spki.base64EncodedString())")
print("cdh=\(Wire.clientDataHash(challenge: "chl_x", spki: spki).base64EncodedString())")
print("ok")
