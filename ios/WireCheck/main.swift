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
check(Wire.keyId(spki: Data([1, 2, 3])) == "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", "key id")
let utc = TimeZone(identifier: "UTC")!
let en = Locale(identifier: "en_US_POSIX")
check(Wire.date("2026-11-24T15:22:11.619516+00:00") != nil, "microsecond ISO time parses")
check(Wire.date("2026-11-24T15:22:11") != nil, "ISO time without offset parses")
check(Wire.date("not a time") == nil, "junk is not a time")
let readable = Wire.readableTimes("new device: restricted until 2026-11-25T15:23:36.989624+00:00", locale: en, zone: utc)
check(!readable.contains("T15:23") && readable.hasPrefix("new device: restricted until ") && readable.contains("2026"), "readable: \(readable)")
check(Wire.isFuture("2999-01-01T00:00:00Z") && !Wire.isFuture("2000-01-01T00:00:00Z") && !Wire.isFuture(""), "isFuture")
print("ok")
