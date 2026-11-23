import XCTest
@testable import GuardianRegistry

/// Runs in the simulator against a real registry (scripts/dev_server.py on the Mac at
/// 127.0.0.1:8010). Exercises the real Keychain key path, the SPKI encoding, signing and the
/// server's checks. The simulator has no Secure Enclave and no App Attest, so the key is a
/// software key there and attestation is absent; on a phone the same code uses the enclave.
final class SignInTests: XCTestCase {
    private let base = URL(string: ProcessInfo.processInfo.environment["GR_TEST_API"] ?? "http://127.0.0.1:8010")!

    private func newMobile() -> String { "+9196\(Int.random(in: 10_000_000...99_999_999))" }

    private func code(_ api: Api, _ mobile: String) async throws -> String {
        let out = try await api.call("POST", "/v1/auth/otp", ["mobile": mobile]) as? [String: Any]
        return try XCTUnwrap(out?["dev_code"] as? String, "server must run with GR_OTP_DEV_ECHO=1")
    }

    private func challenge(_ api: Api) async throws -> String {
        let out = try await api.call("POST", "/v1/auth/challenge") as? [String: Any]
        return try XCTUnwrap(out?["challenge"] as? String)
    }

    private func body(_ mobile: String, _ code: String, _ key: SecKey, _ challenge: String, signOver: String? = nil,
                      name: String? = nil) throws -> [String: Any] {
        var b: [String: Any] = [
            "mobile": mobile, "code": code, "device_id": "sim-device", "platform": "ios", "challenge": challenge,
            "device_key": try DeviceKey.spki(key).base64EncodedString(),
            "device_proof": try DeviceKey.sign(key, challenge: signOver ?? challenge).base64EncodedString(),
        ]
        if let name { b["display_name"] = name }
        return b
    }

    override func setUp() {
        DeviceKey.delete()
    }

    func testKeyEnrolsThenProvesTheDevice() async throws {
        let api = Api(base: base)
        let mobile = newMobile()
        let key = try DeviceKey.create()
        XCTAssertNotNil(DeviceKey.existing(), "the key must persist in the Keychain")

        let code1 = try await code(api, mobile)
        let ch1 = try await challenge(api)
        let first = try await api.call("POST", "/v1/auth/verify",
                                       try body(mobile, code1, key, ch1, name: "Simulator Test")) as? [String: Any]
        XCTAssertEqual(first?["new_user"] as? Bool, true)

        try await Task.sleep(nanoseconds: 31_000_000_000)  // the registry's resend cooldown
        let again = try XCTUnwrap(DeviceKey.existing())
        let code2 = try await code(api, mobile)
        let ch2 = try await challenge(api)
        let second = try await api.call("POST", "/v1/auth/verify",
                                        try body(mobile, code2, again, ch2)) as? [String: Any]
        XCTAssertEqual(second?["device_proven"] as? Bool, true, "a trusted key proves the device")

        let devices = try await Api(base: base, token: second?["token"] as? String).list("/v1/me/devices")
        XCTAssertEqual(devices.count, 1)
        XCTAssertEqual(devices.first?["status"] as? String, "trusted")
    }

    func testSignatureOverTheWrongChallengeIsRefused() async throws {
        let api = Api(base: base)
        let mobile = newMobile()
        let key = try DeviceKey.create()
        let ch = try await challenge(api)
        let otp = try await code(api, mobile)
        do {
            _ = try await api.call("POST", "/v1/auth/verify",
                                   try body(mobile, otp, key, ch, signOver: "not-" + ch, name: "Tamper Test"))
            XCTFail("the registry accepted a signature over a different challenge")
        } catch let e as ApiError {
            XCTAssertEqual(e.status, 401)
            XCTAssertTrue(e.message.contains("signature"), e.message)
        }
    }

    func testAppAttestIsAbsentInTheSimulator() async {
        let evidence = await AppAttest.evidence(challenge: "c", spki: Data())
        XCTAssertNil(evidence)
    }

    func testHindiStringsShip() throws {
        let path = try XCTUnwrap(Bundle.main.path(forResource: "hi", ofType: "lproj"), "hi.lproj missing from the app")
        let hi = try XCTUnwrap(Bundle(path: path))
        XCTAssertEqual(hi.localizedString(forKey: "Approve", value: nil, table: nil), "मंज़ूर करें")
        XCTAssertEqual(String(format: hi.localizedString(forKey: "Hello, %@", value: nil, table: nil), "Asha"), "नमस्ते, Asha")
    }

    func testTokenStoreRoundTrip() {
        TokenStore.token = "gut_test"
        XCTAssertEqual(TokenStore.token, "gut_test")
        TokenStore.token = nil
        XCTAssertNil(TokenStore.token)
    }
}
