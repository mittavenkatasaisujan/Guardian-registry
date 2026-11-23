import Foundation
import Security

@MainActor
final class AppModel: ObservableObject {
    enum Screen { case mobile, code, home }

    @Published var screen: Screen = TokenStore.token == nil ? .mobile : .home
    @Published var mobile = UserDefaults.standard.string(forKey: "mobile") ?? ""
    @Published var code = ""
    @Published var name = ""
    @Published var message: String?
    @Published var busy = false

    @Published var displayName = ""
    @Published var paused = false
    @Published var invitations: [[String: Any]] = []
    @Published var held: [[String: Any]] = []
    @Published var wardNames: [String: String] = [:]
    @Published var alerts: [[String: Any]] = []

    private var api: Api { Api(base: Api.configuredBase, token: TokenStore.token) }

    private var deviceId: String {
        if let id = UserDefaults.standard.string(forKey: "device_id") { return id }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: "device_id")
        return id
    }

    private func run(_ work: @escaping () async throws -> Void) {
        busy = true
        message = nil
        Task {
            defer { busy = false }
            do {
                try await work()
            } catch let e as ApiError where e.status == 401 && screen == .home {
                signedOut(String(format: NSLocalizedString("Signed out: %@", comment: ""), e.message))
            } catch {
                message = error.localizedDescription
            }
        }
    }

    // ------------------------------------------------------------ sign-in
    func sendCode() {
        run {
            let out = try await Api(base: Api.configuredBase).call("POST", "/v1/auth/otp", ["mobile": self.mobile])
            UserDefaults.standard.set(self.mobile, forKey: "mobile")
            if let dev = (out as? [String: Any])?["dev_code"] as? String { self.code = dev }
            self.screen = .code
        }
    }

    /// OTP + device key proof. The Secure Enclave key (and its App Attest evidence) is made
    /// on first use, bound to this sign-in's challenge.
    func signIn() {
        run {
            let anon = Api(base: Api.configuredBase)
            let ch = try await anon.call("POST", "/v1/auth/challenge") as? [String: Any]
            guard let challenge = ch?["challenge"] as? String else { throw ApiError(status: 0, message: "no challenge") }
            var attestation: String?
            let key: SecKey
            if let k = DeviceKey.existing() {
                key = k
            } else {
                key = try DeviceKey.create()
                let spki = try DeviceKey.spki(key)
                attestation = await AppAttest.evidence(challenge: challenge, spki: spki)
            }
            var body: [String: Any] = [
                "mobile": self.mobile, "code": self.code, "device_id": self.deviceId, "platform": "ios",
                "device_key": try DeviceKey.spki(key).base64EncodedString(), "challenge": challenge,
                "device_proof": try DeviceKey.sign(key, challenge: challenge).base64EncodedString(),
            ]
            if !self.name.trimmingCharacters(in: .whitespaces).isEmpty { body["display_name"] = self.name }
            if let attestation { body["key_attestation"] = attestation }
            do {
                let out = try await anon.call("POST", "/v1/auth/verify", body) as? [String: Any]
                TokenStore.token = out?["token"] as? String
            } catch let e as ApiError where e.status == 401 && e.message.contains("revoked") {
                DeviceKey.delete()   // the registry revoked it (lost phone / recovery): make a new one next time
                throw e
            }
            self.code = ""
            self.screen = .home
            await self.registerPush()
            try await self.load()
        }
    }

    /// `text` is an English message key; it is shown in the user's language.
    func signedOut(_ text: String) {
        TokenStore.token = nil
        screen = .mobile
        message = NSLocalizedString(text, comment: "")
    }

    func registerPush() async {
        guard TokenStore.token != nil, let push = UserDefaults.standard.string(forKey: "push_token") else { return }
        _ = try? await api.call("POST", "/v1/me/alerts/push", ["token": push, "platform": "ios"])
    }

    // ------------------------------------------------------------ home
    func refresh() async {
        guard screen == .home else { return }
        try? await load()
    }

    func reload() { run { try await self.load() } }

    private func load() async throws {
        let a = api
        async let me = a.object("/v1/me")
        async let rules = a.object("/v1/me/rules")
        async let inbox = a.object("/v1/guardian/inbox")
        async let wards = a.list("/v1/guardian/wards")
        async let notes = a.list("/v1/me/notifications?limit=20")
        let (m, r, i, w, n) = try await (me, rules, inbox, wards, notes)
        displayName = m["display_name"] as? String ?? ""
        paused = r["kill_switch"] as? Bool ?? false
        invitations = i["invitations"] as? [[String: Any]] ?? []
        held = i["held_payments"] as? [[String: Any]] ?? []
        wardNames = Dictionary(w.compactMap { x in
            (x["principal_id"] as? String).map { ($0, x["principal_name"] as? String ?? "") } },
            uniquingKeysWith: { first, _ in first })
        alerts = n
    }

    func act(_ path: String, done: String) {
        run {
            try await self.api.call("POST", path)
            try await self.load()
            self.message = NSLocalizedString(done, comment: "")
        }
    }

    func lostPhone() {
        run {
            try await self.api.call("POST", "/v1/me/security/lost-phone")
            self.signedOut("Done. Every device is signed out.")
        }
    }

    func signOut() {
        run {
            _ = try? await self.api.call("POST", "/v1/auth/logout", ["everywhere": false])
            self.signedOut("Signed out.")
        }
    }
}
