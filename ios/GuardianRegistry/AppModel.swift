import Foundation
import Security

/// A translated string (the key is the English text, as in Localizable.strings).
func L(_ key: String) -> String { NSLocalizedString(key, comment: "") }
func L(_ key: String, _ args: CVarArg...) -> String { String(format: NSLocalizedString(key, comment: ""), arguments: args) }

struct Preset: Identifiable { let id: String; let label: String }

/// The same four screens as the web app: My protection, I protect, Alerts and Devices.
@MainActor
final class AppModel: ObservableObject {
    enum Screen { case mobile, code, home }
    enum Tab: Hashable { case me, guardian, alerts, devices }

    @Published var screen: Screen
    @Published var tab: Tab = .me
    @Published var mobile = UserDefaults.standard.string(forKey: "mobile") ?? ""
    @Published var code = ""
    @Published var devCode: String?
    @Published var name = ""
    @Published var server = Api.configuredBase.absoluteString
    @Published var message: String?
    @Published var busy = false
    @Published var loaded = false

    // data shown on the screens (server JSON)
    @Published var me: [String: Any] = [:]
    @Published var rules: [String: Any] = [:]
    @Published var security: [String: Any] = [:]
    @Published var guardians: [[String: Any]] = []
    @Published var changes: [[String: Any]] = []
    @Published var payments: [[String: Any]] = []
    @Published var presets: [Preset] = []
    @Published var inbox: [String: Any] = [:]
    @Published var wards: [[String: Any]] = []
    @Published var alerts: [[String: Any]] = []
    @Published var unread = 0
    @Published var devices: [[String: Any]] = []
    @Published var myKeyId: String?
    @Published var nominee: [String: Any]?
    @Published var notice: [String: Any] = [:]
    @Published var agreedToNotice = true

    init() {
        #if DEBUG
        let env = ProcessInfo.processInfo.environment
        if env["GR_TEST_RESET"] == "1" { TokenStore.token = nil; DeviceKey.delete() }
        if let t = env["GR_TEST_TOKEN"] { TokenStore.token = t }
        #endif
        screen = TokenStore.token == nil ? .mobile : .home
    }

    private var api: Api { Api(base: Api.configuredBase, token: TokenStore.token) }

    private var deviceId: String {
        if let id = UserDefaults.standard.string(forKey: "device_id") { return id }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: "device_id")
        return id
    }

    // ------------------------------------------------------------ derived
    var session: [String: Any] { security["this_session"] as? [String: Any] ?? [:] }

    /// This sign-in is restricted (new device, or after a SIM change): the registry refuses
    /// approvals and other high-trust actions, so the screens show a note instead.
    var restricted: Bool { session["restricted"] as? Bool ?? false }

    var restrictionReasons: String {
        (session["reasons"] as? [String] ?? []).map { Wire.readableTimes($0) }.joined(separator: "; ")
    }

    var inboxCount: Int {
        ["held_payments", "pending_changes", "invitations", "recoveries"].reduce(0) { $0 + ((inbox[$1] as? [Any])?.count ?? 0) }
    }

    var wardNames: [String: String] {
        Dictionary(wards.compactMap { w in (w["principal_id"] as? String).map { ($0, w["principal_name"] as? String ?? "") } },
                   uniquingKeysWith: { a, _ in a })
    }

    var paused: Bool { rules["kill_switch"] as? Bool ?? false }

    private func run(_ work: @escaping () async throws -> Void) {
        busy = true
        Task {
            defer { busy = false }
            do {
                try await work()
            } catch let e as ApiError where e.status == 401 && screen == .home {
                signedOut(L("Signed out: %@", e.message))
            } catch let e as URLError where e.code != .cancelled {
                message = L("Can't reach Guardian Registry. Check your connection.")
            } catch {
                message = error.localizedDescription
            }
        }
    }

    // ------------------------------------------------------------ sign-in
    func sendCode() {
        #if DEBUG
        UserDefaults.standard.set(server.trimmingCharacters(in: .whitespaces), forKey: "api_base")
        #endif
        run {
            let out = try await Api(base: Api.configuredBase).call("POST", "/v1/auth/otp", ["mobile": self.mobile, "language": Api.language])
            UserDefaults.standard.set(self.mobile, forKey: "mobile")
            self.devCode = (out as? [String: Any])?["dev_code"] as? String
            self.code = self.devCode ?? ""
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
                "language": Api.language,
                "device_key": try DeviceKey.spki(key).base64EncodedString(), "challenge": challenge,
                "device_proof": try DeviceKey.sign(key, challenge: challenge).base64EncodedString(),
            ]
            if !self.name.trimmingCharacters(in: .whitespaces).isEmpty { body["display_name"] = self.name }
            if let attestation { body["key_attestation"] = attestation }
            let out: [String: Any]?
            do {
                out = try await anon.call("POST", "/v1/auth/verify", body) as? [String: Any]
                TokenStore.token = out?["token"] as? String
            } catch let e as ApiError where e.status == 401 && e.message.contains("revoked") {
                DeviceKey.delete()   // the registry revoked it (lost phone / recovery): make a new one next time
                throw e
            }
            self.code = ""
            self.devCode = nil
            self.tab = .me
            self.screen = .home
            if out?["new_user"] as? Bool == true {
                self.message = L("Welcome! Your account is set up.")
            } else if out?["restricted"] as? Bool == true {
                let why = (out?["restriction_reasons"] as? [String] ?? []).map { Wire.readableTimes($0) }.joined(separator: "; ")
                self.message = L("Signed in with limits: %@", why)
            }
            await self.registerPush()
            try await self.load()
        }
    }

    /// `text` is already in the user's language.
    func signedOut(_ text: String) {
        TokenStore.token = nil
        screen = .mobile
        loaded = false
        message = text
    }

    func registerPush() async {
        guard TokenStore.token != nil, let push = UserDefaults.standard.string(forKey: "push_token") else { return }
        _ = try? await api.call("POST", "/v1/me/alerts/push", ["token": push, "platform": "ios"])
    }

    // ------------------------------------------------------------ loading
    /// Quiet refresh (pull to refresh, the 15-second timer, a push arriving).
    func refresh() async {
        guard screen == .home else { return }
        try? await load()
    }

    func reload() { run { try await self.load() } }

    private func load() async throws {
        let a = api
        async let i = a.object("/v1/guardian/inbox")
        async let u = a.list("/v1/me/notifications?unread_only=true&limit=100")
        async let s = a.object("/v1/me/security")
        let (ib, un, se) = try await (i, u, s)
        switch tab {
        case .me:
            async let m = a.object("/v1/me")
            async let r = a.object("/v1/me/rules")
            async let g = a.list("/v1/me/guardians")
            async let c = a.list("/v1/me/changes")
            async let p = a.list("/v1/me/payments?limit=10")
            async let pr = a.object("/v1/presets")
            async let nm = a.object("/v1/me/nominee")
            async let no = a.object("/v1/privacy/notice")
            async let co = a.object("/v1/me/consents")
            let (mm, rr, gg, cc, pp, ps, nn) = try await (m, r, g, c, p, pr, nm)
            let (nt, cs) = try await (no, co)
            me = mm; rules = rr; guardians = gg; changes = cc; payments = pp
            nominee = nn["nominee"] as? [String: Any]
            notice = nt
            agreedToNotice = cs["accepted_current"] as? Bool ?? false
            presets = ps.keys.sorted().map { k in Preset(id: k, label: (ps[k] as? [String: Any])?["label"] as? String ?? k) }
        case .guardian:
            wards = try await a.list("/v1/guardian/wards")
        case .alerts:
            alerts = try await a.list("/v1/me/notifications?limit=50")
        case .devices:
            devices = try await a.list("/v1/me/devices")
            myKeyId = DeviceKey.existing().flatMap { try? DeviceKey.spki($0) }.map { Wire.keyId(spki: $0) }
        }
        inbox = ib; unread = un.count; security = se
        loaded = true
    }

    // ------------------------------------------------------------ actions
    /// POST, then reload and say `done` (already translated).
    func act(_ path: String, _ body: [String: Any]? = nil, done: String) {
        run {
            try await self.api.call("POST", path, body)
            try await self.load()
            self.message = done
        }
    }

    func switchBackOn() {
        run {
            let out = try await self.api.call("POST", "/v1/me/kill-switch/off") as? [String: Any]
            try await self.load()
            self.message = out?["applied"] as? Bool == true ? L("Payments are back on.")
                : L("Your request is held for 24 hours. Your guardians can approve it sooner.")
        }
    }

    func applyPreset(_ key: String) {
        run {
            let name = key.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? key
            let out = try await self.api.call("POST", "/v1/me/rules/preset/\(name)") as? [String: Any]
            try await self.load()
            self.message = (out?["held"] as? [String: Any]) != nil ? L("Stricter parts apply now; looser parts wait 24 hours.") : L("Applied.")
        }
    }

    /// The person's own limits, in whole rupees ("" = no limit). Stricter ones apply now; looser ones wait.
    func saveLimits(_ rupees: [String: String]) {
        var body: [String: Any] = [:]
        for (key, text) in rupees {
            let t = text.replacingOccurrences(of: ",", with: "").replacingOccurrences(of: "₹", with: "")
                .trimmingCharacters(in: .whitespaces)
            if t.isEmpty {
                body[key] = NSNull()
            } else if let v = Int(t), v > 0 {
                body[key] = v * 100
            } else {
                message = L("Enter amounts in whole rupees, or leave empty for no limit.")
                return
            }
        }
        run {
            let out = try await self.api.call("PATCH", "/v1/me/rules", body) as? [String: Any]
            try await self.load()
            self.message = (out?["held"] as? [String: Any]) != nil ? L("Stricter parts apply now; looser parts wait 24 hours.") : L("Saved.")
        }
    }

    /// Chosen channels off every day from `start` to `end` (hours, India time).
    func saveQuietHours(channels: [String], start: Int, end: Int) {
        if channels.isEmpty || start == end {
            message = L("Choose at least one payment type, and different start and end times.")
            return
        }
        run {
            let out = try await self.api.call("PATCH", "/v1/me/rules",
                                              ["quiet_hours": ["channels": channels, "start": start, "end": end]]) as? [String: Any]
            try await self.load()
            self.message = (out?["held"] as? [String: Any]) != nil ? L("Stricter parts apply now; looser parts wait 24 hours.") : L("Saved.")
        }
    }

    func removeQuietHours() {
        run {
            let out = try await self.api.call("PATCH", "/v1/me/rules", ["quiet_hours": NSNull()]) as? [String: Any]
            try await self.load()
            self.message = (out?["held"] as? [String: Any]) != nil
                ? L("Your request is held for 24 hours. Your guardians can approve it sooner.") : L("Saved.")
        }
    }

    /// DPDP: a clear "I agree" to the current privacy notice.
    func agreeToNotice() {
        let version = notice["version"] as? String ?? ""
        run {
            try await self.api.call("POST", "/v1/me/consents", ["notice_version": version])
            try await self.load()
            self.message = L("Thank you. Your agreement is recorded.")
        }
    }

    func saveName(_ name: String) {
        run {
            try await self.api.call("PUT", "/v1/me/name", ["display_name": name.trimmingCharacters(in: .whitespaces)])
            try await self.load()
            self.message = L("Name saved.")
        }
    }

    func saveNominee(name: String, relation: String, mobile: String) {
        let parts = [name, relation, mobile].map { $0.trimmingCharacters(in: .whitespaces) }
        if parts.contains(where: \.isEmpty) {
            message = L("Fill in the nominee's name, relation and mobile number.")
            return
        }
        run {
            try await self.api.call("PUT", "/v1/me/nominee", ["name": parts[0], "relation": parts[1], "mobile": parts[2]])
            try await self.load()
            self.message = L("Nominee saved.")
        }
    }

    func removeNominee() {
        run {
            try await self.api.call("DELETE", "/v1/me/nominee")
            try await self.load()
            self.message = L("Nominee removed.")
        }
    }

    func removeDevice(_ keyId: String) {
        run {
            try await self.api.call("DELETE", "/v1/me/devices/\(keyId)")
            try await self.load()
            self.message = L("Removed and signed out.")
        }
    }

    func lostPhone() {
        run {
            try await self.api.call("POST", "/v1/me/security/lost-phone")
            self.signedOut(L("Done. Every device is signed out."))
        }
    }

    func signOut(everywhere: Bool) {
        let old = api
        signedOut(L("Signed out."))
        Task { _ = try? await old.call("POST", "/v1/auth/logout", ["everywhere": everywhere]) }
    }
}
