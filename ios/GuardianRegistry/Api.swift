import Foundation
import Security

struct ApiError: LocalizedError {
    let status: Int
    let message: String
    var errorDescription: String? { message }
}

/// JSON over HTTPS to the registry.
struct Api {
    let base: URL
    var token: String?

    /// "hi" when the phone's first language is Hindi, otherwise "en".
    static var language: String {
        (Locale.preferredLanguages.first ?? "en").hasPrefix("hi") ? "hi" : "en"
    }

    static func isLocal(_ url: URL) -> Bool {
        ["127.0.0.1", "localhost", "::1"].contains(url.host ?? "")
    }

    static var configuredBase: URL {
        let s = Bundle.main.object(forInfoDictionaryKey: "GRApiBase") as? String ?? ""
        return URL(string: s.isEmpty ? "https://registry.example.in" : s)!
    }

    @discardableResult
    func call(_ method: String, _ path: String, _ body: [String: Any]? = nil) async throws -> Any {
        var req = URLRequest(url: URL(string: path, relativeTo: base)!)
        req.httpMethod = method
        req.timeoutInterval = 15
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue(Api.language, forHTTPHeaderField: "Accept-Language")  // server errors in the phone's language
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if Api.isLocal(base) {
            // A development server on this machine: don't reuse keep-alive connections. The
            // simulator's network stack has been seen to stall on a reused local connection.
            req.setValue("close", forHTTPHeaderField: "Connection")
        }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        } else if method == "POST" {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = Data("{}".utf8)
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        let json = data.isEmpty ? [String: Any]() : (try? JSONSerialization.jsonObject(with: data)) ?? [:]
        if status >= 400 {
            let detail = (json as? [String: Any])?["detail"] as? String
            throw ApiError(status: status, message: detail ?? "HTTP \(status)")
        }
        return json
    }

    func object(_ path: String) async throws -> [String: Any] {
        try await call("GET", path) as? [String: Any] ?? [:]
    }

    func list(_ path: String) async throws -> [[String: Any]] {
        try await call("GET", path) as? [[String: Any]] ?? []
    }
}

/// The session token lives in the Keychain, this device only.
enum TokenStore {
    private static let service = "in.guardianregistry.app.session"

    static var token: String? {
        get {
            var item: CFTypeRef?
            let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service, kSecReturnData as String: true]
            guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let d = item as? Data else { return nil }
            return String(decoding: d, as: UTF8.self)
        }
        set {
            let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
            SecItemDelete(q as CFDictionary)
            guard let newValue else { return }
            var add = q
            add[kSecValueData as String] = Data(newValue.utf8)
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
    }
}
