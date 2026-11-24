import CryptoKit
import XCTest

/// Drives the real screens in the simulator against a real registry (scripts/dev_server.py on
/// the Mac at 127.0.0.1:8010), the same flows a person uses in the web app: presets, pausing and
/// the held "switch back on", inviting a guardian, a guardian approving that change, approving
/// and denying payments a bank sent, pausing someone else's payments, alerts, devices, a
/// restricted sign-in, sign-in through the screens, sign-out and lost phone. Every action is
/// checked against the registry's API. Screenshots go to $GR_SHOTS (CI keeps them).
final class AppFlowUITests: XCTestCase {
    private let base = ProcessInfo.processInfo.environment["GR_TEST_API"] ?? "http://127.0.0.1:8010"
    private let run = Int.random(in: 1000...9999)

    override func setUp() {
        continueAfterFailure = false
    }

    // ------------------------------------------------------------------ registry helpers
    @discardableResult
    private func call(_ method: String, _ path: String, _ body: [String: Any]? = nil, token: String? = nil,
                      headers: [String: String] = [:]) throws -> Any {
        var req = URLRequest(url: URL(string: base + path)!)
        req.httpMethod = method
        req.timeoutInterval = 20
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("close", forHTTPHeaderField: "Connection")
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        } else if method == "POST" {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = Data("{}".utf8)
        }
        let done = DispatchSemaphore(value: 0)
        var result: (Data?, URLResponse?, Error?) = (nil, nil, nil)
        URLSession.shared.dataTask(with: req) { d, r, e in result = (d, r, e); done.signal() }.resume()
        done.wait()
        if let e = result.2 { throw e }
        let status = (result.1 as? HTTPURLResponse)?.statusCode ?? 0
        let json: Any = result.0.flatMap { $0.isEmpty ? nil : try? JSONSerialization.jsonObject(with: $0) } ?? [String: Any]()
        if status >= 400 {
            throw NSError(domain: "registry", code: status, userInfo: [NSLocalizedDescriptionKey: "\(method) \(path) -> \(status) \(json)"])
        }
        return json
    }

    private func obj(_ path: String, token: String? = nil, headers: [String: String] = [:]) throws -> [String: Any] {
        try call("GET", path, token: token, headers: headers) as? [String: Any] ?? [:]
    }

    private func mobile() -> String { "+9196\(Int.random(in: 10_000_000...99_999_999))" }

    private func devCode(_ mobile: String) throws -> String {
        let out = try call("POST", "/v1/auth/otp", ["mobile": mobile]) as? [String: Any]
        return try XCTUnwrap(out?["dev_code"] as? String)
    }

    /// A person signed in without a device key (as a web browser on plain http would).
    private func person(_ mobile: String, _ name: String) throws -> String {
        let out = try call("POST", "/v1/auth/verify", ["mobile": mobile, "code": try devCode(mobile), "display_name": name]) as? [String: Any]
        return try XCTUnwrap(out?["token"] as? String)
    }

    /// A sign-in with a software P-256 key (a stand-in for another phone's Secure Enclave key).
    private func keySignIn(_ mobile: String, _ name: String?, device: String) throws -> [String: Any] {
        let key = P256.Signing.PrivateKey()
        let code = try devCode(mobile)
        let ch = try XCTUnwrap((try call("POST", "/v1/auth/challenge") as? [String: Any])?["challenge"] as? String)
        let sig = try key.signature(for: Data(("guardian-registry/v1:" + ch).utf8)).derRepresentation
        var body: [String: Any] = ["mobile": mobile, "code": code, "device_id": device, "platform": "ios", "challenge": ch,
                                   "device_key": key.publicKey.derRepresentation.base64EncodedString(),
                                   "device_proof": sig.base64EncodedString()]
        if let name { body["display_name"] = name }
        return try call("POST", "/v1/auth/verify", body) as? [String: Any] ?? [:]
    }

    private func bank() throws -> [String: String] {
        let admin = ["X-Admin-Token": "dev-admin"]
        let ref = "RBI-IOS-\(run)"
        try call("PUT", "/v1/admin/register/bank", ["source": "ios app test", "as_of": "2026-11-24",
                                                    "entities": [["regulator_ref": ref, "name": "iOS Test Bank"]]], headers: admin)
        let b = try call("POST", "/v1/admin/participants", ["name": "iOS Test Bank \(run)", "kind": "bank", "regulator_ref": ref],
                         headers: admin) as? [String: Any]
        XCTAssertEqual(b?["status"] as? String, "active")
        return ["X-Api-Key": try XCTUnwrap(b?["api_key"] as? String)]
    }

    private func check(_ bank: [String: String], _ mobile: String, _ txn: String, rupees: Int) throws -> [String: Any] {
        try call("POST", "/v1/checks", ["mobile": mobile, "participant_txn_id": "\(txn)-\(run)", "amount": rupees * 100,
                                        "payee": "shop\(run)@upi", "channel": "upi"], headers: bank) as? [String: Any] ?? [:]
    }

    private func until(_ what: String, timeout: TimeInterval = 20, _ cond: () throws -> Bool) throws {
        let end = Date().addingTimeInterval(timeout)
        while !(try cond()) {
            if Date() > end { XCTFail("timed out waiting for: \(what)"); return }
            Thread.sleep(forTimeInterval: 0.3)
        }
    }

    // ------------------------------------------------------------------ app helpers
    private func launch(token: String?, reset: Bool = false, hindi: Bool = false) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchEnvironment["GR_UI_TEST"] = "1"
        app.launchEnvironment["GR_API_BASE_OVERRIDE"] = base
        if let token { app.launchEnvironment["GR_TEST_TOKEN"] = token }
        if reset { app.launchEnvironment["GR_TEST_RESET"] = "1" }
        if hindi { app.launchArguments += ["-AppleLanguages", "(hi)", "-AppleLocale", "hi_IN"] }
        app.launch()
        return app
    }

    private func text(_ app: XCUIApplication, _ s: String) -> XCUIElement {
        app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] %@", s)).firstMatch
    }

    /// On screen, clear of the navigation bar at the top and the tab bar at the bottom. A frame
    /// check, not isHittable: asking for hittability while a list is still scrolling can fail.
    private func onScreen(_ app: XCUIApplication, _ el: XCUIElement) -> Bool {
        guard el.exists else { return false }
        let f = el.frame, w = app.frame
        return !f.isEmpty && f.midY > w.minY + 100 && f.midY < w.maxY - 110 && f.midX > w.minX && f.midX < w.maxX
    }

    /// Wait for it, scrolling the list down (then back up) until it is on screen.
    @discardableResult
    private func see(_ app: XCUIApplication, _ el: XCUIElement, _ what: String, timeout: TimeInterval = 25) -> XCUIElement {
        _ = el.waitForExistence(timeout: 5)
        let end = Date().addingTimeInterval(timeout)
        var swipes = 0
        while Date() < end {
            if onScreen(app, el) { return el }
            if el.exists {
                // below the fold or under a bar: scroll towards it
                if el.frame.midY >= app.frame.maxY - 110 { app.swipeUp(velocity: .slow) } else { app.swipeDown(velocity: .slow) }
            } else if swipes < 6 {
                app.swipeUp(velocity: .slow)
            } else {
                app.swipeDown(velocity: .slow)
            }
            swipes += 1
            Thread.sleep(forTimeInterval: 1.0)   // let the list come to rest
        }
        XCTFail("not on screen: \(what)")
        return el
    }

    private func tap(_ app: XCUIApplication, button label: String) {
        let el = see(app, app.buttons[label].firstMatch, "button \(label)")
        el.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
    }

    /// Tap, then wait for the registry to show the effect; if the tap landed while the list
    /// was redrawing and nothing arrived, tap once more.
    private func tapUntil(_ app: XCUIApplication, button label: String, _ what: String, _ cond: () throws -> Bool) throws {
        for attempt in 0..<3 {
            tap(app, button: label)
            let end = Date().addingTimeInterval(8)
            while Date() < end {
                if try cond() { return }
                Thread.sleep(forTimeInterval: 0.3)
            }
            if attempt == 2 { XCTFail("timed out waiting for: \(what)") }
        }
    }

    private func tab(_ app: XCUIApplication, _ index: Int) {
        let b = app.tabBars.buttons.element(boundBy: index)
        XCTAssertTrue(b.waitForExistence(timeout: 10))
        b.tap()
    }

    /// Switch away and back: the tab reloads its data.
    private func reloadTab(_ app: XCUIApplication, _ index: Int) {
        tab(app, index == 0 ? 1 : 0)
        tab(app, index)
    }

    private func confirm(_ app: XCUIApplication, _ label: String) {
        let sheet = app.sheets.firstMatch
        if sheet.waitForExistence(timeout: 5) {
            sheet.buttons[label].tap()
        } else {
            app.buttons.matching(NSPredicate(format: "label == %@", label)).element(boundBy: 1).tap()
        }
    }

    private func shot(_ name: String) {
        Thread.sleep(forTimeInterval: 0.8)
        let png = XCUIScreen.main.screenshot().pngRepresentation
        let attachment = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
        if let dir = ProcessInfo.processInfo.environment["GR_SHOTS"] {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try? png.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(name).png"))
        }
    }

    // ------------------------------------------------------------------ the flows
    func testEveryScreenForAPersonAndTheirGuardian() throws {
        let pm = mobile(), gm = mobile(), third = mobile()
        let p = try person(pm, "Asha \(run)"), g = try person(gm, "Ravi \(run)")
        _ = try person(third, "Meena \(run)")
        let inv = try call("POST", "/v1/me/guardians", ["mobile": gm], token: p) as? [String: Any]
        try call("POST", "/v1/guardian/invitations/\(inv?["id"] as? String ?? "")/accept", token: g)
        let bank = try bank()

        // ---- the protected person: My protection
        var app = launch(token: p)
        see(app, text(app, "Hello, Asha \(run)"), "greeting")
        see(app, text(app, "Payments are on"), "status")
        shot("ios-01-my-protection")

        let before = try obj("/v1/me/rules", token: p)
        try tapUntil(app, button: "Apply", "preset applied") {   // the first ready-made set
            NSDictionary(dictionary: try obj("/v1/me/rules", token: p)) != NSDictionary(dictionary: before)
        }
        try call("POST", "/v1/me/rules/preset/senior_with_guardian", token: p)   // guardian approves from ₹10,000

        app.swipeDown(velocity: .fast); app.swipeDown(velocity: .fast)
        Thread.sleep(forTimeInterval: 1.0)
        try tapUntil(app, button: "Pause all payments", "paused") { try obj("/v1/me/rules", token: p)["kill_switch"] as? Bool == true }
        see(app, text(app, "Payments are paused"), "paused")
        try tapUntil(app, button: "Switch payments back on", "change held") {
            (try call("GET", "/v1/me/changes", token: p) as? [[String: Any]] ?? []).contains { $0["status"] as? String == "pending" }
        }
        see(app, text(app, "Changes waiting"), "held change")
        shot("ios-02-paused-change-waiting")
        XCTAssertEqual(try obj("/v1/me/rules", token: p)["kill_switch"] as? Bool, true, "still paused until a guardian approves")

        let field = see(app, app.textFields["Invite a guardian by mobile number"], "invite field")
        field.tap()
        field.typeText(third)
        tap(app, button: "Invite")
        try until("invitation") {
            (try call("GET", "/v1/me/guardians", token: p) as? [[String: Any]] ?? []).contains { $0["status"] as? String == "invited" }
        }
        see(app, text(app, "invited"), "invited pill")
        shot("ios-03-guardians")
        app.terminate()

        // ---- the guardian: I protect
        app = launch(token: g)
        see(app, text(app, "Hello, Ravi \(run)"), "guardian greeting")
        tab(app, 1)
        see(app, text(app, "Protection changes waiting"), "change waiting")
        see(app, text(app, "Asha \(run) wants to: Switch payments back on"), "who wants what")
        shot("ios-04-guardian-change-waiting")
        try tapUntil(app, button: "Approve now", "payments back on") { try obj("/v1/me/rules", token: p)["kill_switch"] as? Bool == false }

        let c1 = try check(bank, pm, "big", rupees: 20_000)
        XCTAssertEqual(c1["status"] as? String, "pending_approval")
        reloadTab(app, 1)
        see(app, text(app, "Waiting for approval"), "payment waiting")
        see(app, text(app, "from Asha \(run)"), "from whom")
        shot("ios-05-guardian-payment-waiting")
        tap(app, button: "Approve")
        confirm(app, "Approve")
        try until("approved") { try obj("/v1/checks/\(c1["check_id"] as? String ?? "")", headers: bank)["status"] as? String == "approved" }

        let c2 = try check(bank, pm, "deny", rupees: 15_000)
        reloadTab(app, 1)
        see(app, text(app, "Waiting for approval"), "second payment")
        try tapUntil(app, button: "Deny", "denied") { try obj("/v1/checks/\(c2["check_id"] as? String ?? "")", headers: bank)["status"] as? String == "denied" }
        see(app, text(app, "Nothing is waiting for you."), "nothing waiting")

        tap(app, button: "Pause their payments")
        confirm(app, "Pause their payments")
        try until("paused by guardian") { try obj("/v1/me/rules", token: p)["kill_switch"] as? Bool == true }

        tab(app, 3)
        see(app, text(app, "No device keys yet."), "devices (API sign-in has no key)")
        see(app, app.buttons["Sign out here"], "sign out")
        shot("ios-06-devices")
        app.terminate()

        // ---- back to the person: recent payments, alerts, lost phone
        app = launch(token: p)
        see(app, text(app, "Payments are paused"), "paused by guardian")
        see(app, text(app, "Approved"), "approved payment")
        see(app, text(app, "Denied"), "denied payment")
        shot("ios-07-recent-payments")
        tab(app, 2)
        see(app, app.buttons["Mark all read"], "mark all read")
        shot("ios-08-alerts")
        try tapUntil(app, button: "Mark all read", "alerts read") { (try call("GET", "/v1/me/notifications?unread_only=true&limit=100", token: p) as? [Any] ?? [1]).isEmpty }
        tab(app, 0)
        tap(app, button: "Report lost phone")
        confirm(app, "Report lost phone")
        see(app, app.buttons["Send code"], "signed out")
        XCTAssertThrowsError(try obj("/v1/me", token: p), "the old session still works after a lost-phone report")
        app.terminate()
    }

    /// A second phone for the same person is on probation: the banner shows a readable time and
    /// the actions the registry would refuse become a note (Decline stays).
    func testARestrictedSignInShowsANoteInsteadOfApprove() throws {
        let pm = mobile(), gm = mobile()
        let p = try person(pm, "Usha \(run)")
        _ = try keySignIn(gm, "Vikram \(run)", device: "phone-1")   // first phone: trusted at once
        try call("POST", "/v1/me/guardians", ["mobile": gm], token: p)
        Thread.sleep(forTimeInterval: 31)                              // the registry's resend cooldown
        let second = try keySignIn(gm, nil, device: "phone-2")         // a new phone: 24 h probation
        XCTAssertEqual(second["restricted"] as? Bool, true)

        let app = launch(token: try XCTUnwrap(second["token"] as? String))
        tab(app, 1)
        see(app, text(app, "Usha \(run) asked you to be their payment guardian."), "invitation")
        see(app, text(app, "Not on this sign-in yet"), "restricted note")
        XCTAssertFalse(app.buttons["Accept"].exists, "Accept is refused on a restricted sign-in")
        see(app, app.buttons["Decline"], "decline stays")
        let banner = text(app, "This sign-in is restricted for now")
        see(app, banner, "banner")
        XCTAssertFalse(banner.label.contains("+00:00"), banner.label)
        shot("ios-09-restricted-sign-in")
        app.terminate()
    }

    func testSignInThroughTheScreensWithTheDeviceKey() throws {
        let m = mobile()
        let app = launch(token: nil, reset: true)
        let field = see(app, app.textFields["Mobile number"], "mobile field")
        field.tap()
        field.typeText(m)
        shot("ios-10-sign-in")
        tap(app, button: "Send code")
        let name = see(app, app.textFields["Your name (first time only)"], "name field")
        name.tap()
        name.typeText("Kiran \(run)")
        tap(app, button: "Sign in")
        see(app, text(app, "Hello, Kiran \(run)"), "signed in")
        tab(app, 3)
        see(app, text(app, "This device"), "this device")
        see(app, text(app, "trusted"), "trusted key")
        shot("ios-11-this-device")
        tap(app, button: "Sign out here")
        see(app, app.buttons["Send code"], "signed out")
        app.terminate()
    }

    /// The same screens in Hindi, for the screenshots: longer words must still fit.
    func testHindiScreensFit() throws {
        let pm = mobile(), gm = mobile()
        let p = try person(pm, "आशा \(run)"), g = try person(gm, "रवि \(run)")
        let inv = try call("POST", "/v1/me/guardians", ["mobile": gm], token: p) as? [String: Any]
        try call("POST", "/v1/guardian/invitations/\(inv?["id"] as? String ?? "")/accept", token: g)
        try call("POST", "/v1/me/rules/preset/senior_with_guardian", token: p)
        _ = try check(try bank(), pm, "hi", rupees: 20_000)   // before pausing: a paused person's payments are blocked
        try call("POST", "/v1/me/kill-switch/on", token: p)
        try call("POST", "/v1/me/kill-switch/off", token: p)

        var app = launch(token: p, hindi: true)
        see(app, text(app, "भुगतान रुके हुए हैं"), "paused, in Hindi")
        shot("ios-hi-01-my-protection")
        app.terminate()

        app = launch(token: g, hindi: true)
        tab(app, 1)
        see(app, text(app, "प्रतीक्षा में सुरक्षा बदलाव"), "changes waiting, in Hindi")
        shot("ios-hi-02-i-protect")
        app.terminate()
    }

    /// The person's own limits, name correction and nominee, through the screens.
    func testLimitsNameAndNominee() throws {
        let p = try person(mobile(), "Lata \(run)")
        let app = launch(token: p)
        see(app, text(app, "Hello, Lata \(run)"), "greeting")

        let payee = see(app, app.textFields["limit-per_payee_daily_limit"], "per-payee limit field")
        payee.tap()
        payee.typeText("20000")
        try tapUntil(app, button: "Save limits", "per-payee limit") {
            (try obj("/v1/me/rules", token: p)["per_payee_daily_limit"] as? Int) == 20_000 * 100
        }
        see(app, text(app, "Most per payee per day"), "rule row")
        shot("ios-12-limits")

        let name = see(app, app.textFields["Your name"], "name field")
        name.tap()
        let current = name.value as? String ?? ""
        name.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: current.count + 2))
        name.typeText("Lata Devi \(run)")
        try tapUntil(app, button: "Save name", "name") {
            (try obj("/v1/me", token: p)["display_name"] as? String) == "Lata Devi \(run)"
        }

        for (field, value) in [("Nominee's name", "Kumar"), ("Relation (for example, son)", "son"),
                               ("Nominee's mobile number", "9876543210")] {
            let f = see(app, app.textFields[field], field)
            f.tap()
            f.typeText(value)
        }
        try tapUntil(app, button: "Save nominee", "nominee") {
            (try obj("/v1/me/nominee", token: p)["nominee"] as? [String: Any]) != nil
        }
        see(app, app.buttons["Remove nominee"], "nominee shown")
        shot("ios-13-your-details")
        app.terminate()
    }
}
