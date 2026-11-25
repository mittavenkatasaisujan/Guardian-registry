import SwiftUI

/// Sign-in, then the web app's four tabs. Labels are English keys translated through
/// Localizable.strings; names, payees and alerts come from the server and are shown verbatim.
struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            switch model.screen {
            case .mobile: NavigationStack { MobileView() }
            case .code: NavigationStack { CodeView() }
            case .home: HomeTabs()
            }
        }
        .disabled(model.busy)
        .overlay(alignment: .bottom) { Toast() }
    }
}

/// A short message near the bottom that clears itself, like the web app's toast.
struct Toast: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if let m = model.message {
            Text(verbatim: m)
                .font(.subheadline)
                .multilineTextAlignment(.leading)
                .padding(.horizontal, 16).padding(.vertical, 12)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                .shadow(radius: 4, y: 2)
                .padding(.horizontal, 16)
                .padding(.bottom, model.screen == .home ? 100 : 24)   // clear of the tab bar
                .allowsHitTesting(false)   // never in the way of a button underneath
                .task(id: m) {
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                    if model.message == m { model.message = nil }
                }
                .accessibilityIdentifier("toast")
        }
    }
}

// ------------------------------------------------------------------ sign-in
struct MobileView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Form {
            Section {
                Text("Payments from your account can need a family member's OK. Sign in with your mobile number.")
                TextField("Mobile number", text: $model.mobile)
                    .keyboardType(.phonePad).textContentType(.telephoneNumber)
                #if DEBUG
                TextField("Server address (testing)", text: $model.server)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                #endif
                Button("Send code") { model.sendCode() }.disabled(model.mobile.count < 10)
            }
        }
        .navigationTitle("Guardian Registry")
    }
}

struct CodeView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Form {
            Section(footer: Text("Never share this code, not even with a guardian or a bank.")) {
                if let dev = model.devCode {
                    Pill(text: L("Development mode code: %@", dev), color: .orange)
                }
                TextField("6-digit code", text: $model.code).keyboardType(.numberPad).textContentType(.oneTimeCode)
                TextField("Your name (first time only)", text: $model.name)
                Toggle("I am 18 or older", isOn: $model.adult)
                    .accessibilityIdentifier("adult")
                Button("Sign in") { model.signIn() }.disabled(model.code.count < 4)
                Button("Back") { model.screen = .mobile }
            }
        }
        .navigationTitle("Enter the code")
    }
}

// ------------------------------------------------------------------ tabs
struct HomeTabs: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        TabView(selection: $model.tab) {
            NavigationStack { MyProtectionView() }
                .tabItem { Label("My protection", systemImage: "shield.lefthalf.filled") }
                .tag(AppModel.Tab.me)
            NavigationStack { GuardianView() }
                .tabItem { Label("I protect", systemImage: "person.2.fill") }
                .badge(model.inboxCount)
                .tag(AppModel.Tab.guardian)
            NavigationStack { AlertsView() }
                .tabItem { Label("Alerts", systemImage: "bell.fill") }
                .badge(model.unread)
                .tag(AppModel.Tab.alerts)
            NavigationStack { DevicesView() }
                .tabItem { Label("Devices", systemImage: "iphone") }
                .tag(AppModel.Tab.devices)
        }
        .onChange(of: model.tab) { _ in model.reload() }
        .onAppear { model.reload() }
        .task {
            // refresh every 15 seconds while signed in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 15_000_000_000)
                await model.refresh()
            }
        }
    }
}

/// The restricted-sign-in banner, at the top of every tab.
struct RestrictedSection: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if model.restricted {
            Section {
                Text(verbatim: L("This sign-in is restricted for now: %@. You can still pause payments, deny or stop payments, and make rules stricter.",
                                 model.restrictionReasons))
                    .font(.subheadline).foregroundStyle(Color(red: 0.49, green: 0.18, blue: 0.07))
                    .listRowBackground(Color.orange.opacity(0.15))
            }
        }
    }
}

/// A section heading as written (the web app's headings), not in capitals.
struct Heading: View {
    let key: LocalizedStringKey
    init(_ key: LocalizedStringKey) { self.key = key }
    var body: some View {
        Text(key).textCase(nil)
    }
}

/// In place of an action the registry would refuse on a restricted sign-in.
struct RestrictedNote: View {
    var body: some View {
        Text("Not on this sign-in yet: it is restricted (see the note at the top).")
            .font(.footnote).foregroundStyle(.orange)
    }
}

struct Pill: View {
    let text: String
    let color: Color
    var body: some View {
        Text(verbatim: text)
            .font(.caption.bold())
            .foregroundStyle(color)
            .padding(.horizontal, 10).padding(.vertical, 3)
            .background(color.opacity(0.15), in: Capsule())
            .fixedSize()
    }
}

/// One row of a key: value list (rules).
struct RuleRow: View {
    let label: LocalizedStringKey
    let value: String
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(verbatim: value).bold().multilineTextAlignment(.trailing)
        }
        .font(.subheadline)
    }
}

/// Shared texts that depend on server values.
enum Words {
    static func identity(_ level: String) -> String {
        switch level {
        case "bank_verified": return L("verified by a bank")
        case "bank_min_kyc": return L("basic bank check")
        case "otp": return L("phone number only")
        default: return level
        }
    }

    static func change(_ kind: String) -> String {
        switch kind {
        case "update_rules": return L("Loosen payment limits")
        case "kill_switch_off": return L("Switch payments back on")
        case "remove_guardian": return L("Remove a guardian")
        case "change_mobile": return L("Move to a new number")
        default: return kind
        }
    }

    static func status(_ s: String) -> (String, Color) {
        switch s {
        case "allowed": return (L("Allowed"), .green)
        case "approved": return (L("Approved"), .green)
        case "released": return (L("Released"), .green)
        case "pending_approval": return (L("Waiting for approval"), .orange)
        case "cooling_off": return (L("On hold"), .orange)
        case "blocked": return (L("Blocked"), .red)
        case "denied": return (L("Denied"), .red)
        case "expired": return (L("Expired"), .red)
        case "cancelled": return (L("Cancelled"), .gray)
        case "failed": return (L("Failed"), .gray)
        case "active": return (L("active"), .green)
        case "invited": return (L("invited"), .orange)
        case "declined": return (L("declined"), .gray)
        case "trusted": return (L("trusted"), .green)
        case "probation": return (L("probation"), .orange)
        case "revoked": return (L("revoked"), .gray)
        default: return (s, .gray)
        }
    }

    static func money(_ rules: [String: Any], _ key: String) -> String {
        guard let v = rules[key] as? Int else { return L("No limit") }
        return Wire.rupees(paise: v)
    }
}

/// A payment: amount, status, payee, time and reasons.
struct PaymentInfo: View {
    let p: [String: Any]
    let from: String?
    var body: some View {
        let st = Words.status(p["status"] as? String ?? "")
        let reasons = (p["reasons"] as? [String] ?? []).joined(separator: "; ")
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(verbatim: Wire.rupees(paise: p["amount"] as? Int ?? 0)).font(.title3.bold())
                Spacer()
                Pill(text: st.0, color: st.1)
            }
            Text(verbatim: L("To %@", p["payee"] as? String ?? "") + (from.map { " · " + L("from %@", $0) } ?? ""))
            Text(verbatim: Wire.time(p["created_at"] as? String ?? "") + (reasons.isEmpty ? "" : " · " + reasons))
                .font(.footnote).foregroundStyle(.secondary)
        }
    }
}

// ------------------------------------------------------------------ My protection
struct MyProtectionView: View {
    @EnvironmentObject var model: AppModel
    @State private var preset = ""
    @State private var invite = ""
    @State private var confirmLost = false
    @State private var confirmDelete = false
    @State private var complaint = ""
    @State private var limits: [String: String] = [:]
    @State private var limitsLoaded = false
    @State private var newName = ""
    @State private var quietChannels: Set<String> = []
    @State private var quietStart = 22
    @State private var quietEnd = 6
    @State private var quietLoaded = false
    @State private var nomName = ""
    @State private var nomRelation = ""
    @State private var nomMobile = ""

    var body: some View {
        List {
            RestrictedSection()
            if model.loaded {
                if !model.agreedToNotice { privacy }
                status
                simWindow
                changesWaiting
                rules
                limitsForm
                quietHours
                guardians
                recent
                details
                if model.agreedToNotice { privacy }
                yourData
                complaintsSection
                lost
            }
        }
        .textCase(nil)
        .headerProminence(.increased)   // headings in normal case and a little larger, like the web app
        .scrollDismissesKeyboard(.interactively)
        .toolbar {
            // number and phone keypads have no return key: give them a way to close
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("Done") {
                    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
                }
                .accessibilityIdentifier("keyboard-done")
            }
        }
        .navigationTitle(Text(verbatim: model.loaded ? L("Hello, %@", model.me["display_name"] as? String ?? "") : L("My protection")))
        .refreshable { await model.refresh() }
        .confirmationDialog("Sign out of every device and hold larger payments for 72 hours?",
                            isPresented: $confirmLost, titleVisibility: .visible) {
            Button("Report lost phone", role: .destructive) { model.lostPhone() }
        }
        .confirmationDialog("Delete your account in 7 days? Your guardians will stop protecting your payments.",
                            isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete my account", role: .destructive) { model.requestErasure() }
        }
        .fileExporter(isPresented: Binding(get: { model.exportFile != nil }, set: { if !$0 { model.exportFile = nil } }),
                      document: model.exportFile, contentType: .json, defaultFilename: "guardian-registry-my-data") { result in
            if case .success = result { model.message = L("Saved your data.") }
        }
    }

    private var status: some View {
        Section {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Circle().fill(model.paused ? Color.red : Color.green).frame(width: 12, height: 12)
                    (model.paused ? Text("Payments are paused") : Text("Payments are on")).font(.title3.bold())
                }
                (model.paused ? Text("No bank will send money from your accounts until payments are switched back on.")
                              : Text("If someone is pressuring you to pay, pause everything. You can switch back on later."))
                    .foregroundStyle(.secondary)
                if model.paused {
                    if model.restricted {
                        RestrictedNote()
                    } else {
                        Button("Switch payments back on") { model.switchBackOn() }
                            .buttonStyle(.bordered).frame(maxWidth: .infinity)
                    }
                } else {
                    Button(role: .destructive) {
                        model.act("/v1/me/kill-switch/on", done: L("All payments are paused."))
                    } label: {
                        Text("Pause all payments").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent).tint(.red)
                }
            }
            .padding(.vertical, 6)
        } header: {
            Text(verbatim: L("Identity: %@", Words.identity(model.me["identity_level"] as? String ?? "")))
                .font(.footnote).fontWeight(.regular).foregroundStyle(.secondary).textCase(nil)
        }
    }

    @ViewBuilder private var simWindow: some View {
        if model.security["sim_swap_window_open"] as? Bool == true {
            Section {
                Text(verbatim: L("Until %@, larger payments are held and new sign-ins can't approve anything.",
                                 Wire.time(model.security["window_ends_at"] as? String ?? "")))
                Text("If you changed your SIM yourself, confirm it from this phone. If you didn't, call your mobile operator now.")
                    .foregroundStyle(.secondary)
                if model.restricted {
                    RestrictedNote()
                } else {
                    Button("Yes, I changed my SIM") {
                        model.act("/v1/me/security/confirm-sim-change", done: L("Thanks. Normal protection applies again."))
                    }
                }
            } header: { Heading("Your SIM card was reported changed") }
        }
    }

    @ViewBuilder private var changesWaiting: some View {
        let pending = model.changes.filter { $0["status"] as? String == "pending" }
        if !pending.isEmpty {
            Section(header: Heading("Changes waiting")) {
                ForEach(pending.indices, id: \.self) { i in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(verbatim: Words.change(pending[i]["kind"] as? String ?? "")).bold()
                        Text(verbatim: L("Takes effect %@ unless a guardian stops it.", Wire.time(pending[i]["effective_at"] as? String ?? "")))
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private var rules: some View {
        let r = model.rules
        let minutes = { (k: String) in L("%@ min", String(r[k] as? Int ?? 0)) }
        let channels = (r["blocked_channels"] as? [String] ?? []).map { $0.uppercased() }.joined(separator: ", ")
        let yesNo = { (k: String) in (r[k] as? Bool ?? false) ? L("Yes") : L("No") }
        return Section {
            RuleRow(label: "Most per payment", value: Words.money(r, "per_txn_limit"))
            RuleRow(label: "Most per day (all banks)", value: Words.money(r, "daily_limit"))
            RuleRow(label: "Guardian approves from", value: Words.money(r, "approval_threshold"))
            RuleRow(label: "Wait on new payees from", value: Words.money(r, "new_payee_delay_threshold"))
            RuleRow(label: "Wait time", value: minutes("cooling_off_minutes"))
            RuleRow(label: "Time for guardian to answer", value: minutes("approval_timeout_minutes"))
            RuleRow(label: "Blocked channels", value: channels.isEmpty ? L("None") : channels)
            RuleRow(label: "Only bank-verified guardians approve", value: yesNo("require_verified_guardian"))
            RuleRow(label: "Hold payments after a SIM change", value: yesNo("sim_swap_hold"))
            RuleRow(label: "Hold payments that look like a scam", value: yesNo("scam_signals"))
            RuleRow(label: "Most per payee per day", value: Words.money(r, "per_payee_daily_limit"))
            RuleRow(label: "Daily limits by channel", value: {
                let m = r["channel_daily_limits"] as? [String: Int] ?? [:]
                return m.isEmpty ? L("None") : m.keys.sorted().map { "\($0.uppercased()) \(Wire.rupees(paise: m[$0] ?? 0))" }
                    .joined(separator: " · ")
            }())
            RuleRow(label: "Trusted person checks", value: (r["approval_scope"] as? String) == "rbi"
                    ? L("Transfers only (not UPI, shops or recurring)") : L("All payments"))
            RuleRow(label: "Quiet hours", value: (r["quiet_hours"] as? [String: Any]).map(Self.quietText) ?? L("None"))
            RuleRow(label: "New guardian can approve after", value: {
                let h = r["new_guardian_wait_hours"] as? Int ?? 0
                return h > 0 ? L("%@ hours", String(h)) : L("Right away")
            }())
            Picker("Use a ready-made set", selection: $preset) {
                ForEach(model.presets) { p in Text(verbatim: p.label).tag(p.id) }
            }
            .pickerStyle(.navigationLink)
            .onAppear { if preset.isEmpty { preset = model.presets.first?.id ?? "" } }
            Button("Apply") { model.applyPreset(preset) }.disabled(preset.isEmpty)
        } header: {
            Heading("My rules")
        } footer: {
            Text("Making rules stricter works at once. Loosening them waits 24 hours, and your guardians can stop it.")
        }
    }

    private struct LimitField: Identifiable {
        let id: String
        let label: LocalizedStringKey
    }

    private static let limitKeys = [
        LimitField(id: "per_txn_limit", label: "Most per payment (₹)"),
        LimitField(id: "daily_limit", label: "Most per day, all banks (₹)"),
        LimitField(id: "per_payee_daily_limit", label: "Most per payee per day (₹)"),
        LimitField(id: "approval_threshold", label: "Guardian approves from (₹)"),
    ]

    private var limitsForm: some View {
        Section {
            ForEach(Self.limitKeys) { field in
                VStack(alignment: .leading, spacing: 4) {
                    Text(field.label).font(.subheadline.bold())
                    TextField("No limit", text: Binding(get: { limits[field.id] ?? "" }, set: { limits[field.id] = $0 }))
                        .keyboardType(.numberPad)
                        .accessibilityIdentifier("limit-\(field.id)")
                }
            }
            Button("Save limits") { model.saveLimits(limits) }
        } header: {
            Heading("Change my limits")
        } footer: {
            Text("Leave a box empty for no limit. Stricter limits apply at once; looser ones wait 24 hours and your guardians can stop them.")
        }
        .onAppear {
            guard !limitsLoaded else { return }
            limitsLoaded = true
            for field in Self.limitKeys {
                if let v = model.rules[field.id] as? Int { limits[field.id] = String(v / 100) }
            }
        }
    }

    private static let channels = ["upi", "imps", "neft", "rtgs", "card", "netbanking"]

    private static func channelName(_ c: String) -> String {
        switch c {
        case "card": return L("Card")
        case "netbanking": return L("Net banking")
        default: return c.uppercased()
        }
    }

    private static func hourText(_ h: Int) -> String { String(format: "%02d:00", h) }

    /// "UPI, Card · 22:00–06:00"
    private static func quietText(_ q: [String: Any]) -> String {
        let names = (q["channels"] as? [String] ?? []).map(channelName).joined(separator: ", ")
        return "\(names) · \(hourText(q["start"] as? Int ?? 0))–\(hourText(q["end"] as? Int ?? 0))"
    }

    private var quietHours: some View {
        Section {
            Text("Payment types to switch off").font(.subheadline.bold())
            ForEach(Self.channels, id: \.self) { c in
                Toggle(isOn: Binding(get: { quietChannels.contains(c) },
                                     set: { on in if on { quietChannels.insert(c) } else { quietChannels.remove(c) } })) {
                    Text(verbatim: Self.channelName(c))
                }
                .accessibilityIdentifier("quiet-\(c)")
            }
            Picker("From", selection: $quietStart) {
                ForEach(0..<24, id: \.self) { Text(verbatim: Self.hourText($0)).tag($0) }
            }
            Picker("To", selection: $quietEnd) {
                ForEach(0..<24, id: \.self) { Text(verbatim: Self.hourText($0)).tag($0) }
            }
            Button("Save quiet hours") {
                model.saveQuietHours(channels: Self.channels.filter { quietChannels.contains($0) }, start: quietStart, end: quietEnd)
            }
            if model.rules["quiet_hours"] is [String: Any] {
                Button("Turn off quiet hours", role: .destructive) { model.removeQuietHours() }
            }
        } header: {
            Heading("Quiet hours")
        } footer: {
            Text("Switch chosen payment types off every day between two times (India time). Recurring payments you have already set up still run.")
        }
        .onAppear {
            guard !quietLoaded else { return }
            quietLoaded = true
            if let q = model.rules["quiet_hours"] as? [String: Any] {
                quietChannels = Set(q["channels"] as? [String] ?? [])
                quietStart = q["start"] as? Int ?? 22
                quietEnd = q["end"] as? Int ?? 6
            }
        }
    }

    private static let noticeParts: [(String, LocalizedStringKey)] = [
        ("what_we_collect", "What we collect"), ("why", "Why we use it"), ("who_sees_it", "Who sees it"),
        ("who_can_use_it", "Who can use this service"), ("how_long", "How long we keep it"), ("your_rights", "Your rights"),
    ]

    /// The privacy notice (in the language the server sent) and, until they agree, the "I agree" button.
    private var privacy: some View {
        Section {
            if !model.agreedToNotice {
                Text("Please read how we use your data. Your protection works once you agree.")
            }
            DisclosureGroup("Read the privacy notice") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(Self.noticeParts, id: \.0) { key, title in
                        if let items = model.notice[key] as? [String], !items.isEmpty {
                            Text(title).font(.subheadline.bold()).padding(.top, 6)
                            ForEach(items, id: \.self) { Text(verbatim: "•  " + $0).font(.footnote) }
                        }
                    }
                    Text("Grievance officer").font(.subheadline.bold()).padding(.top, 6)
                    Text(verbatim: model.notice["grievance_officer"] as? String ?? "").font(.footnote)
                    Text(verbatim: L("Version %@", model.notice["version"] as? String ?? ""))
                        .font(.caption).foregroundStyle(.secondary).padding(.top, 4)
                }
            }
            if !model.agreedToNotice {
                Button("I agree") { model.agreeToNotice() }.bold()
            }
        } header: {
            Heading("Privacy notice")
        }
    }

    /// DPDP rights: a copy of everything held, and deleting the account (held 7 days, can be cancelled).
    private var yourData: some View {
        Section {
            Text("Everything we hold about you, as a file (JSON). Keep it private: it has your mobile number.")
                .font(.footnote).foregroundStyle(.secondary)
            if model.restricted {
                RestrictedNote()
            } else {
                Button("Download my data") { model.prepareExport() }
            }
            Text("Delete my account").font(.headline).padding(.top, 6)
            if let e = model.erasure {
                Text(verbatim: L("Your account will be deleted on %@.", Wire.time(e["erase_at"] as? String ?? ""))).bold()
                Text("Your guardians stop protecting your payments then. If someone told you to do this, cancel it.")
                    .font(.footnote).foregroundStyle(.secondary)
                Button("Cancel deletion") { model.cancelErasure() }.bold()
            } else {
                Text("Your account and your protection end 7 days after you ask. Your guardians are told, and you can cancel until then.")
                    .font(.footnote).foregroundStyle(.secondary)
                if model.restricted {
                    RestrictedNote()
                } else {
                    Button("Delete my account", role: .destructive) { confirmDelete = true }
                }
            }
        } header: {
            Heading("Your data")
        }
    }

    /// DPDP Act s.13: complain to the grievance officer; answers come back here within 90 days.
    private var complaintsSection: some View {
        Section {
            TextField("Your complaint", text: $complaint, axis: .vertical)
                .lineLimit(3...8)
                .accessibilityIdentifier("complaint")
            Button("Send complaint") { model.sendComplaint(complaint) { complaint = "" } }
                .disabled(complaint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            ForEach(model.complaints.indices, id: \.self) { i in
                let g = model.complaints[i]
                let answered = (g["status"] as? String) == "answered"
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(verbatim: Wire.time(g["created_at"] as? String ?? "")).font(.footnote).foregroundStyle(.secondary)
                        Spacer()
                        Text(answered ? "Answered" : "Waiting").font(.caption.bold())
                            .foregroundStyle(answered ? .green : .orange)
                    }
                    Text(verbatim: g["text"] as? String ?? "")
                    if answered {
                        Text(verbatim: L("Our answer: %@", g["answer"] as? String ?? "")).foregroundStyle(.green)
                    } else {
                        Text(verbatim: L("Answer due by %@", Wire.time(g["due_at"] as? String ?? "")))
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)
            }
        } header: {
            Heading("Complaints")
        } footer: {
            Text("Not happy with how we handle your data or your protection? Write to our grievance officer. We answer within 90 days, here in the app.")
        }
    }

    private var details: some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                Text("Your name").font(.subheadline.bold())
                HStack(spacing: 12) {
                    TextField("Your name", text: $newName).textContentType(.name)
                        .onAppear { if newName.isEmpty { newName = model.me["display_name"] as? String ?? "" } }
                    Button("Save name") { model.saveName(newName) }
                        .buttonStyle(.bordered).disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Nominee").font(.headline)
                Text("Someone who can use your data rights if you die or can't act yourself. They get no access to your account or payments.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if let n = model.nominee {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: n["name"] as? String ?? "").bold()
                    Text(verbatim: "\(n["relation"] as? String ?? "") · \(n["mobile"] as? String ?? "")")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if model.restricted {
                    RestrictedNote()
                } else {
                    Button("Remove nominee", role: .destructive) { model.removeNominee() }
                }
            } else {
                Text("No nominee yet.").foregroundStyle(.secondary)
                if model.restricted {
                    RestrictedNote()
                } else {
                    TextField("Nominee's name", text: $nomName).textContentType(.name)
                    TextField("Relation (for example, son)", text: $nomRelation)
                    TextField("Nominee's mobile number", text: $nomMobile).keyboardType(.phonePad)
                    Button("Save nominee") { model.saveNominee(name: nomName, relation: nomRelation, mobile: nomMobile) }
                }
            }
        } header: {
            Heading("Your details")
        }
    }

    private var guardians: some View {
        Section(header: Heading("My guardians")) {
            if model.guardians.isEmpty {
                Text("No guardians yet. A guardian can approve large payments and pause payments for you.").foregroundStyle(.secondary)
            }
            ForEach(model.guardians.indices, id: \.self) { i in
                let g = model.guardians[i]
                let st = Words.status(g["status"] as? String ?? "")
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: g["guardian_name"] as? String ?? "").bold()
                        Text(verbatim: Words.identity(g["guardian_identity_level"] as? String ?? "")).font(.footnote).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Pill(text: st.0, color: st.1)
                }
            }
            if model.restricted {
                RestrictedNote()
            } else {
                // the number and its button side by side, like the web app: the button stays above the keyboard
                HStack(spacing: 12) {
                    TextField("Mobile number", text: $invite)
                        .accessibilityLabel(Text("Invite a guardian by mobile number"))
                        .keyboardType(.phonePad).textContentType(.telephoneNumber)
                    Button("Invite") {
                        let m = invite.trimmingCharacters(in: .whitespaces)
                        invite = ""
                        model.act("/v1/me/guardians", ["mobile": m], done: L("Invitation sent. They need to accept it in their app."))
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(invite.trimmingCharacters(in: .whitespaces).count < 10)
                }
            }
        }
    }

    private var recent: some View {
        Section(header: Heading("Recent payments")) {
            if model.payments.isEmpty { Text("No payments checked yet.").foregroundStyle(.secondary) }
            ForEach(model.payments.indices, id: \.self) { i in PaymentInfo(p: model.payments[i], from: nil) }
        }
    }

    private var lost: some View {
        Section {
            Text("This signs you out everywhere and holds larger payments for 72 hours.").foregroundStyle(.secondary)
            Button("Report lost phone", role: .destructive) { confirmLost = true }
        } header: { Heading("Lost your phone?") }
    }
}

// ------------------------------------------------------------------ I protect
struct GuardianView: View {
    @EnvironmentObject var model: AppModel
    @State private var approvePayment: String?
    @State private var pauseWard: [String: Any]?

    var body: some View {
        let names = model.wardNames
        let invites = model.inbox["invitations"] as? [[String: Any]] ?? []
        let held = model.inbox["held_payments"] as? [[String: Any]] ?? []
        let changes = model.inbox["pending_changes"] as? [[String: Any]] ?? []
        let recoveries = model.inbox["recoveries"] as? [[String: Any]] ?? []
        let active = model.wards.filter { $0["status"] as? String == "active" }
        List {
            RestrictedSection()
            if !invites.isEmpty {
                Section(header: Heading("Guardian requests")) {
                    ForEach(invites.indices, id: \.self) { i in
                        let g = invites[i]
                        let id = g["id"] as? String ?? ""
                        let who = g["principal_name"] as? String ?? L("Someone")
                        VStack(alignment: .leading, spacing: 10) {
                            Text(verbatim: L("%@ asked you to be their payment guardian.", who))
                            if model.restricted { RestrictedNote() }
                            HStack {
                                if !model.restricted {
                                    Button("Accept") { model.act("/v1/guardian/invitations/\(id)/accept", done: L("You now protect %@.", who)) }
                                        .buttonStyle(.borderedProminent).tint(.green)
                                }
                                Button("Decline") { model.act("/v1/guardian/invitations/\(id)/decline", done: L("Declined.")) }
                                    .buttonStyle(.bordered)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }

            Section(header: Heading("Payments waiting")) {
                if held.isEmpty { Text("Nothing is waiting for you.").foregroundStyle(.secondary) }
                ForEach(held.indices, id: \.self) { i in
                    let p = held[i]
                    let id = p["check_id"] as? String ?? ""
                    VStack(alignment: .leading, spacing: 8) {
                        PaymentInfo(p: p, from: names[p["principal_id"] as? String ?? ""])
                        if let note = p["narration"] as? String, !note.isEmpty {
                            Text(verbatim: L("Note: %@", note)).italic()   // as the bank sent it
                        }
                        if let t = p["approval_expires_at"] as? String {
                            Text(verbatim: L("Answer by %@", Wire.time(t))).font(.footnote).foregroundStyle(.secondary)
                        }
                        if let t = p["release_at"] as? String {
                            Text(verbatim: L("Goes through at %@ unless stopped", Wire.time(t))).font(.footnote).foregroundStyle(.secondary)
                        }
                        Text("Not sure? Call them on a number you know before approving.").font(.footnote).foregroundStyle(.secondary)
                        if (p["status"] as? String) == "pending_approval" {
                            if model.restricted { RestrictedNote() }
                            HStack {
                                if !model.restricted {
                                    Button("Approve") { approvePayment = id }.buttonStyle(.borderedProminent).tint(.green)
                                }
                                Button("Deny", role: .destructive) {
                                    model.act("/v1/guardian/payments/\(id)/deny", done: L("Denied. The payment will not go through."))
                                }
                                .buttonStyle(.bordered)
                            }
                        } else {
                            Button("Stop this payment", role: .destructive) {
                                model.act("/v1/guardian/payments/\(id)/cancel", done: L("Cancelled."))
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }

            if !changes.isEmpty {
                Section(header: Heading("Protection changes waiting")) {
                    ForEach(changes.indices, id: \.self) { i in
                        let c = changes[i]
                        let id = c["id"] as? String ?? ""
                        VStack(alignment: .leading, spacing: 8) {
                            Text(verbatim: L("%1$@ wants to: %2$@", names[c["principal_id"] as? String ?? ""] ?? L("Someone"),
                                             Words.change(c["kind"] as? String ?? "")))
                            Text(verbatim: L("Happens %@ unless you stop it. Scammers often ask people to do this.",
                                             Wire.time(c["effective_at"] as? String ?? "")))
                                .font(.footnote).foregroundStyle(.secondary)
                            if model.restricted { RestrictedNote() }
                            HStack {
                                Button("Stop it", role: .destructive) {
                                    model.act("/v1/guardian/changes/\(id)/veto", done: L("Stopped."))
                                }
                                .buttonStyle(.borderedProminent).tint(.red)
                                if !model.restricted {
                                    Button("Approve now") { model.act("/v1/guardian/changes/\(id)/approve", done: L("Approved.")) }
                                        .buttonStyle(.bordered)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }

            if !recoveries.isEmpty {
                Section(header: Heading("Account recovery requests")) {
                    ForEach(recoveries.indices, id: \.self) { i in
                        let r = recoveries[i]
                        let id = r["recovery_id"] as? String ?? ""
                        let pending = r["status"] as? String == "pending"
                        let opens = r["vouching_opens_at"] as? String ?? ""
                        VStack(alignment: .leading, spacing: 8) {
                            Text(verbatim: L("%1$@ wants to move their account to %2$@.", r["person_name"] as? String ?? "",
                                             r["new_number"] as? String ?? ""))
                            Text("Only approve if you have spoken to them yourself, on a call YOU placed or in person. If in doubt, deny.")
                                .font(.footnote).foregroundStyle(.secondary)
                            if pending && Wire.isFuture(opens) {
                                Text(verbatim: L("You can approve from %@.", Wire.time(opens))).font(.footnote).foregroundStyle(.secondary)
                            }
                            if pending && model.restricted { RestrictedNote() }
                            HStack {
                                if pending && !model.restricted {
                                    Button("I spoke to them: approve") {
                                        model.act("/v1/guardian/recoveries/\(id)/approve", done: L("Thank you. Your vouch is recorded."))
                                    }
                                    .buttonStyle(.borderedProminent).tint(.green)
                                }
                                Button("Deny", role: .destructive) {
                                    model.act("/v1/guardian/recoveries/\(id)/deny", done: L("Stopped."))
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
            }

            Section(header: Heading("People I protect")) {
                if active.isEmpty {
                    Text("You don't protect anyone yet. Someone has to invite you from their app.").foregroundStyle(.secondary)
                }
                ForEach(active.indices, id: \.self) { i in
                    let w = active[i]
                    HStack {
                        Text(verbatim: w["principal_name"] as? String ?? "").bold()
                        Spacer()
                        Button("Pause their payments", role: .destructive) { pauseWard = w }.buttonStyle(.bordered)
                    }
                }
            }
        }
        .textCase(nil)
        .headerProminence(.increased)   // headings in normal case and a little larger, like the web app
        .navigationTitle("People I protect")
        .refreshable { await model.refresh() }
        .confirmationDialog("Approve this payment?", isPresented: Binding(get: { approvePayment != nil }, set: { if !$0 { approvePayment = nil } }),
                            titleVisibility: .visible) {
            Button("Approve") {
                if let id = approvePayment { model.act("/v1/guardian/payments/\(id)/approve", done: L("Approved.")) }
            }
        }
        .confirmationDialog(Text(verbatim: L("Pause all payments for %@?", pauseWard?["principal_name"] as? String ?? "")),
                            isPresented: Binding(get: { pauseWard != nil }, set: { if !$0 { pauseWard = nil } }),
                            titleVisibility: .visible) {
            Button("Pause their payments", role: .destructive) {
                if let w = pauseWard, let id = w["principal_id"] as? String {
                    let who = w["principal_name"] as? String ?? ""
                    model.act("/v1/guardian/wards/\(id)/kill-switch/on", done: L("Payments paused for %@.", who))
                }
            }
        }
    }
}

// ------------------------------------------------------------------ Alerts
struct AlertsView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            RestrictedSection()
            if model.alerts.contains(where: { !($0["read"] as? Bool ?? false) }) {
                Section {
                    Button("Mark all read") { model.act("/v1/me/notifications/read", [:], done: L("All marked as read.")) }
                }
            }
            Section {
                if model.alerts.isEmpty { Text("No alerts yet.").foregroundStyle(.secondary) }
                ForEach(model.alerts.indices, id: \.self) { i in
                    let n = model.alerts[i]
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(verbatim: n["title"] as? String ?? "").bold()
                            Spacer()
                            if !(n["read"] as? Bool ?? false) { Pill(text: L("New"), color: .orange) }
                        }
                        Text(verbatim: n["body"] as? String ?? "")
                        Text(verbatim: Wire.time(n["created_at"] as? String ?? "")).font(.footnote).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .textCase(nil)
        .headerProminence(.increased)   // headings in normal case and a little larger, like the web app
        .navigationTitle("Alerts")
        .refreshable { await model.refresh() }
    }
}

// ------------------------------------------------------------------ Devices
struct DevicesView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        List {
            RestrictedSection()
            Section {
                Text("Each phone or browser you sign in on has its own key. A new one can't approve payments for 24 hours.")
                    .foregroundStyle(.secondary)
                if model.devices.isEmpty { Text("No device keys yet.").foregroundStyle(.secondary) }
                ForEach(model.devices.indices, id: \.self) { i in
                    let d = model.devices[i]
                    let kid = d["key_id"] as? String ?? ""
                    let mine = kid == model.myKeyId
                    let st = d["status"] as? String ?? ""
                    let word = Words.status(st)
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: mine ? L("This device") : L("Device %@", String(kid.prefix(8)))).bold()
                            Text(verbatim: L("Added %@", Wire.time(d["created_at"] as? String ?? ""))).font(.footnote).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Pill(text: word.0, color: word.1)
                        if st != "revoked" && !mine && !model.restricted {
                            Button("Remove") { model.removeDevice(kid) }.buttonStyle(.bordered)
                        }
                    }
                }
            }
            Section(header: Heading("Sign out")) {
                Button("Sign out here") { model.signOut(everywhere: false) }
                Button("Sign out everywhere", role: .destructive) { model.signOut(everywhere: true) }
            }
        }
        .textCase(nil)
        .headerProminence(.increased)   // headings in normal case and a little larger, like the web app
        .navigationTitle("Devices")
        .refreshable { await model.refresh() }
    }
}
