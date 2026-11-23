import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        NavigationStack {
            Group {
                switch model.screen {
                case .mobile: MobileView()
                case .code: CodeView()
                case .home: HomeView()
                }
            }
            .disabled(model.busy)
            .overlay(alignment: .bottom) {
                if let m = model.message {
                    Text(m).padding().frame(maxWidth: .infinity).background(.thinMaterial)
                        .onTapGesture { model.message = nil }
                }
            }
        }
    }
}

struct MobileView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Form {
            Section {
                Text("Payments from your account can need a family member's OK. Sign in with your mobile number.")
                TextField("Mobile number", text: $model.mobile).keyboardType(.phonePad).textContentType(.telephoneNumber)
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
                TextField("6-digit code", text: $model.code).keyboardType(.numberPad).textContentType(.oneTimeCode)
                TextField("Your name (first time only)", text: $model.name)
                Button("Sign in") { model.signIn() }.disabled(model.code.count < 4)
                Button("Back") { model.screen = .mobile }
            }
        }
        .navigationTitle("Enter the code")
    }
}

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmPause = false
    @State private var confirmLost = false

    var body: some View {
        List {
            if !model.invitations.isEmpty {
                Section("Guardian requests") {
                    ForEach(model.invitations.indices, id: \.self) { i in
                        let g = model.invitations[i]
                        let id = g["id"] as? String ?? ""
                        VStack(alignment: .leading, spacing: 8) {
                            Text("\(g["principal_name"] as? String ?? "Someone") asked you to be their payment guardian.")
                            HStack {
                                Button("Accept") { model.act("/v1/guardian/invitations/\(id)/accept", done: "You now protect them.") }
                                    .buttonStyle(.borderedProminent)
                                Button("Decline") { model.act("/v1/guardian/invitations/\(id)/decline", done: "Declined.") }
                                    .buttonStyle(.bordered)
                            }
                        }
                    }
                }
            }

            Section("Payments waiting") {
                if model.held.isEmpty { Text("Nothing is waiting for you.").foregroundStyle(.secondary) }
                ForEach(model.held.indices, id: \.self) { i in
                    PaymentRow(p: model.held[i], from: model.wardNames[model.held[i]["principal_id"] as? String ?? ""])
                }
            }

            Section("My protection") {
                if model.paused {
                    Text("All payments from your account are paused.").foregroundStyle(.orange)
                    Button("Resume payments") { model.act("/v1/me/kill-switch/off", done: "Resume requested.") }
                } else {
                    Button("Pause all my payments", role: .destructive) { confirmPause = true }
                }
            }

            Section("Alerts") {
                if model.alerts.isEmpty { Text("No alerts.").foregroundStyle(.secondary) }
                ForEach(model.alerts.prefix(10).indices, id: \.self) { i in
                    VStack(alignment: .leading) {
                        Text(model.alerts[i]["title"] as? String ?? "").bold()
                        Text(model.alerts[i]["body"] as? String ?? "").font(.subheadline)
                    }
                }
            }

            Section("Security") {
                Button("I lost my phone", role: .destructive) { confirmLost = true }
                Button("Sign out") { model.signOut() }
            }
        }
        .navigationTitle("Hello, \(model.displayName)")
        .refreshable { await model.refresh() }
        .onAppear { model.reload() }
        .confirmationDialog("Pause every payment from your account until you resume?", isPresented: $confirmPause,
                            titleVisibility: .visible) {
            Button("Pause payments", role: .destructive) { model.act("/v1/me/kill-switch/on", done: "Payments paused.") }
        }
        .confirmationDialog("Sign out every device and block approvals from this number for a while?",
                            isPresented: $confirmLost, titleVisibility: .visible) {
            Button("Yes, I lost my phone", role: .destructive) { model.lostPhone() }
        }
    }
}

struct PaymentRow: View {
    @EnvironmentObject var model: AppModel
    let p: [String: Any]
    let from: String?
    @State private var confirmApprove = false

    var body: some View {
        let id = p["check_id"] as? String ?? ""
        VStack(alignment: .leading, spacing: 8) {
            Text(Wire.rupees(paise: p["amount"] as? Int ?? 0)).font(.title3).bold()
            Text("To \(p["payee"] as? String ?? "")\(from.map { String(format: NSLocalizedString(" · from %@", comment: ""), $0) } ?? "")")
            if (p["status"] as? String) == "pending_approval" {
                HStack {
                    Button("Approve") { confirmApprove = true }.buttonStyle(.borderedProminent)
                    Button("Deny", role: .destructive) {
                        model.act("/v1/guardian/payments/\(id)/deny", done: "Denied. The payment will not go through.")
                    }.buttonStyle(.bordered)
                }
            } else {
                Button("Stop this payment", role: .destructive) {
                    model.act("/v1/guardian/payments/\(id)/cancel", done: "Cancelled.")
                }.buttonStyle(.bordered)
            }
        }
        .confirmationDialog("Approve this payment?", isPresented: $confirmApprove, titleVisibility: .visible) {
            Button("Approve") { model.act("/v1/guardian/payments/\(id)/approve", done: "Approved.") }
        }
    }
}
