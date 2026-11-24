import SwiftUI
import UniformTypeIdentifiers

/// Phase 0 PoC screen: import pairing file, test connection (M3), install a package (M4).
/// Deliberately bare: one screen, a log, and a share button for the log.
struct ContentView: View {
    @State private var pairing: Data? = PairingStore.loadPairing()
    @State private var pairingKind: PairingKind = .invalid
    @State private var pairingInfo = "No pairing file imported"
    @State private var ipaName: String? = FileManager.default.fileExists(atPath: PairingStore.ipaURL.path) ? "test.ipa (saved)" : nil

    @State private var targetIP = "10.7.0.1"
    @State private var portText = String(RemotePairingPortFinder.fallbackPort)

    @State private var busy = false
    @State private var progress: Double?
    @State private var log = UserDefaults.standard.string(forKey: Keys.log) ?? ""
    @State private var showImporter = false
    // Kept separately: the picker clears its isPresented binding before calling the completion.
    @State private var importTarget: ImportTarget = .pairing
    @State private var portFinder: RemotePairingPortFinder?

    // Free Apple ID signing
    @State private var appleID = UserDefaults.standard.string(forKey: Keys.appleID) ?? ""
    @State private var password = ""
    @State private var signedIn = Bridge.isSignedIn
    @State private var allowRevoke = false
    @State private var confirmSign = false
    @State private var twoFactor: TwoFactorRequest?
    @State private var twoFactorCode = ""

    enum ImportTarget: Identifiable { case pairing, ipa; var id: Self { self } }

    private enum Keys {
        static let log = "poc.log"
        static let appleID = "poc.appleID"
        static let selfTestPending = "poc.selftest.pending"
        static let selfTestOldPath = "poc.selftest.oldBundlePath"
        static let selfTestProgress = "poc.selftest.lastProgress"
        static let selfTestOldStamp = "poc.selftest.oldExecutableStamp"
    }

    /// Modification time of this app's executable (changes when installd writes a new copy).
    static func executableStamp() -> Double {
        guard let path = Bundle.main.executablePath,
              let date = (try? FileManager.default.attributesOfItem(atPath: path))?[.modificationDate] as? Date
        else { return 0 }
        return date.timeIntervalSince1970
    }

    private var ready: Bool { !busy && pairing != nil && pairingKind != .invalid }

    var body: some View {
        NavigationStack {
            Form {
                Section("1 · Pairing file (NOT the IPA)") {
                    Button("Import pairing file…") { importTarget = .pairing; showImporter = true }
                    Text(pairingInfo).font(.footnote).foregroundStyle(.secondary)
                    LabeledContent("Mode", value: pairing == nil ? "—" : pairingKind.label)
                }

                Section("2 · Target (LocalDevVPN must be connected)") {
                    TextField("Device IP", text: $targetIP)
                        .keyboardType(.numbersAndPunctuation)
                        .autocorrectionDisabled()
                    if pairingKind == .rppairing {
                        HStack {
                            TextField("Remote pairing port", text: $portText).keyboardType(.numberPad)
                            Button("Discover") { discoverPort() }.disabled(busy)
                        }
                    }
                }

                Section("3 · Milestone M3") {
                    Button("Test connection") { runTestConnection() }.disabled(!ready)
                }

                Section {
                    Button("Self-reinstall test") { runSelfReinstall() }.disabled(!ready)
                    Button("Choose IPA…") { importTarget = .ipa; showImporter = true }
                    if let ipaName { Text(ipaName).font(.footnote).foregroundStyle(.secondary) }
                    Button("Install chosen IPA") { runInstall(url: PairingStore.ipaURL, label: ipaName ?? "IPA") }
                        .disabled(!ready || ipaName == nil)
                    if let progress { ProgressView(value: progress, total: 100) }
                } header: {
                    Text("4 · Milestone M4")
                } footer: {
                    Text("Self-reinstall installs a copy of this app (already signed for this iPhone). iOS will close the app near the end — reopen it to see the result. A chosen IPA must already be signed for this iPhone; an unsigned IPA should fail (that is the expected negative test).")
                }

                Section {
                    if signedIn {
                        LabeledContent("Signed in", value: appleID)
                        Button("Sign out", role: .destructive) { signOut() }.disabled(busy)
                    } else {
                        TextField("Apple ID email", text: $appleID)
                            .textContentType(.username)
                            .keyboardType(.emailAddress)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        SecureField("Password", text: $password).textContentType(.password)
                        Button("Sign in") { runLogin() }
                            .disabled(busy || appleID.isEmpty || password.isEmpty)
                    }
                    Toggle("Allow revoking old certificates", isOn: $allowRevoke)
                    Button("Sign & install chosen IPA") { confirmSign = true }
                        .disabled(!ready || !signedIn || ipaName == nil)
                } header: {
                    Text("5 · Free Apple ID signing")
                } footer: {
                    Text("""
                    Your password goes only to Apple (gsa.apple.com) and is not saved. A helper server (ani.iloader.app) supplies device-identity headers Apple requires; it never sees your password. The signing certificate's private key is kept in this iPhone's Keychain.
                    Free accounts: apps expire after 7 days, max 3 sideloaded apps, 10 new App IDs per week. The bundle ID becomes <original>.<TEAMID>, so it installs as a separate app.
                    Revoking old certificates can stop apps signed by SideStore/iloader/other tools from opening.
                    """)
                }

                Section {
                    if busy { ProgressView() }
                    Text(log.isEmpty ? "Log is empty" : log)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                } header: {
                    HStack {
                        Text("Log")
                        Spacer()
                        ShareLink(item: fullLogForSharing()) { Image(systemName: "square.and.arrow.up") }
                        Button("Clear") { setLog("") }
                    }
                }
            }
            .navigationTitle("IPA PoC")
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: allowedTypes()) { handleImport($0) }
            .confirmationDialog("Sign and install \(ipaName ?? "this IPA")?",
                                isPresented: $confirmSign, titleVisibility: .visible) {
                Button("Sign & install") { runSignAndInstall() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("It will be signed with \(appleID), installed on this iPhone and expire in 7 days. This app does not check what the IPA contains — only install apps you trust.")
            }
            .alert("Apple ID verification", isPresented: Binding(
                get: { twoFactor != nil },
                set: { if !$0 { answerTwoFactor(nil) } })) {
                TextField("Code / d / r / p<id>", text: $twoFactorCode)
                    .keyboardType(.asciiCapable)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Submit") { answerTwoFactor(twoFactorCode) }
                Button("Cancel", role: .cancel) { answerTwoFactor(nil) }
            } message: {
                Text(twoFactor?.prompt ?? "")
            }
            .onAppear {
                refreshPairingInfo()
                checkSelfReinstallResult()
            }
        }
    }

    // MARK: - Import

    private func allowedTypes() -> [UTType] {
        switch importTarget {
        case .ipa: return [UTType(filenameExtension: "ipa") ?? .data, .data]
        default: return [.propertyList, .xml, .data, .item]
        }
    }

    private func handleImport(_ result: Result<URL, Error>) {
        let target = importTarget
        switch result {
        case .failure(let error):
            append("Import failed: \(error.localizedDescription)")
        case .success(let url):
            do {
                let data = try PairingStore.read(url)
                if target == .ipa {
                    try PairingStore.save(data, to: PairingStore.ipaURL)
                    ipaName = url.lastPathComponent
                    append("IPA chosen: \(url.lastPathComponent) (\(data.count) bytes)")
                } else {
                    // Validate first so a wrong file never replaces a working pairing file.
                    let (kind, info) = Bridge.inspect(data)
                    guard kind != .invalid else {
                        append("Rejected \(url.lastPathComponent): not a pairing file. Your saved pairing file was kept.\n\(info)")
                        return
                    }
                    try PairingStore.save(data, to: PairingStore.pairingURL)
                    pairing = data
                    pairingKind = kind
                    pairingInfo = info
                    append("Pairing file imported: \(url.lastPathComponent) → \(info)")
                }
            } catch {
                append("Import failed: \(error.localizedDescription)")
            }
        }
    }

    private func refreshPairingInfo() {
        guard let pairing else { return }
        let (kind, info) = Bridge.inspect(pairing)
        pairingKind = kind
        pairingInfo = kind == .invalid ? "Saved pairing file is not valid — import it again.\n\(info)" : info
    }

    // MARK: - Actions

    private var currentPort: UInt16 { UInt16(portText) ?? RemotePairingPortFinder.fallbackPort }

    private func discoverPort() {
        busy = true
        append("Discovering _remotepairing._tcp port…")
        let finder = RemotePairingPortFinder()
        portFinder = finder
        finder.find { port, description in
            DispatchQueue.main.async {
                append(description)
                if let port { portText = String(port) } else { append("Keeping port \(portText)") }
                busy = false
                portFinder = nil
            }
        }
    }

    private func runTestConnection() {
        guard let pairing else { return }
        let kind = pairingKind, ip = targetIP, port = currentPort
        busy = true
        append("── Test connection (\(kind.label), \(ip)\(kind == .rppairing ? ":\(port)" : "")) ──")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Bridge.testConnection(kind: kind, pairing: pairing, ip: ip, port: port)
            DispatchQueue.main.async {
                append(result.log)
                busy = false
            }
        }
    }

    private func runSelfReinstall() {
        let defaults = UserDefaults.standard
        defaults.set(true, forKey: Keys.selfTestPending)
        defaults.set(Bundle.main.bundlePath, forKey: Keys.selfTestOldPath)
        defaults.set(Self.executableStamp(), forKey: Keys.selfTestOldStamp)
        defaults.set(0, forKey: Keys.selfTestProgress)
        append("Self-reinstall: current bundle at \(Bundle.main.bundlePath)")
        runInstall(url: Bundle.main.bundleURL, label: "self (\(Bundle.main.bundleURL.lastPathComponent))") { pct in
            UserDefaults.standard.set(Int(pct), forKey: Keys.selfTestProgress)
        }
    }

    private func runInstall(url: URL, label: String, extraProgress: ((UInt64) -> Void)? = nil) {
        guard let pairing else { return }
        let kind = pairingKind, ip = targetIP, port = currentPort
        busy = true
        progress = 0
        append("── Install \(label) (\(kind.label)) ──")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Bridge.install(kind: kind, pairing: pairing, ip: ip, port: port, ipaURL: url) { pct in
                extraProgress?(pct)
                DispatchQueue.main.async { progress = Double(pct) }
            }
            DispatchQueue.main.async {
                append(result.log)
                progress = nil
                busy = false
            }
        }
    }

    // MARK: - Apple ID signing

    private func runLogin() {
        let email = appleID.trimmingCharacters(in: .whitespaces)
        let pw = password
        password = ""
        UserDefaults.standard.set(email, forKey: Keys.appleID)
        busy = true
        append("── Apple ID sign-in (\(email)) ──")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Bridge.login(email: email, password: pw) { prompt in
                // Background thread: show the prompt on the main thread and wait for the answer.
                let request = TwoFactorRequest(prompt: prompt)
                DispatchQueue.main.async {
                    twoFactorCode = ""
                    twoFactor = request
                }
                request.semaphore.wait()
                return request.answer
            }
            DispatchQueue.main.async {
                append(result.log)
                signedIn = Bridge.isSignedIn
                busy = false
            }
        }
    }

    private func answerTwoFactor(_ answer: String?) {
        guard let request = twoFactor else { return }
        twoFactor = nil
        let trimmed = answer?.trimmingCharacters(in: .whitespaces)
        request.answer = (trimmed?.isEmpty ?? true) ? nil : trimmed
        request.semaphore.signal()
    }

    private func signOut() {
        Bridge.signOut()
        KeychainStore.deleteAll()
        signedIn = false
        append("Signed out. Certificate key and anisette state removed from the Keychain.")
    }

    private func runSignAndInstall() {
        guard let pairing else { return }
        let kind = pairingKind, ip = targetIP, port = currentPort, revoke = allowRevoke
        let label = ipaName ?? "IPA"
        busy = true
        progress = 0
        append("── Sign & install \(label) (\(kind.label), revoke \(revoke ? "allowed" : "off")) ──")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Bridge.signAndInstall(kind: kind, pairing: pairing, ip: ip, port: port,
                                               ipaURL: PairingStore.ipaURL, allowRevoke: revoke) { pct in
                DispatchQueue.main.async { progress = Double(pct) }
            }
            DispatchQueue.main.async {
                append(result.log)
                progress = nil
                busy = false
            }
        }
    }

    /// After a self-reinstall iOS usually terminates the app. On the next launch, compare the
    /// bundle path: installd puts a reinstalled app in a new container directory.
    private func checkSelfReinstallResult() {
        let defaults = UserDefaults.standard
        guard defaults.bool(forKey: Keys.selfTestPending) else { return }
        let oldPath = defaults.string(forKey: Keys.selfTestOldPath) ?? "?"
        let newPath = Bundle.main.bundlePath
        let oldStamp = defaults.double(forKey: Keys.selfTestOldStamp)
        let newStamp = Self.executableStamp()
        // Same path and same executable timestamp = same install (e.g. still this launch).
        guard oldPath != newPath || oldStamp != newStamp else { return }
        defaults.set(false, forKey: Keys.selfTestPending)
        let lastPct = defaults.integer(forKey: Keys.selfTestProgress)
        append("""
        ── Self-reinstall result ──
        Bundle path: \(oldPath)
                  →  \(newPath)
        Executable timestamp changed: \(oldStamp != newStamp ? "yes" : "no")
        Last progress seen before iOS closed the app: \(lastPct)%
        App data kept across reinstall: YES (this log and the test flag survived)
        RESULT: SUCCESS — installd replaced this app from an install started inside the app
        """)
    }

    // MARK: - Log

    private func append(_ text: String) {
        let stamp = Date().formatted(date: .omitted, time: .standard)
        setLog(log + (log.isEmpty ? "" : "\n") + "[\(stamp)] " + text)
    }

    /// Persisted so the log survives the app being closed by a self-reinstall.
    private func setLog(_ text: String) {
        log = text
        UserDefaults.standard.set(text, forKey: Keys.log)
    }

    private func fullLogForSharing() -> String {
        let device = UIDevice.current
        return """
        IPA PoC log — \(Bridge.version)
        Device: \(device.model), \(device.systemName) \(device.systemVersion)
        Pairing: \(pairing == nil ? "none" : pairingKind.label)

        \(log)
        """
    }
}

/// One pending 2FA question from the signing bridge; the bridge thread waits on `semaphore`.
final class TwoFactorRequest {
    let prompt: String
    let semaphore = DispatchSemaphore(value: 0)
    var answer: String?
    init(prompt: String) { self.prompt = prompt }
}
