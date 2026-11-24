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

    enum ImportTarget: Identifiable { case pairing, ipa; var id: Self { self } }

    private enum Keys {
        static let log = "poc.log"
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
