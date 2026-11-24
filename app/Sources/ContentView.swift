import SwiftUI
import UniformTypeIdentifiers

/// Phase 0 PoC screen: import pairing file, test connection (M3), install a pre-signed IPA (M4).
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
    @State private var log = ""
    @State private var importing: ImportTarget?
    @State private var portFinder: RemotePairingPortFinder?

    enum ImportTarget: Identifiable { case pairing, ipa; var id: Self { self } }

    var body: some View {
        NavigationStack {
            Form {
                Section("1 · Pairing file") {
                    Button("Import pairing file…") { importing = .pairing }
                    Text(pairingInfo).font(.footnote).foregroundStyle(.secondary)
                    LabeledContent("Mode", value: pairingKind.label)
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
                    Button("Test connection") { runTestConnection() }
                        .disabled(busy || pairing == nil || pairingKind == .invalid)
                }

                Section("4 · Milestone M4") {
                    Button("Choose pre-signed IPA…") { importing = .ipa }
                    if let ipaName { Text(ipaName).font(.footnote).foregroundStyle(.secondary) }
                    Button("Install IPA") { runInstall() }
                        .disabled(busy || pairing == nil || pairingKind == .invalid || ipaName == nil)
                    if let progress { ProgressView(value: progress, total: 100) }
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
                        Button("Clear") { log = "" }
                    }
                }
            }
            .navigationTitle("IPA PoC")
            .fileImporter(isPresented: Binding(get: { importing != nil }, set: { if !$0 { importing = nil } }),
                          allowedContentTypes: allowedTypes()) { handleImport($0) }
            .onAppear { refreshPairingInfo() }
        }
    }

    // MARK: - Actions

    private func allowedTypes() -> [UTType] {
        switch importing {
        case .ipa: return [UTType(filenameExtension: "ipa") ?? .data, .data]
        default: return [.propertyList, .xml, .data, .item]
        }
    }

    private func handleImport(_ result: Result<URL, Error>) {
        let target = importing
        importing = nil
        switch result {
        case .failure(let error):
            append("Import failed: \(error.localizedDescription)")
        case .success(let url):
            do {
                if target == .ipa {
                    try PairingStore.importFile(from: url, to: PairingStore.ipaURL)
                    ipaName = url.lastPathComponent
                    append("IPA imported: \(url.lastPathComponent)")
                } else {
                    try PairingStore.importFile(from: url, to: PairingStore.pairingURL)
                    pairing = PairingStore.loadPairing()
                    refreshPairingInfo()
                    append("Pairing file imported: \(url.lastPathComponent) → \(pairingInfo)")
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
        pairingInfo = info
    }

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
        let kind = pairingKind, ip = targetIP, port = UInt16(portText) ?? RemotePairingPortFinder.fallbackPort
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

    private func runInstall() {
        guard let pairing else { return }
        let kind = pairingKind, ip = targetIP, port = UInt16(portText) ?? RemotePairingPortFinder.fallbackPort
        busy = true
        progress = 0
        append("── Install IPA (\(kind.label)) ──")
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Bridge.install(kind: kind, pairing: pairing, ip: ip, port: port,
                                        ipaURL: PairingStore.ipaURL) { pct in
                DispatchQueue.main.async { progress = Double(pct) }
            }
            DispatchQueue.main.async {
                append(result.log)
                progress = nil
                busy = false
            }
        }
    }

    // MARK: - Log

    private func append(_ text: String) {
        let stamp = Date().formatted(date: .omitted, time: .standard)
        log += (log.isEmpty ? "" : "\n") + "[\(stamp)] " + text
    }

    private func fullLogForSharing() -> String {
        let device = UIDevice.current
        return """
        IPA PoC log — \(Bridge.version)
        Device: \(device.model), \(device.systemName) \(device.systemVersion)
        Pairing: \(pairingKind.label)

        \(log)
        """
    }
}
