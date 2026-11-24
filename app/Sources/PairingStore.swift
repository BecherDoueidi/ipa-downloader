import Foundation

/// Keeps the pairing file and the test IPA inside the app container.
/// The pairing file is a trusted-host credential: complete file protection, excluded from backup,
/// never exported.
enum PairingStore {
    private static var directory: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("PoC", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var mutable = dir
        try? mutable.setResourceValues(values)
        return dir
    }

    static var pairingURL: URL { directory.appendingPathComponent("pairing.plist") }
    static var ipaURL: URL { directory.appendingPathComponent("test.ipa") }

    static func loadPairing() -> Data? { try? Data(contentsOf: pairingURL) }

    /// Copies a user-picked file into the container (handles security-scoped URLs from Files).
    static func importFile(from source: URL, to destination: URL) throws {
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        let data = try Data(contentsOf: source)
        try data.write(to: destination, options: [.atomic, .completeFileProtection])
    }
}
