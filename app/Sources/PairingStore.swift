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

    /// Reads a user-picked file (handles security-scoped URLs from Files).
    static func read(_ source: URL) throws -> Data {
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        return try Data(contentsOf: source)
    }

    static func save(_ data: Data, to destination: URL) throws {
        try data.write(to: destination, options: [.atomic, .completeFileProtection])
    }
}
