import Foundation
import Security

/// Storage backend for the Rust signing code (development certificate private key, anisette
/// state, team selection). Items live in the iOS Keychain, readable only while the device is
/// unlocked, never synced to iCloud and never included in backups that leave this device.
/// The Apple ID password is NOT stored here or anywhere else.
enum KeychainStore {
    private static let service = "dev.ipapoc.signing"

    static func set(_ key: String, _ value: String) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        var status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add.merge(update) { $1 }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        return status == errSecSuccess
    }

    static func get(_ key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Removes every item this app stored (certificate key, anisette state).
    static func deleteAll() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    /// Hands the Keychain to the Rust bridge. Call once at launch.
    static func registerWithBridge() {
        Bridge.registerStorage(
            store: { key, value in
                guard let key, let value else { return 1 }
                return KeychainStore.set(String(cString: key), String(cString: value)) ? 0 : 1
            },
            retrieve: { key in
                guard let key, let value = KeychainStore.get(String(cString: key)) else { return nil }
                return strdup(value)
            })
    }
}
