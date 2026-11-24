import Foundation
import IPABridge

/// Thin Swift wrapper over the C ABI in bridge/include/ipabridge.h.
/// Every call blocks, so callers must run it off the main thread.
enum PairingKind: Equatable {
    case lockdown, rppairing, invalid

    var mode: Int32 { self == .rppairing ? Int32(IPAB_MODE_RPPAIRING) : Int32(IPAB_MODE_LOCKDOWN) }

    var label: String {
        switch self {
        case .lockdown: return "Lockdown (iOS 17.4 – 26.3)"
        case .rppairing: return "RPPairing (iOS 26.4+)"
        case .invalid: return "Not recognised"
        }
    }
}

struct BridgeResult {
    let success: Bool
    let log: String
}

enum Bridge {
    static let hostname = "ipa-poc"

    static var version: String { String(cString: ipab_version()) }

    static func inspect(_ pairing: Data) -> (PairingKind, String) {
        var out: UnsafeMutablePointer<CChar>?
        let code = pairing.withUnsafeBytes { raw in
            ipab_inspect_pairing(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &out)
        }
        let message = take(out)
        switch code {
        case Int32(IPAB_PAIRING_LOCKDOWN): return (.lockdown, message)
        case Int32(IPAB_PAIRING_RPPAIRING): return (.rppairing, message)
        default: return (.invalid, message)
        }
    }

    static func testConnection(kind: PairingKind, pairing: Data, ip: String, port: UInt16) -> BridgeResult {
        var out: UnsafeMutablePointer<CChar>?
        let code = pairing.withUnsafeBytes { raw in
            ipab_test_connection(kind.mode, raw.bindMemory(to: UInt8.self).baseAddress, raw.count,
                                 ip, port, hostname, &out)
        }
        return BridgeResult(success: code == 0, log: take(out))
    }

    static func install(kind: PairingKind, pairing: Data, ip: String, port: UInt16,
                        ipaURL: URL, onProgress: @escaping (UInt64) -> Void) -> BridgeResult {
        let box = ProgressBox(onProgress)
        let context = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<ProgressBox>.fromOpaque(context).release() }

        var out: UnsafeMutablePointer<CChar>?
        let code = pairing.withUnsafeBytes { raw in
            ipab_install_ipa(kind.mode, raw.bindMemory(to: UInt8.self).baseAddress, raw.count,
                             ip, port, hostname, ipaURL.path,
                             { percent, ctx in
                                 guard let ctx else { return }
                                 Unmanaged<ProgressBox>.fromOpaque(ctx).takeUnretainedValue().handler(percent)
                             },
                             context, &out)
        }
        return BridgeResult(success: code == 0, log: take(out))
    }

    // MARK: - Free Apple ID signing

    static func registerStorage(store: ipab_store_cb, retrieve: ipab_retrieve_cb) {
        ipab_set_storage_callbacks(store, retrieve)
    }

    static var isSignedIn: Bool { ipab_is_signed_in() == 1 }

    static func signOut() { ipab_sign_out() }

    /// Blocking. `askTwoFactor` is called on a background thread and must block until the user
    /// answers; return nil to cancel.
    static func login(email: String, password: String,
                      askTwoFactor: @escaping (String) -> String?) -> BridgeResult {
        let box = TwoFactorBox(askTwoFactor)
        let context = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<TwoFactorBox>.fromOpaque(context).release() }
        var out: UnsafeMutablePointer<CChar>?
        let code = ipab_apple_login(email, password, { prompt, ctx in
            guard let ctx else { return nil }
            let text = prompt.map { String(cString: $0) } ?? ""
            let box = Unmanaged<TwoFactorBox>.fromOpaque(ctx).takeUnretainedValue()
            guard let answer = box.handler(text) else { return nil }
            return strdup(answer)
        }, context, &out)
        return BridgeResult(success: code == 0, log: take(out))
    }

    static func signAndInstall(kind: PairingKind, pairing: Data, ip: String, port: UInt16,
                               ipaURL: URL, allowRevoke: Bool,
                               onProgress: @escaping (UInt64) -> Void) -> BridgeResult {
        let box = ProgressBox(onProgress)
        let context = Unmanaged.passRetained(box).toOpaque()
        defer { Unmanaged<ProgressBox>.fromOpaque(context).release() }
        var out: UnsafeMutablePointer<CChar>?
        let code = pairing.withUnsafeBytes { raw in
            ipab_sign_and_install(kind.mode, raw.bindMemory(to: UInt8.self).baseAddress, raw.count,
                                  ip, port, hostname, ipaURL.path, allowRevoke ? 1 : 0,
                                  { percent, ctx in
                                      guard let ctx else { return }
                                      Unmanaged<ProgressBox>.fromOpaque(ctx).takeUnretainedValue().handler(percent)
                                  },
                                  context, &out)
        }
        return BridgeResult(success: code == 0, log: take(out))
    }

    private static func take(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr else { return "" }
        defer { ipab_free_string(ptr) }
        return String(cString: ptr)
    }
}

private final class ProgressBox {
    let handler: (UInt64) -> Void
    init(_ handler: @escaping (UInt64) -> Void) { self.handler = handler }
}

private final class TwoFactorBox {
    let handler: (String) -> String?
    init(_ handler: @escaping (String) -> String?) { self.handler = handler }
}
