import Foundation
import Network

/// Finds the port of this iPhone's own `_remotepairing._tcp` Bonjour service (needed for the
/// RPPairing path on iOS 26.4+). The port is dynamic; 49152 is only a fallback, as in StikDebug.
final class RemotePairingPortFinder {
    static let fallbackPort: UInt16 = 49152

    private let queue = DispatchQueue(label: "poc.portfinder")
    private var browser: NWBrowser?
    private var connection: NWConnection?
    private var done = false
    private var completion: ((UInt16?, String) -> Void)?

    /// Calls `completion` once, on an arbitrary queue, with the port (or nil) and a description.
    func find(timeout: TimeInterval = 6, completion: @escaping (UInt16?, String) -> Void) {
        self.completion = completion
        let params = NWParameters.tcp
        params.includePeerToPeer = true
        let browser = NWBrowser(for: .bonjour(type: "_remotepairing._tcp", domain: "local."), using: params)
        self.browser = browser

        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self, !self.done, self.connection == nil else { return }
            // Prefer a result seen on the loopback interface: that one is this device itself.
            let loopback = results.first { r in r.interfaces.contains { $0.name.hasPrefix("lo") } }
            guard let result = loopback ?? results.first else { return }
            let conn = NWConnection(to: result.endpoint, using: params)
            self.connection = conn
            conn.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready, .waiting:
                    if case let .hostPort(_, port)? = conn.currentPath?.remoteEndpoint {
                        self.finish(port.rawValue, "Bonjour: \(result.endpoint) -> port \(port.rawValue)")
                    }
                case .failed(let error):
                    self.finish(nil, "Bonjour connection failed: \(error)")
                default:
                    break
                }
            }
            conn.start(queue: self.queue)
        }
        browser.stateUpdateHandler = { [weak self] state in
            if case .failed(let error) = state { self?.finish(nil, "Bonjour browse failed: \(error)") }
        }
        browser.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.finish(nil, "No _remotepairing._tcp service found within \(Int(timeout))s")
        }
    }

    private func finish(_ port: UInt16?, _ description: String) {
        queue.async {
            guard !self.done else { return }
            self.done = true
            self.connection?.cancel()
            self.browser?.cancel()
            self.completion?(port, description)
            self.completion = nil
        }
    }
}
