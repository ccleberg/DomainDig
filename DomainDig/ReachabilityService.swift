import Foundation
import Network

struct ReachabilityService {
    static func check(domain: String, port: UInt16) async -> PortReachability {
        await withCheckedContinuation { continuation in
            let host = NWEndpoint.Host(domain)
            let nwPort = NWEndpoint.Port(rawValue: port)!
            let connection = NWConnection(host: host, port: nwPort, using: .tcp)
            let context = ConnectionContext(port: port, connection: connection, continuation: continuation)

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    context.finish(reachable: true)
                case .failed, .cancelled:
                    context.finish(reachable: false)
                default:
                    break
                }
            }

            let queue = DispatchQueue(label: "reachability.\(port)")
            connection.start(queue: queue)

            queue.asyncAfter(deadline: .now() + 2) {
                context.finish(reachable: false)
            }
        }
    }

    static func checkAll(domain: String) async -> ServiceResult<[PortReachability]> {
        async let port443 = check(domain: domain, port: 443)
        async let port80 = check(domain: domain, port: 80)
        let results = await [port443, port80]
        return results.isEmpty ? .empty("No reachability results") : .success(results)
    }
}

private final class ConnectionContext: @unchecked Sendable {
    private let port: UInt16
    private let connection: NWConnection
    private let continuation: CheckedContinuation<PortReachability, Never>
    private let start = CFAbsoluteTimeGetCurrent()
    private let lock = NSLock()
    private nonisolated(unsafe) var resumed = false

    init(port: UInt16, connection: NWConnection, continuation: CheckedContinuation<PortReachability, Never>) {
        self.port = port
        self.connection = connection
        self.continuation = continuation
    }

    nonisolated func finish(reachable: Bool) {
        lock.lock()
        guard !resumed else {
            lock.unlock()
            return
        }
        resumed = true
        lock.unlock()

        let elapsed = CFAbsoluteTimeGetCurrent() - start
        let ms = reachable ? Int(elapsed * 1000) : nil
        connection.cancel()
        continuation.resume(returning: PortReachability(port: port, reachable: reachable, latencyMs: ms))
    }
}
