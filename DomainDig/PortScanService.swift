import Foundation
import Network

struct PortScanService {
    struct PortInfo: Sendable {
        let port: UInt16
        let service: String
    }

    static let ports: [PortInfo] = [
        PortInfo(port: 21, service: "FTP"),
        PortInfo(port: 22, service: "SSH"),
        PortInfo(port: 25, service: "SMTP"),
        PortInfo(port: 80, service: "HTTP"),
        PortInfo(port: 443, service: "HTTPS"),
        PortInfo(port: 587, service: "SMTP (TLS)"),
        PortInfo(port: 3306, service: "MySQL"),
        PortInfo(port: 5432, service: "PostgreSQL"),
        PortInfo(port: 8080, service: "HTTP Alt"),
        PortInfo(port: 8443, service: "HTTPS Alt"),
    ]

    static func scanAll(domain: String) async -> ServiceResult<[PortScanResult]> {
        await withTaskGroup(of: PortScanResult.self, returning: [PortScanResult].self) { group in
            for info in ports {
                group.addTask {
                    let result = await probe(domain: domain, port: info.port)
                    return PortScanResult(
                        port: info.port,
                        service: info.service,
                        open: result.open,
                        kind: .standard,
                        durationMs: result.durationMs
                    )
                }
            }

            var results: [PortScanResult] = []
            for await result in group {
                results.append(result)
            }

            // Sort by port number
            let sorted = results.sorted { $0.port < $1.port }
            return sorted.isEmpty ? [] : sorted
        }
        .pipe { $0.isEmpty ? .empty("No port scan results") : .success($0) }
    }

    static func scanPorts(domain: String, ports: [UInt16], timeout: TimeInterval) async -> ServiceResult<[PortScanResult]> {
        await withTaskGroup(of: PortScanResult.self, returning: [PortScanResult].self) { group in
            for port in ports {
                let service = self.ports.first(where: { $0.port == port })?.service ?? "Custom"
                group.addTask {
                    let result = await probe(domain: domain, port: port, timeout: timeout)
                    return PortScanResult(
                        port: port,
                        service: service,
                        open: result.open,
                        kind: .custom,
                        durationMs: result.durationMs
                    )
                }
            }

            var results: [PortScanResult] = []
            for await result in group {
                results.append(result)
            }

            let sorted = results.sorted { $0.port < $1.port }
            return sorted.isEmpty ? [] : sorted
        }
        .pipe { $0.isEmpty ? .empty("No custom port scan results") : .success($0) }
    }

    static func grabBanner(host: String, port: UInt16, timeout: TimeInterval = 3.0) async -> String? {
        await withCheckedContinuation { continuation in
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                continuation.resume(returning: nil)
                return
            }

            let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
            let context = BannerContext(connection: connection, continuation: continuation)
            let queue = DispatchQueue(label: "portscan.banner.\(port)")

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, error in
                        guard error == nil,
                              let data,
                              !data.isEmpty,
                              let rawBanner = String(data: data, encoding: .utf8) else {
                            context.finish(with: nil)
                            return
                        }

                        let printableBanner = rawBanner.filter { character in
                            guard let scalar = character.unicodeScalars.first,
                                  character.unicodeScalars.count == 1 else {
                                return false
                            }
                            return (32...126).contains(scalar.value)
                        }

                        let banner = String(printableBanner.prefix(80))
                        context.finish(with: banner.isEmpty ? nil : banner)
                    }
                case .failed, .cancelled:
                    context.finish(with: nil)
                default:
                    break
                }
            }

            connection.start(queue: queue)

            queue.asyncAfter(deadline: .now() + timeout) {
                context.finish(with: nil)
            }
        }
    }

    private static func probe(domain: String, port: UInt16) async -> PortProbeResult {
        await probe(domain: domain, port: port, timeout: 5)
    }

    private static func probe(domain: String, port: UInt16, timeout: TimeInterval) async -> PortProbeResult {
        await withCheckedContinuation { continuation in
            let host = NWEndpoint.Host(domain)
            let nwPort = NWEndpoint.Port(rawValue: port)!
            let connection = NWConnection(host: host, port: nwPort, using: .tcp)
            let context = ProbeContext(connection: connection, continuation: continuation)

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    context.finish(open: true)
                case .failed, .cancelled:
                    context.finish(open: false)
                default:
                    break
                }
            }

            let queue = DispatchQueue(label: "portscan.\(port)")
            connection.start(queue: queue)

            queue.asyncAfter(deadline: .now() + timeout) {
                context.finish(open: false)
            }
        }
    }
}

private struct PortProbeResult: Sendable {
    let open: Bool
    let durationMs: Int?
}

private final class ProbeContext: @unchecked Sendable {
    private let connection: NWConnection
    private let continuation: CheckedContinuation<PortProbeResult, Never>
    private let start = CFAbsoluteTimeGetCurrent()
    private let lock = NSLock()
    private nonisolated(unsafe) var resumed = false

    init(connection: NWConnection, continuation: CheckedContinuation<PortProbeResult, Never>) {
        self.connection = connection
        self.continuation = continuation
    }

    nonisolated func finish(open: Bool) {
        lock.lock()
        guard !resumed else {
            lock.unlock()
            return
        }
        resumed = true
        lock.unlock()

        connection.cancel()
        let elapsedMs = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
        continuation.resume(returning: PortProbeResult(
            open: open,
            durationMs: elapsedMs >= 0 ? elapsedMs : nil
        ))
    }
}

private extension Array {
    func pipe<T>(_ transform: (Self) -> T) -> T {
        transform(self)
    }
}

private final class BannerContext: @unchecked Sendable {
    private let connection: NWConnection
    private let continuation: CheckedContinuation<String?, Never>
    private let lock = NSLock()
    private nonisolated(unsafe) var resumed = false

    init(connection: NWConnection, continuation: CheckedContinuation<String?, Never>) {
        self.connection = connection
        self.continuation = continuation
    }

    nonisolated func finish(with banner: String?) {
        lock.lock()
        guard !resumed else {
            lock.unlock()
            return
        }
        resumed = true
        lock.unlock()

        connection.cancel()
        continuation.resume(returning: banner)
    }
}
