import Foundation
import Network
import Observation
import Security

@MainActor
@Observable
final class IntegrationService {
    static let shared = IntegrationService()

    var targets: [IntegrationTarget]
    var deliveryRecords: [DeliveryRecord]
    var queue: [QueuedDelivery]
    var statusMessage: String?

    private let defaults: UserDefaults
    private var processingTask: Task<Void, Never>?

    private init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        self.targets = Self.loadTargets(defaults: defaults)
        self.deliveryRecords = Self.loadRecords(defaults: defaults)
        self.queue = Self.loadQueue(defaults: defaults)
    }

    func refresh() {
        targets = Self.loadTargets(defaults: defaults)
        deliveryRecords = Self.loadRecords(defaults: defaults)
        queue = Self.loadQueue(defaults: defaults)
    }

    func upsert(
        target: IntegrationTarget,
        webhookURL: String? = nil,
        slackWebhookURL: String? = nil,
        emailPassword: String? = nil
    ) throws {
        var updatedTarget = target

        switch updatedTarget.configuration {
        case .webhook(var configuration):
            if let webhookURL {
                let reference = configuration.credentialReference ?? Self.secretReference(for: updatedTarget.id, suffix: "webhook")
                try IntegrationSecretStore.save(secret: webhookURL, reference: reference)
                configuration.credentialReference = reference
                configuration.endpointDisplayHost = Self.hostLabel(from: webhookURL)
                updatedTarget.configuration = .webhook(configuration)
            }
        case .slack(var configuration):
            if let slackWebhookURL {
                let reference = configuration.credentialReference ?? Self.secretReference(for: updatedTarget.id, suffix: "slack")
                try IntegrationSecretStore.save(secret: slackWebhookURL, reference: reference)
                configuration.credentialReference = reference
                configuration.destinationLabel = Self.hostLabel(from: slackWebhookURL)
                updatedTarget.configuration = .slack(configuration)
            }
        case .email(var configuration):
            if let emailPassword {
                let reference = configuration.credentialReference ?? Self.secretReference(for: updatedTarget.id, suffix: "smtp")
                try IntegrationSecretStore.save(secret: emailPassword, reference: reference)
                configuration.credentialReference = reference
                updatedTarget.configuration = .email(configuration)
            }
        }

        if let index = targets.firstIndex(where: { $0.id == updatedTarget.id }) {
            targets[index] = updatedTarget
        } else {
            targets.append(updatedTarget)
        }
        targets.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        persistTargets()
        statusMessage = "Saved integration settings."
    }

    func delete(targetID: UUID) {
        guard let target = targets.first(where: { $0.id == targetID }) else { return }
        deleteSecrets(for: target)
        targets.removeAll { $0.id == targetID }
        queue.removeAll { $0.integrationID == targetID }
        deliveryRecords.removeAll { $0.integrationID == targetID }
        persistTargets()
        persistQueue()
        persistRecords()
    }

    func setEnabled(_ isEnabled: Bool, for targetID: UUID) {
        guard let index = targets.firstIndex(where: { $0.id == targetID }) else { return }
        targets[index].isEnabled = isEnabled
        persistTargets()
    }

    func deliveryRecords(for targetID: UUID) -> [DeliveryRecord] {
        deliveryRecords
            .filter { $0.integrationID == targetID }
            .sorted { $0.timestamp > $1.timestamp }
    }

    func enqueue(events: [MonitoringEvent]) {
        guard !events.isEmpty else { return }
        let eligibleTargets = targets.filter(\.isEnabled)
        for event in events {
            for target in eligibleTargets {
                if let reason = filterMismatchReason(for: event, target: target) {
                    appendRecord(
                        DeliveryRecord(
                            integrationID: target.id,
                            eventID: event.id,
                            status: .skipped,
                            destination: destinationLabel(for: target),
                            summary: event.summary,
                            failureReason: reason
                        )
                    )
                    continue
                }

                queue.append(QueuedDelivery(integrationID: target.id, event: event))
                appendRecord(
                    DeliveryRecord(
                        integrationID: target.id,
                        eventID: event.id,
                        status: .pending,
                        destination: destinationLabel(for: target),
                        summary: event.summary
                    )
                )
            }
        }
        persistQueue()
        scheduleProcessing()
    }

    func recordNoOutboundEvents(for runSummary: String) {
        let eligibleTargets = targets.filter(\.isEnabled)
        for target in eligibleTargets {
            appendRecord(
                DeliveryRecord(
                    integrationID: target.id,
                    eventID: UUID(),
                    status: .skipped,
                    destination: destinationLabel(for: target),
                    summary: runSummary,
                    failureReason: "Monitoring run produced no outbound events."
                )
            )
        }
    }

    func sendTest(for targetID: UUID) {
        guard targets.contains(where: { $0.id == targetID }) else { return }
        let event = MonitoringEvent(
            type: .test,
            severity: .info,
            domain: "example.com",
            summary: "DomainDig integration test",
            details: [
                "source": "manual test",
                "environment": "local-first"
            ]
        )
        queue.append(QueuedDelivery(integrationID: targetID, event: event))
        appendRecord(
            DeliveryRecord(
                integrationID: targetID,
                eventID: event.id,
                status: .pending,
                destination: targets.first(where: { $0.id == targetID }).map(destinationLabel(for:)) ?? "Unknown",
                summary: event.summary
            )
        )
        persistQueue()
        scheduleProcessing()
    }

    func processQueueNow() {
        scheduleProcessing(force: true)
    }

    func localSecretReferences() -> [String] {
        targets.compactMap { target in
            switch target.configuration {
            case .webhook(let configuration):
                configuration.credentialReference
            case .slack(let configuration):
                configuration.credentialReference
            case .email(let configuration):
                configuration.credentialReference
            }
        }
    }

    func resetAfterLocalWipe() {
        processingTask?.cancel()
        processingTask = nil
        targets = []
        deliveryRecords = []
        queue = []
        statusMessage = nil
    }

    private func scheduleProcessing(force: Bool = false) {
        if force {
            processingTask?.cancel()
            processingTask = nil
        }
        guard processingTask == nil else { return }
        processingTask = Task { [weak self] in
            guard let self else { return }
            await self.processQueueLoop()
        }
    }

    private func processQueueLoop() async {
        defer { processingTask = nil }

        while true {
            let dueItems = queue
                .enumerated()
                .filter { $0.element.nextAttemptAt <= Date() }

            if dueItems.isEmpty {
                guard let nextAttemptAt = queue.map(\.nextAttemptAt).min() else {
                    break
                }

                let delay = max(0.25, nextAttemptAt.timeIntervalSinceNow)
                do {
                    try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                    continue
                } catch {
                    break
                }
            }

            for entry in dueItems.reversed() {
                guard entry.offset < queue.count else { continue }
                let item = queue[entry.offset]
                await process(item: item, at: entry.offset)
            }
        }
    }

    private func process(item: QueuedDelivery, at index: Int) async {
        guard let target = targets.first(where: { $0.id == item.integrationID }) else {
            queue.remove(at: index)
            persistQueue()
            return
        }

        guard item.expiresAt > Date() else {
            queue.remove(at: index)
            persistQueue()
            appendRecord(
                DeliveryRecord(
                    integrationID: target.id,
                    eventID: item.event.id,
                    status: .expired,
                    destination: destinationLabel(for: target),
                    summary: item.event.summary,
                    failureReason: "Delivery expired before succeeding.",
                    attemptCount: item.attemptCount
                )
            )
            return
        }

        do {
            try await deliver(item.event, to: target)
            queue.remove(at: index)
            persistQueue()
            appendRecord(
                DeliveryRecord(
                    integrationID: target.id,
                    eventID: item.event.id,
                    status: .delivered,
                    destination: destinationLabel(for: target),
                    summary: item.event.summary,
                    attemptCount: item.attemptCount + 1
                )
            )
            statusMessage = "Delivered \(item.event.summary)."
        } catch {
            var updated = item
            updated.attemptCount += 1
            updated.lastError = error.localizedDescription

            if updated.attemptCount >= 5 {
                queue.remove(at: index)
                appendRecord(
                    DeliveryRecord(
                        integrationID: target.id,
                        eventID: item.event.id,
                        status: .failed,
                        destination: destinationLabel(for: target),
                        summary: item.event.summary,
                        failureReason: error.localizedDescription,
                        attemptCount: updated.attemptCount
                    )
                )
            } else {
                let backoff = min(pow(2, Double(updated.attemptCount)) * 30, 3600)
                updated.nextAttemptAt = Date().addingTimeInterval(backoff)
                queue[index] = updated
                appendRecord(
                    DeliveryRecord(
                        integrationID: target.id,
                        eventID: item.event.id,
                        status: .retrying,
                        destination: destinationLabel(for: target),
                        summary: item.event.summary,
                        failureReason: error.localizedDescription,
                        attemptCount: updated.attemptCount
                    )
                )
            }

            persistQueue()
            statusMessage = error.localizedDescription
        }
    }

    private func deliver(_ event: MonitoringEvent, to target: IntegrationTarget) async throws {
        switch target.configuration {
        case .webhook(let configuration):
            guard let reference = configuration.credentialReference else {
                throw IntegrationError.missingSecret
            }
            let webhookURLString = try IntegrationSecretStore.secret(reference: reference)
            try await HTTPIntegrationClient.sendJSON(
                payload: IntegrationEventPayload(event: event),
                to: webhookURLString,
                headers: configuration.additionalHeaders,
                timeoutSeconds: configuration.timeoutSeconds
            )
        case .slack(let configuration):
            guard let reference = configuration.credentialReference else {
                throw IntegrationError.missingSecret
            }
            let webhookURLString = try IntegrationSecretStore.secret(reference: reference)
            try await HTTPIntegrationClient.sendJSON(
                payload: SlackPayload(event: event),
                to: webhookURLString,
                headers: [:],
                timeoutSeconds: 15
            )
        case .email(let configuration):
            guard let reference = configuration.credentialReference else {
                throw IntegrationError.missingSecret
            }
            let password = try IntegrationSecretStore.secret(reference: reference)
            try await SMTPClient.send(
                event: event,
                configuration: configuration,
                password: password
            )
        }
    }

    private func appendRecord(_ record: DeliveryRecord) {
        deliveryRecords.insert(record, at: 0)
        deliveryRecords = Array(deliveryRecords.prefix(250))
        persistRecords()
    }

    private func persistTargets() {
        Self.save(targets, key: StorageKey.targets, defaults: defaults)
    }

    private func persistRecords() {
        Self.save(deliveryRecords, key: StorageKey.records, defaults: defaults)
    }

    private func persistQueue() {
        Self.save(queue, key: StorageKey.queue, defaults: defaults)
    }

    private func deleteSecrets(for target: IntegrationTarget) {
        switch target.configuration {
        case .webhook(let configuration):
            if let reference = configuration.credentialReference {
                try? IntegrationSecretStore.delete(reference: reference)
            }
        case .slack(let configuration):
            if let reference = configuration.credentialReference {
                try? IntegrationSecretStore.delete(reference: reference)
            }
        case .email(let configuration):
            if let reference = configuration.credentialReference {
                try? IntegrationSecretStore.delete(reference: reference)
            }
        }
    }

    private func destinationLabel(for target: IntegrationTarget) -> String {
        switch target.configuration {
        case .webhook(let configuration):
            return configuration.endpointDisplayHost.isEmpty ? target.name : configuration.endpointDisplayHost
        case .slack(let configuration):
            return configuration.destinationLabel
        case .email(let configuration):
            return configuration.recipientAddresses.joined(separator: ", ")
        }
    }

    private func filterMismatchReason(for event: MonitoringEvent, target: IntegrationTarget) -> String? {
        let filters = target.filters

        if event.severity < filters.minimumSeverity {
            return "Filtered by severity. Event was \(event.severity.title), target requires \(filters.minimumSeverity.title)."
        }

        if !filters.eventTypes.isEmpty, !filters.eventTypes.contains(event.type) {
            return "Filtered by event type. Event was \(event.type.title)."
        }

        if !filters.domains.isEmpty, !filters.domains.map({ $0.lowercased() }).contains(event.domain.lowercased()) {
            return "Filtered by domain. Event was for \(event.domain)."
        }

        return nil
    }

    private static func hostLabel(from string: String) -> String {
        URL(string: string)?.host ?? "Configured"
    }

    private static func secretReference(for integrationID: UUID, suffix: String) -> String {
        "integration.\(integrationID.uuidString).\(suffix)"
    }

    private static func loadTargets(defaults: UserDefaults) -> [IntegrationTarget] {
        load([IntegrationTarget].self, key: StorageKey.targets, defaults: defaults) ?? []
    }

    private static func loadRecords(defaults: UserDefaults) -> [DeliveryRecord] {
        load([DeliveryRecord].self, key: StorageKey.records, defaults: defaults) ?? []
    }

    private static func loadQueue(defaults: UserDefaults) -> [QueuedDelivery] {
        load([QueuedDelivery].self, key: StorageKey.queue, defaults: defaults) ?? []
    }

    private static func load<T: Decodable>(_ type: T.Type, key: String, defaults: UserDefaults) -> T? {
        guard let data = defaults.data(forKey: key) else {
            return nil
        }
        return try? JSONDecoder().decode(type, from: data)
    }

    private static func save<T: Encodable>(_ value: T, key: String, defaults: UserDefaults) {
        if let data = try? JSONEncoder().encode(value) {
            defaults.set(data, forKey: key)
        }
    }

    private enum StorageKey {
        static let targets = "integrations.targets"
        static let records = "integrations.records"
        static let queue = "integrations.queue"
    }
}

private struct IntegrationEventPayload: Encodable {
    let eventType: String
    let domain: String
    let timestamp: Date
    let severity: String
    let summary: String
    let details: [String: String]

    init(event: MonitoringEvent) {
        self.eventType = event.type.rawValue
        self.domain = event.domain
        self.timestamp = event.timestamp
        self.severity = event.severity.rawValue
        self.summary = event.summary
        self.details = event.details
    }
}

private struct SlackPayload: Encodable {
    let text: String
    let blocks: [SlackBlock]

    init(event: MonitoringEvent) {
        let title = "\(event.severity.title.uppercased()) • \(event.domain)"
        let detailLines = event.details
            .sorted { $0.key < $1.key }
            .prefix(6)
            .map { "\($0.key): \($0.value)" }
            .joined(separator: "\n")

        self.text = "\(title) — \(event.summary)"
        self.blocks = [
            SlackBlock(
                type: "section",
                text: .init(type: "mrkdwn", text: "*\(title)*\n\(event.summary)")
            ),
            SlackBlock(
                type: "section",
                text: .init(
                    type: "mrkdwn",
                    text: "*Event*: \(event.type.title)\n*Timestamp*: \(event.timestamp.formatted(date: .abbreviated, time: .shortened))"
                )
            ),
            SlackBlock(
                type: "section",
                text: .init(type: "mrkdwn", text: detailLines.isEmpty ? "_No extra details_" : detailLines)
            )
        ]
    }
}

private struct SlackBlock: Encodable {
    let type: String
    let text: SlackText
}

private struct SlackText: Encodable {
    let type: String
    let text: String
}

private enum IntegrationError: LocalizedError {
    case invalidURL
    case missingSecret
    case invalidResponse(Int)
    case invalidSMTPPort
    case smtp(String)
    case streamClosed

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "The integration URL is invalid."
        case .missingSecret:
            return "This integration is missing a saved secret."
        case .invalidResponse(let statusCode):
            return "The remote endpoint returned \(statusCode)."
        case .invalidSMTPPort:
            return "The SMTP port is invalid."
        case .smtp(let message):
            return message
        case .streamClosed:
            return "The SMTP connection closed unexpectedly."
        }
    }
}

private enum HTTPIntegrationClient {
    static func sendJSON<T: Encodable>(
        payload: T,
        to urlString: String,
        headers: [String: String],
        timeoutSeconds: Double
    ) async throws {
        guard let url = URL(string: urlString) else {
            throw IntegrationError.invalidURL
        }

        var request = URLRequest(url: url, timeoutInterval: timeoutSeconds)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        request.httpBody = try encoder.encode(payload)

        let (_, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw IntegrationError.invalidResponse(-1)
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw IntegrationError.invalidResponse(httpResponse.statusCode)
        }
    }
}

private enum IntegrationSecretStore {
    static func save(secret: String, reference: String) throws {
        let data = Data(secret.utf8)
        try? delete(reference: reference)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: reference,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw IntegrationError.smtp("Could not save integration secret.")
        }
    }

    static func secret(reference: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: reference,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let secret = String(data: data, encoding: .utf8) else {
            throw IntegrationError.missingSecret
        }

        return secret
    }

    static func delete(reference: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: reference
        ]
        SecItemDelete(query as CFDictionary)
    }
}

private enum SMTPClient {
    static func send(
        event: MonitoringEvent,
        configuration: EmailIntegrationConfiguration,
        password: String
    ) async throws {
        guard let port = NWEndpoint.Port(rawValue: UInt16(configuration.port)) else {
            throw IntegrationError.invalidSMTPPort
        }

        let parameters: NWParameters = {
            switch configuration.securityMode {
            case .plain:
                return .tcp
            case .directTLS:
                let tls = NWProtocolTLS.Options()
                return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
            }
        }()

        let channel = SMTPChannel(host: configuration.smtpHost, port: port, parameters: parameters)
        try await channel.start()
        _ = try await channel.readResponse(expecting: [220])
        _ = try await channel.sendCommand("EHLO domaindig.local", expecting: [250])

        if !configuration.username.isEmpty {
            _ = try await channel.sendCommand("AUTH LOGIN", expecting: [334])
            _ = try await channel.sendCommand(Data(configuration.username.utf8).base64EncodedString(), expecting: [334])
            _ = try await channel.sendCommand(Data(password.utf8).base64EncodedString(), expecting: [235])
        }

        _ = try await channel.sendCommand("MAIL FROM:<\(configuration.senderAddress)>", expecting: [250])
        for recipient in configuration.recipientAddresses {
            _ = try await channel.sendCommand("RCPT TO:<\(recipient)>", expecting: [250, 251])
        }
        _ = try await channel.sendCommand("DATA", expecting: [354])

        let detailLines = event.details
            .sorted { $0.key < $1.key }
            .map { "\($0.key): \($0.value)" }
            .joined(separator: "\r\n")
        let body = [
            "From: DomainDig <\(configuration.senderAddress)>",
            "To: \(configuration.recipientAddresses.joined(separator: ", "))",
            "Subject: [DomainDig] \(event.severity.title) \(event.domain) \(event.type.title)",
            "Date: \(DateFormatter.rfc2822.string(from: Date()))",
            "",
            event.summary,
            "",
            "Domain: \(event.domain)",
            "Severity: \(event.severity.title)",
            "Event: \(event.type.title)",
            "Timestamp: \(event.timestamp.formatted(date: .abbreviated, time: .shortened))",
            detailLines
        ]
        .joined(separator: "\r\n")

        try await channel.sendRaw(body + "\r\n.\r\n")
        _ = try await channel.readResponse(expecting: [250])
        _ = try await channel.sendCommand("QUIT", expecting: [221])
        channel.cancel()
    }
}

private final class SMTPChannel {
    private let connection: NWConnection
    private var parsedLines: [String] = []
    private var lineWaiters: [CheckedContinuation<String, Error>] = []
    private var receiveBuffer = Data()

    init(host: String, port: NWEndpoint.Port, parameters: NWParameters) {
        connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters)
    }

    func start() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    DispatchQueue.global(qos: .utility).async {
                        self?.startReceiveLoop()
                    }
                    continuation.resume()
                case .failed(let error):
                    continuation.resume(throwing: error)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))
        }
    }

    func cancel() {
        connection.cancel()
    }

    func sendCommand(_ command: String, expecting codes: Set<Int>) async throws -> String {
        try await sendRaw(command + "\r\n")
        return try await readResponse(expecting: codes)
    }

    func sendCommand(_ command: String, expecting codes: [Int]) async throws -> String {
        try await sendCommand(command, expecting: Set(codes))
    }

    func sendRaw(_ string: String) async throws {
        let data = Data(string.utf8)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func readResponse(expecting codes: Set<Int>) async throws -> String {
        var lines: [String] = []

        while true {
            let line = try await readLine()
            lines.append(line)

            guard line.count >= 4,
                  let code = Int(line.prefix(3)) else {
                continue
            }

            let delimiterIndex = line.index(line.startIndex, offsetBy: 3)
            if line[delimiterIndex] == " " {
                guard codes.contains(code) else {
                    throw IntegrationError.smtp(line)
                }
                return lines.joined(separator: "\n")
            }
        }
    }

    private func readLine() async throws -> String {
        if !parsedLines.isEmpty {
            return parsedLines.removeFirst()
        }

        return try await withCheckedThrowingContinuation { continuation in
            lineWaiters.append(continuation)
        }
    }

    private func startReceiveLoop() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self else { return }

            if let error {
                self.failWaiters(with: error)
                return
            }

            if let data, !data.isEmpty {
                self.receiveBuffer.append(data)
                self.flushBuffer()
            }

            if isComplete {
                self.failWaiters(with: IntegrationError.streamClosed)
                return
            }

            self.startReceiveLoop()
        }
    }

    private func flushBuffer() {
        let delimiter = Data("\r\n".utf8)
        while let range = receiveBuffer.range(of: delimiter) {
            let lineData = receiveBuffer.subdata(in: receiveBuffer.startIndex..<range.lowerBound)
            receiveBuffer.removeSubrange(receiveBuffer.startIndex..<range.upperBound)
            let line = String(data: lineData, encoding: .utf8) ?? ""
            if !lineWaiters.isEmpty {
                let continuation = lineWaiters.removeFirst()
                continuation.resume(returning: line)
            } else {
                parsedLines.append(line)
            }
        }
    }

    private func failWaiters(with error: Error) {
        let waiters = lineWaiters
        lineWaiters.removeAll()
        for waiter in waiters {
            waiter.resume(throwing: error)
        }
    }
}

private extension DateFormatter {
    static let rfc2822: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter
    }()
}
