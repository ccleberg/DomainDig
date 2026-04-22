import Foundation

actor ExternalDataService {
    static let shared = ExternalDataService()

    private enum RequestKey: Hashable {
        case ownershipHistory(String)
        case dnsHistory(String)
        case extendedSubdomains(String)
        case pricing(String)
    }

    private enum RateLimitBucket: Hashable {
        case history
        case subdomains
        case pricing

        var minimumSpacing: TimeInterval {
            switch self {
            case .history:
                return 1.0
            case .subdomains:
                return 1.5
            case .pricing:
                return 1.0
            }
        }
    }

    private enum CachedPayload {
        case ownershipHistory(ServiceResult<[DomainOwnershipHistoryEvent]>)
        case dnsHistory(ServiceResult<[DNSHistoryEvent]>)
        case extendedSubdomains(ServiceResult<[DiscoveredSubdomain]>)
        case pricing(ServiceResult<DomainPricingInsight>)
    }

    private struct CacheEntry {
        let payload: CachedPayload
        let expiresAt: Date
    }

    private struct Configuration {
        let ownershipHistoryURL: String?
        let dnsHistoryURL: String?
        let extendedSubdomainsURL: String?
        let pricingURL: String?
    }

    private let ttl: TimeInterval = 900
    private let session: URLSession = .shared
    private var cache: [RequestKey: CacheEntry] = [:]
    private var inFlight: [RequestKey: Task<CachedPayload, Never>] = [:]
    private var nextAllowedAt: [RateLimitBucket: Date] = [:]

    func clearCache() {
        cache.removeAll()
        inFlight.values.forEach { $0.cancel() }
        inFlight.removeAll()
        nextAllowedAt.removeAll()
    }

    func ownershipHistory(
        domain: String,
        currentOwnership: DomainOwnership?,
        historyEntries: [HistoryEntry]
    ) async -> CachedLookupResult<ServiceResult<[DomainOwnershipHistoryEvent]>> {
        let normalizedDomain = Self.normalize(domain)
        return await execute(
            key: .ownershipHistory(normalizedDomain),
            rateLimitBucket: .history,
            extract: { payload in
                guard case let .ownershipHistory(result) = payload else { return nil }
                return result
            },
            operation: { [configuration = configuration()] in
                let localEvents = Self.localOwnershipHistory(
                    domain: normalizedDomain,
                    currentOwnership: currentOwnership,
                    historyEntries: historyEntries
                )
                let externalEvents = await self.fetchOwnershipHistory(domain: normalizedDomain, configuration: configuration)
                return .ownershipHistory(Self.mergeOwnershipHistory(localEvents: localEvents, externalEvents: externalEvents))
            }
        )
    }

    func dnsHistory(
        domain: String,
        dnsSections: [DNSSection],
        historyEntries: [HistoryEntry]
    ) async -> CachedLookupResult<ServiceResult<[DNSHistoryEvent]>> {
        let normalizedDomain = Self.normalize(domain)
        return await execute(
            key: .dnsHistory(normalizedDomain),
            rateLimitBucket: .history,
            extract: { payload in
                guard case let .dnsHistory(result) = payload else { return nil }
                return result
            },
            operation: { [configuration = configuration()] in
                let localEvents = Self.localDNSHistory(
                    domain: normalizedDomain,
                    dnsSections: dnsSections,
                    historyEntries: historyEntries
                )
                let externalEvents = await self.fetchDNSHistory(domain: normalizedDomain, configuration: configuration)
                return .dnsHistory(Self.mergeDNSHistory(localEvents: localEvents, externalEvents: externalEvents))
            }
        )
    }

    func extendedSubdomains(
        domain: String,
        existing: [DiscoveredSubdomain]
    ) async -> CachedLookupResult<ServiceResult<[DiscoveredSubdomain]>> {
        let normalizedDomain = Self.normalize(domain)
        return await execute(
            key: .extendedSubdomains(normalizedDomain),
            rateLimitBucket: .subdomains,
            extract: { payload in
                guard case let .extendedSubdomains(result) = payload else { return nil }
                return result
            },
            operation: { [configuration = configuration()] in
                var merged = existing
                switch await SubdomainDiscoveryService.discover(for: normalizedDomain, limit: 100) {
                case let .success(results):
                    merged = Self.mergeSubdomains(primary: merged, additional: results.map {
                        DiscoveredSubdomain(hostname: $0.hostname, source: $0.source ?? "crt.sh", isExtended: true)
                    })
                case .empty, .error:
                    break
                }

                if let external = await self.fetchExtendedSubdomains(domain: normalizedDomain, configuration: configuration) {
                    merged = Self.mergeSubdomains(primary: merged, additional: external)
                }

                if merged.count <= existing.count {
                    return .extendedSubdomains(.empty("No extended subdomains available"))
                }

                let onlyExtended = merged.filter(\.isExtended)
                return .extendedSubdomains(.success(onlyExtended.sorted { $0.hostname < $1.hostname }))
            }
        )
    }

    func pricing(domain: String) async -> CachedLookupResult<ServiceResult<DomainPricingInsight>> {
        let normalizedDomain = Self.normalize(domain)
        return await execute(
            key: .pricing(normalizedDomain),
            rateLimitBucket: .pricing,
            extract: { payload in
                guard case let .pricing(result) = payload else { return nil }
                return result
            },
            operation: { [configuration = configuration()] in
                .pricing(await self.fetchPricing(domain: normalizedDomain, configuration: configuration))
            }
        )
    }

    private func execute<T>(
        key: RequestKey,
        rateLimitBucket: RateLimitBucket,
        extract: @escaping (CachedPayload) -> T?,
        operation: @escaping @Sendable () async -> CachedPayload
    ) async -> CachedLookupResult<T> {
        if let cachedEntry = cache[key], cachedEntry.expiresAt > Date(), let value = extract(cachedEntry.payload) {
            return CachedLookupResult(value: value, source: .cached)
        }

        if let task = inFlight[key], let value = extract(await task.value) {
            return CachedLookupResult(value: value, source: .mixed)
        }

        let task = Task<CachedPayload, Never> {
            await self.enforceRateLimit(for: rateLimitBucket)
            return await operation()
        }
        inFlight[key] = task

        let payload = await task.value
        cache[key] = CacheEntry(payload: payload, expiresAt: Date().addingTimeInterval(ttl))
        inFlight[key] = nil

        guard let value = extract(payload) else {
            fatalError("ExternalDataService payload extraction mismatch")
        }

        return CachedLookupResult(value: value, source: .live)
    }

    private func enforceRateLimit(for bucket: RateLimitBucket) async {
        let now = Date()
        if let nextAllowed = nextAllowedAt[bucket], nextAllowed > now {
            let delay = nextAllowed.timeIntervalSince(now)
            if delay > 0 {
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }
        nextAllowedAt[bucket] = Date().addingTimeInterval(bucket.minimumSpacing)
    }

    private func configuration() -> Configuration {
        let defaults = UserDefaults.standard
        return Configuration(
            ownershipHistoryURL: defaults.string(forKey: "externalData.ownershipHistoryURL")
                ?? Bundle.main.object(forInfoDictionaryKey: "ExternalOwnershipHistoryURL") as? String,
            dnsHistoryURL: defaults.string(forKey: "externalData.dnsHistoryURL")
                ?? Bundle.main.object(forInfoDictionaryKey: "ExternalDNSHistoryURL") as? String,
            extendedSubdomainsURL: defaults.string(forKey: "externalData.extendedSubdomainsURL")
                ?? Bundle.main.object(forInfoDictionaryKey: "ExternalExtendedSubdomainsURL") as? String,
            pricingURL: defaults.string(forKey: "externalData.pricingURL")
                ?? Bundle.main.object(forInfoDictionaryKey: "ExternalPricingURL") as? String
        )
    }

    private func fetchOwnershipHistory(
        domain: String,
        configuration: Configuration
    ) async -> [DomainOwnershipHistoryEvent] {
        guard let template = configuration.ownershipHistoryURL,
              let url = Self.url(from: template, domain: domain) else {
            return []
        }

        switch await requestData(url: url) {
        case let .success(data):
            return parseOwnershipHistoryEvents(from: data)
        case .empty, .error:
            return []
        }
    }

    private func fetchDNSHistory(
        domain: String,
        configuration: Configuration
    ) async -> [DNSHistoryEvent] {
        guard let template = configuration.dnsHistoryURL,
              let url = Self.url(from: template, domain: domain) else {
            return []
        }

        switch await requestData(url: url) {
        case let .success(data):
            return parseDNSHistoryEvents(from: data)
        case .empty, .error:
            return []
        }
    }

    private func fetchExtendedSubdomains(
        domain: String,
        configuration: Configuration
    ) async -> [DiscoveredSubdomain]? {
        guard let template = configuration.extendedSubdomainsURL,
              let url = Self.url(from: template, domain: domain) else {
            return nil
        }

        switch await requestData(url: url) {
        case let .success(data):
            return parseSubdomains(from: data)
        case .empty, .error:
            return nil
        }
    }

    private func fetchPricing(
        domain: String,
        configuration: Configuration
    ) async -> ServiceResult<DomainPricingInsight> {
        guard let template = configuration.pricingURL,
              let url = Self.url(from: template, domain: domain) else {
            return .empty("External pricing unavailable")
        }

        switch await requestData(url: url) {
        case let .success(data):
            guard let pricing = parsePricing(from: data) else {
                return .error("Invalid external response")
            }
            return .success(pricing)
        case let .empty(message):
            return .empty(message)
        case let .error(message):
            return .error(message)
        }
    }

    private func requestData(url: URL) async -> ServiceResult<Data> {
        for attempt in 0..<2 {
            do {
                let (data, response) = try await session.data(for: URLRequest(url: url, timeoutInterval: 8))
                guard let httpResponse = response as? HTTPURLResponse else {
                    return .error("External data unavailable")
                }

                switch httpResponse.statusCode {
                case 200:
                    return .success(data)
                case 204, 404:
                    return .empty("No external data available")
                case 429:
                    return .error("Rate limit reached")
                case 500...599 where attempt == 0:
                    continue
                default:
                    return .error("External provider failed")
                }
            } catch is DecodingError {
                return .error("Invalid external response")
            } catch {
                if attempt == 0 {
                    continue
                }
                return .error(error.localizedDescription)
            }
        }

        return .error("External provider failed")
    }

    private func parseOwnershipHistoryEvents(from data: Data) -> [DomainOwnershipHistoryEvent] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawEvents = json["events"] as? [[String: Any]] else {
            return []
        }

        return rawEvents.compactMap { event in
            guard let dateString = event["date"] as? String,
                  let date = Self.iso8601DateFormatter.date(from: dateString) else {
                return nil
            }

            return DomainOwnershipHistoryEvent(
                date: date,
                summary: event["summary"] as? String ?? "Ownership change observed",
                registrar: event["registrar"] as? String,
                registrant: event["registrant"] as? String,
                nameservers: event["nameservers"] as? [String] ?? [],
                source: event["source"] as? String ?? "Configured external history feed",
                isExternal: true
            )
        }
    }

    private func parseDNSHistoryEvents(from data: Data) -> [DNSHistoryEvent] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawEvents = json["events"] as? [[String: Any]] else {
            return []
        }

        return rawEvents.compactMap { event in
            guard let dateString = event["date"] as? String,
                  let date = Self.iso8601DateFormatter.date(from: dateString) else {
                return nil
            }

            return DNSHistoryEvent(
                date: date,
                summary: event["summary"] as? String ?? "DNS change observed",
                aRecords: event["a_records"] as? [String] ?? [],
                nameservers: event["nameservers"] as? [String] ?? [],
                source: event["source"] as? String ?? "Configured external history feed",
                isExternal: true
            )
        }
    }

    private func parseSubdomains(from data: Data) -> [DiscoveredSubdomain] {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawSubdomains = json["subdomains"] as? [[String: Any]] else {
            return []
        }

        return rawSubdomains.compactMap { item in
            guard let hostname = item["hostname"] as? String else { return nil }
            return DiscoveredSubdomain(
                hostname: hostname,
                source: item["source"] as? String ?? "Configured external subdomain feed",
                isExtended: true
            )
        }
    }

    private func parsePricing(from data: Data) -> DomainPricingInsight? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        return DomainPricingInsight(
            estimatedPrice: json["estimated_price"] as? String,
            premiumIndicator: json["premium"] as? Bool,
            resaleSignal: json["resale_signal"] as? String,
            auctionSignal: json["auction_signal"] as? String,
            source: json["source"] as? String ?? "Configured external pricing feed",
            collectedAt: Date()
        )
    }

    private static func localOwnershipHistory(
        domain: String,
        currentOwnership: DomainOwnership?,
        historyEntries: [HistoryEntry]
    ) -> [DomainOwnershipHistoryEvent] {
        let domainHistory = historyEntries
            .filter { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }
            .sorted { $0.timestamp < $1.timestamp }

        var events: [DomainOwnershipHistoryEvent] = []
        var previousOwnership: DomainOwnership?

        for entry in domainHistory {
            guard let ownership = entry.ownership else { continue }
            let summary = ownershipSummaryChange(previous: previousOwnership, current: ownership)
            if let summary {
                events.append(
                    DomainOwnershipHistoryEvent(
                        date: entry.timestamp,
                        summary: summary,
                        registrar: ownership.registrar,
                        registrant: ownership.registrant,
                        nameservers: ownership.nameservers,
                        source: "Local observations",
                        isExternal: false
                    )
                )
            }
            previousOwnership = ownership
        }

        if let currentOwnership, events.isEmpty {
            events.append(
                DomainOwnershipHistoryEvent(
                    date: Date(),
                    summary: "Current ownership snapshot",
                    registrar: currentOwnership.registrar,
                    registrant: currentOwnership.registrant,
                    nameservers: currentOwnership.nameservers,
                    source: "Local observations",
                    isExternal: false
                )
            )
        }

        return events.sorted { $0.date > $1.date }
    }

    private static func localDNSHistory(
        domain: String,
        dnsSections: [DNSSection],
        historyEntries: [HistoryEntry]
    ) -> [DNSHistoryEvent] {
        let domainHistory = historyEntries
            .filter { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }
            .sorted { $0.timestamp < $1.timestamp }

        var events: [DNSHistoryEvent] = []
        var previousARecords: [String] = []
        var previousNameservers: [String] = []

        for entry in domainHistory {
            let aRecords = Self.dnsValues(for: .A, in: entry.dnsSections)
            let nameservers = Self.dnsValues(for: .NS, in: entry.dnsSections)
            let summary = dnsSummaryChange(
                previousARecords: previousARecords,
                currentARecords: aRecords,
                previousNameservers: previousNameservers,
                currentNameservers: nameservers
            )

            if let summary {
                events.append(
                    DNSHistoryEvent(
                        date: entry.timestamp,
                        summary: summary,
                        aRecords: aRecords,
                        nameservers: nameservers,
                        source: "Local observations",
                        isExternal: false
                    )
                )
            }

            previousARecords = aRecords
            previousNameservers = nameservers
        }

        if events.isEmpty {
            let currentARecords = Self.dnsValues(for: .A, in: dnsSections)
            let currentNameservers = Self.dnsValues(for: .NS, in: dnsSections)
            if !currentARecords.isEmpty || !currentNameservers.isEmpty {
                events.append(
                    DNSHistoryEvent(
                        date: Date(),
                        summary: "Current DNS snapshot",
                        aRecords: currentARecords,
                        nameservers: currentNameservers,
                        source: "Local observations",
                        isExternal: false
                    )
                )
            }
        }

        return events.sorted { $0.date > $1.date }
    }

    private static func mergeOwnershipHistory(
        localEvents: [DomainOwnershipHistoryEvent],
        externalEvents: [DomainOwnershipHistoryEvent]
    ) -> ServiceResult<[DomainOwnershipHistoryEvent]> {
        let merged = (externalEvents + localEvents)
            .sorted { $0.date > $1.date }
            .reduce(into: [DomainOwnershipHistoryEvent]()) { partialResult, event in
                let duplicate = partialResult.contains {
                    $0.date == event.date
                        && $0.summary == event.summary
                        && $0.registrar == event.registrar
                        && $0.nameservers == event.nameservers
                }
                if !duplicate {
                    partialResult.append(event)
                }
            }

        return merged.isEmpty ? .empty("No ownership history available") : .success(merged)
    }

    private static func mergeDNSHistory(
        localEvents: [DNSHistoryEvent],
        externalEvents: [DNSHistoryEvent]
    ) -> ServiceResult<[DNSHistoryEvent]> {
        let merged = (externalEvents + localEvents)
            .sorted { $0.date > $1.date }
            .reduce(into: [DNSHistoryEvent]()) { partialResult, event in
                let duplicate = partialResult.contains {
                    $0.date == event.date
                        && $0.summary == event.summary
                        && $0.aRecords == event.aRecords
                        && $0.nameservers == event.nameservers
                }
                if !duplicate {
                    partialResult.append(event)
                }
            }

        return merged.isEmpty ? .empty("No DNS history available") : .success(merged)
    }

    private static func mergeSubdomains(
        primary: [DiscoveredSubdomain],
        additional: [DiscoveredSubdomain]
    ) -> [DiscoveredSubdomain] {
        var seen = Set(primary.map { $0.hostname.lowercased() })
        var merged = primary

        for subdomain in additional where seen.insert(subdomain.hostname.lowercased()).inserted {
            merged.append(subdomain)
        }

        return merged.sorted { $0.hostname < $1.hostname }
    }

    private static func ownershipSummaryChange(previous: DomainOwnership?, current: DomainOwnership) -> String? {
        guard let previous else {
            return "Initial ownership observation"
        }

        var changes: [String] = []
        if previous.registrar != current.registrar {
            changes.append("Registrar changed")
        }
        if previous.registrant != current.registrant, current.registrant != nil {
            changes.append("Ownership changed")
        }
        if previous.nameservers != current.nameservers {
            changes.append("Nameservers changed")
        }

        return changes.isEmpty ? nil : changes.joined(separator: " • ")
    }

    private static func dnsSummaryChange(
        previousARecords: [String],
        currentARecords: [String],
        previousNameservers: [String],
        currentNameservers: [String]
    ) -> String? {
        var changes: [String] = []
        if previousARecords != currentARecords, !currentARecords.isEmpty {
            changes.append("A records changed")
        }
        if previousNameservers != currentNameservers, !currentNameservers.isEmpty {
            changes.append("NS records changed")
        }
        if previousARecords.isEmpty && previousNameservers.isEmpty && (!currentARecords.isEmpty || !currentNameservers.isEmpty) {
            changes.append("Initial DNS observation")
        }
        return changes.isEmpty ? nil : changes.joined(separator: " • ")
    }

    private static func url(from template: String, domain: String) -> URL? {
        URL(string: template.replacingOccurrences(of: "{domain}", with: domain))
    }

    private static func normalize(_ domain: String) -> String {
        domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func dnsValues(for type: DNSRecordType, in sections: [DNSSection]) -> [String] {
        sections
            .first(where: { $0.recordType == type })?
            .records
            .map(\.value)
            .sorted() ?? []
    }

    private static let iso8601DateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}
