import Foundation

struct CachedLookupResult<Value> {
    let value: Value
    let source: LookupResultSource
}

actor LookupRuntime {
    static let shared = LookupRuntime()

    private let ttl: TimeInterval = 300

    private enum RequestKey: Hashable {
        case domain(String, LookupSectionKind)
        case subject(String, LookupSectionKind)
    }

    private enum RateLimitBucket: Hashable {
        case crtsh
        case rdap
        case ipGeolocation

        var minimumSpacing: TimeInterval {
            switch self {
            case .crtsh:
                return 1.0
            case .rdap:
                return 0.75
            case .ipGeolocation:
                return 0.75
            }
        }
    }

    private enum CachedPayload {
        case dns(ServiceResult<[DNSSection]>)
        case availability(DomainAvailabilityResult)
        case ssl(ServiceResult<SSLCertificateInfo>)
        case hsts(Bool?)
        case http(ServiceResult<HTTPHeadersResult>)
        case reachability(ServiceResult<[PortReachability]>)
        case ownership(ServiceResult<DomainOwnership>)
        case redirect(ServiceResult<[RedirectHop]>)
        case subdomains(ServiceResult<[DiscoveredSubdomain]>)
        case portScan(ServiceResult<[PortScanResult]>)
        case email(ServiceResult<EmailSecurityResult>)
        case ptr(ServiceResult<String>)
        case ipGeolocation(ServiceResult<IPGeolocation>)
        case suggestions([DomainSuggestionResult])
    }

    private struct CacheEntry {
        let payload: CachedPayload
        let expiresAt: Date
    }

    private var cache: [RequestKey: CacheEntry] = [:]
    private var inFlight: [RequestKey: Task<CachedPayload, Never>] = [:]
    private var nextAllowedAt: [RateLimitBucket: Date] = [:]

    func clearCache() {
        cache.removeAll()
        inFlight.values.forEach { $0.cancel() }
        inFlight.removeAll()
        nextAllowedAt.removeAll()
    }

    func dns(domain: String) async -> CachedLookupResult<ServiceResult<[DNSSection]>> {
        await execute(
            key: .domain(domain, .dns),
            extract: { payload in
                guard case let .dns(result) = payload else { return nil }
                return result
            },
            operation: {
                .dns(await DNSLookupService.lookupAll(domain: domain))
            }
        )
    }

    func availability(domain: String) async -> CachedLookupResult<DomainAvailabilityResult> {
        CachedLookupResult(
            value: await DomainAvailabilityService.check(domain: domain),
            source: .live
        )
    }

    func ssl(domain: String) async -> CachedLookupResult<ServiceResult<SSLCertificateInfo>> {
        await execute(
            key: .domain(domain, .ssl),
            extract: { payload in
                guard case let .ssl(result) = payload else { return nil }
                return result
            },
            operation: {
                .ssl(await SSLCheckService.check(domain: domain))
            }
        )
    }

    func hsts(domain: String) async -> CachedLookupResult<Bool?> {
        await execute(
            key: .domain(domain, .hsts),
            extract: { payload in
                guard case let .hsts(result) = payload else { return nil }
                return result
            },
            operation: {
                .hsts(await SSLCheckService.checkHSTSPreload(domain: domain))
            }
        )
    }

    func http(domain: String) async -> CachedLookupResult<ServiceResult<HTTPHeadersResult>> {
        await execute(
            key: .domain(domain, .httpHeaders),
            extract: { payload in
                guard case let .http(result) = payload else { return nil }
                return result
            },
            operation: {
                .http(await HTTPHeadersService.fetch(domain: domain))
            }
        )
    }

    func reachability(domain: String) async -> CachedLookupResult<ServiceResult<[PortReachability]>> {
        await execute(
            key: .domain(domain, .reachability),
            extract: { payload in
                guard case let .reachability(result) = payload else { return nil }
                return result
            },
            operation: {
                .reachability(await ReachabilityService.checkAll(domain: domain))
            }
        )
    }

    func ownership(domain: String) async -> CachedLookupResult<ServiceResult<DomainOwnership>> {
        await execute(
            key: .domain(domain, .ownership),
            rateLimitBucket: .rdap,
            extract: { payload in
                guard case let .ownership(result) = payload else { return nil }
                return result
            },
            operation: {
                .ownership(await DomainOwnershipService.lookup(domain: domain))
            }
        )
    }

    func redirectChain(domain: String) async -> CachedLookupResult<ServiceResult<[RedirectHop]>> {
        await execute(
            key: .domain(domain, .redirectChain),
            extract: { payload in
                guard case let .redirect(result) = payload else { return nil }
                return result
            },
            operation: {
                .redirect(await RedirectChainService.trace(domain: domain))
            }
        )
    }

    func subdomains(domain: String) async -> CachedLookupResult<ServiceResult<[DiscoveredSubdomain]>> {
        await execute(
            key: .domain(domain, .subdomains),
            rateLimitBucket: .crtsh,
            extract: { payload in
                guard case let .subdomains(result) = payload else { return nil }
                return result
            },
            operation: {
                .subdomains(await SubdomainDiscoveryService.discover(for: domain))
            }
        )
    }

    func portScan(domain: String) async -> CachedLookupResult<ServiceResult<[PortScanResult]>> {
        await execute(
            key: .domain(domain, .portScan),
            extract: { payload in
                guard case let .portScan(result) = payload else { return nil }
                return result
            },
            operation: {
                .portScan(await PortScanService.scanAll(domain: domain))
            }
        )
    }

    func email(domain: String, txtRecords: [DNSRecord]) async -> CachedLookupResult<ServiceResult<EmailSecurityResult>> {
        await execute(
            key: .domain(domain, .emailSecurity),
            extract: { payload in
                guard case let .email(result) = payload else { return nil }
                return result
            },
            operation: {
                .email(await EmailSecurityService.analyze(domain: domain, txtRecords: txtRecords))
            }
        )
    }

    func ptr(ip: String, resolverURLString: String) async -> CachedLookupResult<ServiceResult<String>> {
        await execute(
            key: .subject("\(resolverURLString)|\(ip)", .ptr),
            extract: { payload in
                guard case let .ptr(result) = payload else { return nil }
                return result
            },
            operation: {
                .ptr(await ReverseDNSService.lookup(ip: ip, resolverURLString: resolverURLString))
            }
        )
    }

    func ipGeolocation(ip: String) async -> CachedLookupResult<ServiceResult<IPGeolocation>> {
        await execute(
            key: .subject(ip, .ipGeolocation),
            rateLimitBucket: .ipGeolocation,
            extract: { payload in
                guard case let .ipGeolocation(result) = payload else { return nil }
                return result
            },
            operation: {
                .ipGeolocation(await IPGeolocationService.lookup(ip: ip))
            }
        )
    }

    func suggestions(domain: String) async -> CachedLookupResult<[DomainSuggestionResult]> {
        await execute(
            key: .domain(domain, .suggestions),
            extract: { payload in
                guard case let .suggestions(result) = payload else { return nil }
                return result
            },
            operation: {
                .suggestions(await DomainAvailabilityService.suggestions(for: domain))
            }
        )
    }

    private func execute<T>(
        key: RequestKey,
        rateLimitBucket: RateLimitBucket? = nil,
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
            if let rateLimitBucket {
                await self.enforceRateLimit(for: rateLimitBucket)
            }
            return await operation()
        }
        inFlight[key] = task

        let payload = await task.value
        cache[key] = CacheEntry(payload: payload, expiresAt: Date().addingTimeInterval(ttl))
        inFlight[key] = nil

        guard let value = extract(payload) else {
            fatalError("LookupRuntime payload extraction mismatch")
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
}
