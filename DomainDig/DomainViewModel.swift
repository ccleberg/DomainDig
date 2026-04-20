import Foundation
import SwiftUI

enum ResultTone {
    case primary
    case secondary
    case success
    case warning
    case failure
}

struct SummaryFieldViewData: Identifiable {
    let id = UUID()
    let label: String
    let value: String
    let tone: ResultTone
}

struct InfoRowViewData: Identifiable {
    let id = UUID()
    let label: String
    let value: String
    let tone: ResultTone
}

struct SectionMessageViewData {
    let text: String
    let isError: Bool
}

struct DNSRecordSectionViewData: Identifiable {
    let id = UUID()
    let title: String
    let rows: [InfoRowViewData]
    let wildcardRows: [InfoRowViewData]
    let wildcardTitle: String?
    let message: SectionMessageViewData?
}

struct EmailRowViewData: Identifiable {
    let id = UUID()
    let label: String
    let status: String
    let statusTone: ResultTone
    let detail: String
    let auxiliaryDetail: String?
}

struct RedirectHopViewData: Identifiable {
    let id = UUID()
    let stepLabel: String
    let statusCode: String
    let url: String
    let isFinal: Bool
}

struct ReachabilityRowViewData: Identifiable {
    let id = UUID()
    let portLabel: String
    let latencyLabel: String
    let statusLabel: String
    let statusTone: ResultTone
}

struct PortScanRowViewData: Identifiable {
    let id = UUID()
    let portLabel: String
    let service: String
    let statusLabel: String
    let statusTone: ResultTone
    let banner: String?
    let durationLabel: String?
}

struct LookupSnapshot {
    let domain: String
    let timestamp: Date
    let resolverDisplayName: String
    let resolverURLString: String
    let totalLookupDurationMs: Int?
    let dnsSections: [DNSSection]
    let dnsError: String?
    let sslInfo: SSLCertificateInfo?
    let sslError: String?
    let hstsPreloaded: Bool?
    let httpHeaders: [HTTPHeader]
    let httpSecurityGrade: String?
    let httpStatusCode: Int?
    let httpResponseTimeMs: Int?
    let httpProtocol: String?
    let http3Advertised: Bool
    let httpHeadersError: String?
    let reachabilityResults: [PortReachability]
    let reachabilityError: String?
    let ipGeolocation: IPGeolocation?
    let ipGeolocationError: String?
    let emailSecurity: EmailSecurityResult?
    let emailSecurityError: String?
    let ptrRecord: String?
    let ptrError: String?
    let redirectChain: [RedirectHop]
    let redirectChainError: String?
    let portScanResults: [PortScanResult]
    let portScanError: String?
    let isLive: Bool
}

extension HistoryEntry {
    var snapshot: LookupSnapshot {
        LookupSnapshot(
            domain: domain,
            timestamp: timestamp,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: totalLookupDurationMs,
            dnsSections: dnsSections,
            dnsError: nil,
            sslInfo: sslInfo,
            sslError: sslError,
            hstsPreloaded: hstsPreloaded,
            httpHeaders: httpHeaders,
            httpSecurityGrade: HTTPSecurityGrade.grade(for: httpHeaders).rawValue,
            httpStatusCode: nil,
            httpResponseTimeMs: nil,
            httpProtocol: nil,
            http3Advertised: false,
            httpHeadersError: httpHeadersError,
            reachabilityResults: reachabilityResults,
            reachabilityError: reachabilityError,
            ipGeolocation: ipGeolocation,
            ipGeolocationError: ipGeolocationError,
            emailSecurity: emailSecurity,
            emailSecurityError: emailSecurityError,
            ptrRecord: ptrRecord,
            ptrError: ptrError,
            redirectChain: redirectChain,
            redirectChainError: redirectChainError,
            portScanResults: portScanResults,
            portScanError: portScanError,
            isLive: false
        )
    }
}

@MainActor
@Observable
final class DomainViewModel {
    var domain: String = ""

    var dnsSections: [DNSSection] = []
    var dnsLoading = false
    var dnsError: String?

    var sslInfo: SSLCertificateInfo?
    var sslLoading = false
    var sslError: String?
    var hstsPreloaded: Bool?
    var hstsLoading = false

    var httpHeaders: [HTTPHeader] = []
    var httpSecurityGrade: String?
    var httpStatusCode: Int?
    var httpResponseTimeMs: Int?
    var httpProtocol: String?
    var http3Advertised = false
    var httpHeadersLoading = false
    var httpHeadersError: String?

    var reachabilityResults: [PortReachability] = []
    var reachabilityLoading = false
    var reachabilityError: String?

    var ipGeolocation: IPGeolocation?
    var ipGeolocationLoading = false
    var ipGeolocationError: String?

    var emailSecurity: EmailSecurityResult?
    var emailSecurityLoading = false
    var emailSecurityError: String?

    var ptrRecord: String?
    var ptrLoading = false
    var ptrError: String?

    var redirectChain: [RedirectHop] = []
    var redirectChainLoading = false
    var redirectChainError: String?

    var portScanResults: [PortScanResult] = []
    var portScanLoading = false
    var portScanError: String?
    var customPortResults: [PortScanResult] = []
    var customPortScanLoading = false
    var customPortScanError: String?

    var hasRun = false
    private(set) var searchedDomain: String = ""
    private(set) var lastLookupDurationMs: Int?

    private var lookupTask: Task<Void, Never>?
    private var customPortScanTask: Task<Void, Never>?
    private var activeLookupID = UUID()
    private var lookupStartedAt: Date?

    private static let recentSearchesKey = "recentSearches"
    private static let maxRecent = 20
    var recentSearches: [String] = UserDefaults.standard.stringArray(forKey: recentSearchesKey) ?? []

    private static let savedDomainsKey = "savedDomains"
    var savedDomains: [String] = UserDefaults.standard.stringArray(forKey: savedDomainsKey) ?? []

    private static let historyKey = "lookupHistory"
    private static let maxHistory = 50
    var history: [HistoryEntry] = {
        guard let data = UserDefaults.standard.data(forKey: historyKey),
              let entries = try? JSONDecoder().decode([HistoryEntry].self, from: data) else {
            return []
        }
        return entries
    }()

    var trimmedDomain: String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .components(separatedBy: "/").first ?? ""
    }

    var resultsLoaded: Bool {
        hasRun &&
            !dnsLoading &&
            !sslLoading &&
            !hstsLoading &&
            !httpHeadersLoading &&
            !reachabilityLoading &&
            !ipGeolocationLoading &&
            !emailSecurityLoading &&
            !ptrLoading &&
            !redirectChainLoading &&
            !portScanLoading &&
            !customPortScanLoading
    }

    var isCloudflareProxied: Bool {
        httpHeaders.contains { $0.name.lowercased() == "cf-ray" }
    }

    var isCurrentDomainSaved: Bool {
        !searchedDomain.isEmpty && savedDomains.contains(where: { $0.lowercased() == searchedDomain.lowercased() })
    }

    var resolverDisplayName: String {
        DNSLookupService.currentResolverDisplayName()
    }

    var resolverURLString: String {
        DNSLookupService.currentResolverURLString()
    }

    var allPortScanResults: [PortScanResult] {
        (portScanResults + customPortResults).sorted {
            if $0.kind == $1.kind {
                return $0.port < $1.port
            }
            return $0.kind == .standard
        }
    }

    var currentSnapshot: LookupSnapshot {
        LookupSnapshot(
            domain: searchedDomain,
            timestamp: Date(),
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: lastLookupDurationMs,
            dnsSections: dnsSections,
            dnsError: dnsError,
            sslInfo: sslInfo,
            sslError: sslError,
            hstsPreloaded: hstsPreloaded,
            httpHeaders: httpHeaders,
            httpSecurityGrade: httpSecurityGrade,
            httpStatusCode: httpStatusCode,
            httpResponseTimeMs: httpResponseTimeMs,
            httpProtocol: httpProtocol,
            http3Advertised: http3Advertised,
            httpHeadersError: httpHeadersError,
            reachabilityResults: reachabilityResults,
            reachabilityError: reachabilityError,
            ipGeolocation: ipGeolocation,
            ipGeolocationError: ipGeolocationError,
            emailSecurity: emailSecurity,
            emailSecurityError: emailSecurityError,
            ptrRecord: ptrRecord,
            ptrError: ptrError,
            redirectChain: redirectChain,
            redirectChainError: redirectChainError,
            portScanResults: allPortScanResults,
            portScanError: combinedPortScanError,
            isLive: true
        )
    }

    var summaryFields: [SummaryFieldViewData] {
        Self.summaryFields(from: currentSnapshot)
    }

    var domainRows: [InfoRowViewData] {
        Self.domainRows(from: currentSnapshot)
    }

    var dnsRows: [DNSRecordSectionViewData] {
        Self.dnsRows(from: currentSnapshot)
    }

    var dnssecLabel: String? {
        Self.dnssecLabel(from: currentSnapshot)
    }

    var ptrMessage: SectionMessageViewData? {
        Self.ptrMessage(from: currentSnapshot)
    }

    var webCertificateRows: [InfoRowViewData] {
        Self.webCertificateRows(from: currentSnapshot)
    }

    var webResponseRows: [InfoRowViewData] {
        Self.webResponseRows(from: currentSnapshot)
    }

    var redirectRows: [RedirectHopViewData] {
        Self.redirectRows(from: currentSnapshot)
    }

    var emailRows: [EmailRowViewData] {
        Self.emailRows(from: currentSnapshot)
    }

    var reachabilityRows: [ReachabilityRowViewData] {
        Self.reachabilityRows(from: currentSnapshot)
    }

    var locationRows: [InfoRowViewData] {
        Self.locationRows(from: currentSnapshot)
    }

    var standardPortRows: [PortScanRowViewData] {
        Self.portRows(from: currentSnapshot, kind: .standard)
    }

    var customPortRows: [PortScanRowViewData] {
        Self.portRows(from: currentSnapshot, kind: .custom)
    }

    var combinedPortScanError: String? {
        [portScanError, customPortScanError].compactMap { $0 }.joined(separator: "\n").nilIfEmpty
    }

    func toggleSavedDomain() {
        if isCurrentDomainSaved {
            savedDomains.removeAll { $0.lowercased() == searchedDomain.lowercased() }
        } else {
            savedDomains.append(searchedDomain)
        }
        UserDefaults.standard.set(savedDomains, forKey: Self.savedDomainsKey)
    }

    func removeSavedDomains(at offsets: IndexSet) {
        savedDomains.remove(atOffsets: offsets)
        UserDefaults.standard.set(savedDomains, forKey: Self.savedDomainsKey)
    }

    func removeHistoryEntries(at offsets: IndexSet) {
        history.remove(atOffsets: offsets)
        persistHistory()
    }

    func clearRecentSearches() {
        recentSearches.removeAll()
        UserDefaults.standard.removeObject(forKey: Self.recentSearchesKey)
    }

    func rerunLookup(from entry: HistoryEntry) {
        UserDefaults.standard.set(entry.resolverURLString, forKey: DNSResolverOption.userDefaultsKey)
        domain = entry.domain
        run()
    }

    func reset() {
        lookupTask?.cancel()
        customPortScanTask?.cancel()
        hasRun = false
        searchedDomain = ""
        lastLookupDurationMs = nil
        clearLookupState()
    }

    func run() {
        let target = trimmedDomain
        guard !target.isEmpty else { return }

        lookupTask?.cancel()
        customPortScanTask?.cancel()

        let lookupID = UUID()
        activeLookupID = lookupID
        lookupStartedAt = Date()
        lastLookupDurationMs = nil
        addRecentSearch(target)
        searchedDomain = target
        hasRun = true
        clearLookupState()
        setAllLoadingStates(true)
        customPortScanLoading = false

        lookupTask = Task { [weak self] in
            guard let self else { return }
            await self.performLookup(domain: target, lookupID: lookupID)
        }
    }

    func runCustomPortScan(ports: [UInt16]) async {
        guard !searchedDomain.isEmpty else {
            customPortScanError = "Run a domain lookup first"
            return
        }

        guard !ports.isEmpty else {
            customPortScanError = "Enter at least one valid port"
            customPortResults = []
            return
        }

        customPortScanTask?.cancel()
        let domain = searchedDomain
        let lookupID = activeLookupID

        customPortScanLoading = true
        customPortScanError = nil
        customPortResults = []

        customPortScanTask = Task { [weak self] in
            guard let self else { return }
            let result = await PortScanService.scanPorts(domain: domain, ports: ports, timeout: 3.0)
            guard !Task.isCancelled, self.isCurrentLookup(lookupID) else { return }
            self.applyCustomPortResult(result)
        }
    }

    func exportText() -> String {
        Self.formatExportText(from: currentSnapshot)
    }

    private func performLookup(domain: String, lookupID: UUID) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.runDNS(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runSSL(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runHSTSPreload(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runHTTPHeaders(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runReachability(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runRedirectChain(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runPortScan(domain: domain, lookupID: lookupID) }
        }

        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }

        let txtRecords = dnsSections.first(where: { $0.recordType == .TXT })?.records ?? []
        let primaryIP = primaryIPAddress(from: dnsSections)

        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.runEmailSecurity(domain: domain, txtRecords: txtRecords, lookupID: lookupID) }
            if let primaryIP {
                group.addTask { await self.runReverseDNS(ip: primaryIP, lookupID: lookupID) }
                group.addTask { await self.runIPGeolocation(ip: primaryIP, lookupID: lookupID) }
            } else {
                group.addTask { await self.finishDependentWithoutPrimaryIP(lookupID: lookupID) }
            }
        }

        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        lastLookupDurationMs = lookupStartedAt.map { Int(Date().timeIntervalSince($0) * 1000) }
        saveHistoryEntry(replaceLatest: false)
    }

    private func runDNS(domain: String, lookupID: UUID) async {
        let result = await DNSLookupService.lookupAll(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(sections):
            dnsSections = sections
            dnsError = nil
        case let .empty(message):
            dnsSections = []
            dnsError = message
        case let .error(message):
            dnsSections = []
            dnsError = message
        }
        dnsLoading = false
    }

    private func runSSL(domain: String, lookupID: UUID) async {
        let result = await SSLCheckService.check(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(info):
            sslInfo = info
            sslError = nil
        case let .empty(message):
            sslInfo = nil
            sslError = message
        case let .error(message):
            sslInfo = nil
            sslError = message
        }
        sslLoading = false
    }

    private func runHSTSPreload(domain: String, lookupID: UUID) async {
        let result = await SSLCheckService.checkHSTSPreload(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        hstsPreloaded = result
        hstsLoading = false
    }

    private func runHTTPHeaders(domain: String, lookupID: UUID) async {
        let result = await HTTPHeadersService.fetch(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(headersResult):
            httpHeaders = headersResult.headers
            httpSecurityGrade = HTTPSecurityGrade.grade(for: headersResult.headers).rawValue
            httpStatusCode = headersResult.statusCode
            httpResponseTimeMs = headersResult.responseTimeMs
            httpProtocol = headersResult.httpProtocol
            http3Advertised = headersResult.http3Advertised
            httpHeadersError = nil
        case let .empty(message):
            httpHeaders = []
            httpSecurityGrade = nil
            httpStatusCode = nil
            httpResponseTimeMs = nil
            httpProtocol = nil
            http3Advertised = false
            httpHeadersError = message
        case let .error(message):
            httpHeaders = []
            httpSecurityGrade = nil
            httpStatusCode = nil
            httpResponseTimeMs = nil
            httpProtocol = nil
            http3Advertised = false
            httpHeadersError = message
        }
        httpHeadersLoading = false
    }

    private func runReachability(domain: String, lookupID: UUID) async {
        let result = await ReachabilityService.checkAll(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(results):
            reachabilityResults = results
            reachabilityError = nil
        case let .empty(message):
            reachabilityResults = []
            reachabilityError = message
        case let .error(message):
            reachabilityResults = []
            reachabilityError = message
        }
        reachabilityLoading = false
    }

    private func runEmailSecurity(domain: String, txtRecords: [DNSRecord], lookupID: UUID) async {
        let result = await EmailSecurityService.analyze(domain: domain, txtRecords: txtRecords)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(emailResult):
            emailSecurity = emailResult
            emailSecurityError = nil
        case let .empty(message):
            emailSecurity = nil
            emailSecurityError = message
        case let .error(message):
            emailSecurity = nil
            emailSecurityError = message
        }
        emailSecurityLoading = false
    }

    private func runReverseDNS(ip: String, lookupID: UUID) async {
        let result = await ReverseDNSService.lookup(ip: ip, resolverURLString: resolverURLString)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(record):
            ptrRecord = record
            ptrError = nil
        case let .empty(message):
            ptrRecord = nil
            ptrError = message
        case let .error(message):
            ptrRecord = nil
            ptrError = message
        }
        ptrLoading = false
    }

    private func runRedirectChain(domain: String, lookupID: UUID) async {
        let result = await RedirectChainService.trace(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(hops):
            redirectChain = hops
            redirectChainError = nil
        case let .empty(message):
            redirectChain = []
            redirectChainError = message
        case let .error(message):
            redirectChain = []
            redirectChainError = message
        }
        redirectChainLoading = false
    }

    private func runPortScan(domain: String, lookupID: UUID) async {
        let result = await PortScanService.scanAll(domain: domain)
        switch result {
        case let .success(results):
            let enrichedResults = await enrichOpenPortBanners(in: results, domain: domain)
            guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
            portScanResults = enrichedResults
            portScanError = nil
        case let .empty(message):
            guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
            portScanResults = []
            portScanError = message
        case let .error(message):
            guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
            portScanResults = []
            portScanError = message
        }
        portScanLoading = false
    }

    private func runIPGeolocation(ip: String, lookupID: UUID) async {
        let result = await IPGeolocationService.lookup(ip: ip)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        switch result {
        case let .success(geolocation):
            ipGeolocation = geolocation
            ipGeolocationError = nil
        case let .empty(message):
            ipGeolocation = nil
            ipGeolocationError = message
        case let .error(message):
            ipGeolocation = nil
            ipGeolocationError = message
        }
        ipGeolocationLoading = false
    }

    private func finishDependentWithoutPrimaryIP(lookupID: UUID) async {
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        ptrLoading = false
        ptrError = "No A record available"
        ipGeolocationLoading = false
        ipGeolocationError = "No A record available"
    }

    private func applyCustomPortResult(_ result: ServiceResult<[PortScanResult]>) {
        switch result {
        case let .success(results):
            customPortResults = results
            customPortScanError = nil
            saveHistoryEntry(replaceLatest: true)
        case let .empty(message):
            customPortResults = []
            customPortScanError = message
        case let .error(message):
            customPortResults = []
            customPortScanError = message
        }
        customPortScanLoading = false
    }

    private func enrichOpenPortBanners(in results: [PortScanResult], domain: String) async -> [PortScanResult] {
        let banners = await withTaskGroup(of: (UInt16, String?).self, returning: [UInt16: String].self) { group in
            for result in results where result.open {
                group.addTask {
                    let banner = await PortScanService.grabBanner(host: domain, port: result.port)
                    return (result.port, banner)
                }
            }

            var collected: [UInt16: String] = [:]
            for await (port, banner) in group {
                if let banner {
                    collected[port] = banner
                }
            }
            return collected
        }

        return results.map { result in
            var updated = result
            updated.banner = banners[result.port]
            return updated
        }
    }

    private func saveHistoryEntry(replaceLatest: Bool) {
        guard !searchedDomain.isEmpty else { return }
        let entry = HistoryEntry(
            domain: searchedDomain,
            timestamp: Date(),
            dnsSections: dnsSections,
            sslInfo: sslInfo,
            httpHeaders: httpHeaders,
            reachabilityResults: reachabilityResults,
            ipGeolocation: ipGeolocation,
            emailSecurity: emailSecurity,
            mtaSts: emailSecurity?.mtaSts,
            ptrRecord: ptrRecord,
            redirectChain: redirectChain,
            portScanResults: allPortScanResults,
            hstsPreloaded: hstsPreloaded,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: lastLookupDurationMs,
            sslError: sslError,
            httpHeadersError: httpHeadersError,
            reachabilityError: reachabilityError,
            ipGeolocationError: ipGeolocationError,
            emailSecurityError: emailSecurityError,
            ptrError: ptrError,
            redirectChainError: redirectChainError,
            portScanError: combinedPortScanError
        )

        if replaceLatest, !history.isEmpty, history[0].domain.caseInsensitiveCompare(searchedDomain) == .orderedSame {
            history[0] = entry
        } else {
            history.insert(entry, at: 0)
            if history.count > Self.maxHistory {
                history = Array(history.prefix(Self.maxHistory))
            }
        }
        persistHistory()
    }

    private func persistHistory() {
        if let data = try? JSONEncoder().encode(history) {
            UserDefaults.standard.set(data, forKey: Self.historyKey)
        }
    }

    private func addRecentSearch(_ domain: String) {
        recentSearches.removeAll { $0.lowercased() == domain.lowercased() }
        recentSearches.insert(domain, at: 0)
        if recentSearches.count > Self.maxRecent {
            recentSearches = Array(recentSearches.prefix(Self.maxRecent))
        }
        UserDefaults.standard.set(recentSearches, forKey: Self.recentSearchesKey)
    }

    private func clearLookupState() {
        dnsSections = []
        dnsError = nil
        dnsLoading = false
        sslInfo = nil
        sslError = nil
        sslLoading = false
        hstsPreloaded = nil
        hstsLoading = false
        httpHeaders = []
        httpSecurityGrade = nil
        httpStatusCode = nil
        httpResponseTimeMs = nil
        httpProtocol = nil
        http3Advertised = false
        httpHeadersError = nil
        httpHeadersLoading = false
        reachabilityResults = []
        reachabilityError = nil
        reachabilityLoading = false
        ipGeolocation = nil
        ipGeolocationError = nil
        ipGeolocationLoading = false
        emailSecurity = nil
        emailSecurityError = nil
        emailSecurityLoading = false
        ptrRecord = nil
        ptrError = nil
        ptrLoading = false
        redirectChain = []
        redirectChainError = nil
        redirectChainLoading = false
        portScanResults = []
        portScanError = nil
        portScanLoading = false
        customPortResults = []
        customPortScanError = nil
        customPortScanLoading = false
    }

    private func setAllLoadingStates(_ loading: Bool) {
        dnsLoading = loading
        sslLoading = loading
        hstsLoading = loading
        httpHeadersLoading = loading
        reachabilityLoading = loading
        ipGeolocationLoading = loading
        emailSecurityLoading = loading
        ptrLoading = loading
        redirectChainLoading = loading
        portScanLoading = loading
    }

    private func primaryIPAddress(from sections: [DNSSection]) -> String? {
        sections.first(where: { $0.recordType == .A })?.records.first?.value
    }

    private func isCurrentLookup(_ lookupID: UUID) -> Bool {
        activeLookupID == lookupID
    }

    static func summaryFields(from snapshot: LookupSnapshot) -> [SummaryFieldViewData] {
        [
            SummaryFieldViewData(label: "Domain", value: snapshot.domain.nonEmpty ?? "Unavailable", tone: .primary),
            SummaryFieldViewData(label: "Primary IP", value: primaryIPAddress(from: snapshot) ?? "Unavailable", tone: .primary),
            SummaryFieldViewData(label: "HTTPS", value: httpsSummary(from: snapshot), tone: httpsSummaryTone(from: snapshot)),
            SummaryFieldViewData(label: "Redirect", value: finalRedirectTarget(from: snapshot) ?? "Unavailable", tone: .secondary),
            SummaryFieldViewData(label: "Email", value: emailSummary(from: snapshot), tone: .secondary)
        ]
    }

    static func domainRows(from snapshot: LookupSnapshot) -> [InfoRowViewData] {
        [
            InfoRowViewData(label: "Domain", value: snapshot.domain, tone: .primary),
            InfoRowViewData(label: "Resolver", value: snapshot.resolverDisplayName, tone: .secondary),
            InfoRowViewData(label: snapshot.isLive ? "Result" : "Snapshot", value: snapshot.isLive ? "Live" : "Snapshot", tone: snapshot.isLive ? .success : .warning),
            InfoRowViewData(label: "Lookup Duration", value: durationLabel(snapshot.totalLookupDurationMs), tone: .secondary)
        ]
    }

    static func dnsRows(from snapshot: LookupSnapshot) -> [DNSRecordSectionViewData] {
        snapshot.dnsSections.map { section in
            DNSRecordSectionViewData(
                title: section.recordType.rawValue,
                rows: section.records.map { InfoRowViewData(label: "TTL \($0.ttl)", value: $0.value, tone: .primary) },
                wildcardRows: section.wildcardRecords.map { InfoRowViewData(label: "TTL \($0.ttl)", value: $0.value, tone: .primary) },
                wildcardTitle: section.wildcardRecords.isEmpty ? nil : "*.\(snapshot.domain)",
                message: section.error.map { SectionMessageViewData(text: $0, isError: true) } ??
                    ((section.records.isEmpty && section.wildcardRecords.isEmpty) ? SectionMessageViewData(text: "No records found", isError: false) : nil)
            )
        }
    }

    static func dnssecLabel(from snapshot: LookupSnapshot) -> String? {
        guard let signed = snapshot.dnsSections.compactMap(\.dnssecSigned).first else { return nil }
        return "Resolver-reported DNSSEC (not full validation): \(signed ? "Yes" : "No")"
    }

    static func ptrMessage(from snapshot: LookupSnapshot) -> SectionMessageViewData? {
        if let ptrRecord = snapshot.ptrRecord {
            return SectionMessageViewData(text: ptrRecord, isError: false)
        }
        if let ptrError = snapshot.ptrError {
            return SectionMessageViewData(text: ptrError, isError: ptrError != "No A record available" && ptrError != "No PTR record found")
        }
        return nil
    }

    static func webCertificateRows(from snapshot: LookupSnapshot) -> [InfoRowViewData] {
        guard let sslInfo = snapshot.sslInfo else { return [] }
        var rows = [
            InfoRowViewData(label: "Common Name", value: sslInfo.commonName, tone: .primary),
            InfoRowViewData(label: "Issuer", value: sslInfo.issuer, tone: .primary),
            InfoRowViewData(label: "Valid From", value: DateFormatter.certDate.string(from: sslInfo.validFrom), tone: .secondary),
            InfoRowViewData(label: "Valid Until", value: DateFormatter.certDate.string(from: sslInfo.validUntil), tone: .secondary),
            InfoRowViewData(label: "Days Until Expiry", value: "\(sslInfo.daysUntilExpiry)", tone: sslInfo.daysUntilExpiry < 30 ? .failure : (sslInfo.daysUntilExpiry < 60 ? .warning : .success)),
            InfoRowViewData(label: "Chain Depth", value: "\(sslInfo.chainDepth)", tone: .secondary)
        ]
        if let tlsVersion = sslInfo.tlsVersion {
            rows.append(InfoRowViewData(label: "TLS Version", value: tlsVersion, tone: .secondary))
        }
        if let cipherSuite = sslInfo.cipherSuite {
            rows.append(InfoRowViewData(label: "Cipher Suite", value: cipherSuite, tone: .secondary))
        }
        if let hstsPreloaded = snapshot.hstsPreloaded {
            rows.append(InfoRowViewData(label: "HSTS Preload", value: hstsPreloaded ? "Preloaded" : "Not preloaded", tone: hstsPreloaded ? .success : .secondary))
        }
        return rows
    }

    static func webResponseRows(from snapshot: LookupSnapshot) -> [InfoRowViewData] {
        var rows: [InfoRowViewData] = []
        if let httpStatusCode = snapshot.httpStatusCode {
            rows.append(InfoRowViewData(label: "Status", value: "\(httpStatusCode)", tone: .primary))
        }
        if let httpResponseTimeMs = snapshot.httpResponseTimeMs {
            rows.append(InfoRowViewData(label: "Response Time", value: "\(httpResponseTimeMs) ms", tone: .secondary))
        }
        if let httpProtocol = snapshot.httpProtocol {
            rows.append(InfoRowViewData(label: "Protocol", value: httpProtocol, tone: .secondary))
        }
        if let httpSecurityGrade = snapshot.httpSecurityGrade {
            rows.append(InfoRowViewData(label: "Security Grade", value: httpSecurityGrade, tone: securityGradeTone(httpSecurityGrade)))
        }
        if snapshot.http3Advertised {
            rows.append(InfoRowViewData(label: "HTTP/3", value: "Advertised", tone: .secondary))
        }
        return rows
    }

    static func redirectRows(from snapshot: LookupSnapshot) -> [RedirectHopViewData] {
        snapshot.redirectChain.map {
            RedirectHopViewData(
                stepLabel: "\($0.stepNumber)",
                statusCode: "\($0.statusCode)",
                url: $0.url,
                isFinal: $0.isFinal
            )
        }
    }

    static func emailRows(from snapshot: LookupSnapshot) -> [EmailRowViewData] {
        guard let emailSecurity = snapshot.emailSecurity else { return [] }
        return [
            EmailRowViewData(label: "SPF", status: emailSecurity.spf.found ? "Present" : "Missing", statusTone: emailSecurity.spf.found ? .success : .warning, detail: emailSecurity.spf.value ?? "No record found", auxiliaryDetail: nil),
            EmailRowViewData(label: "DMARC", status: emailSecurity.dmarc.found ? "Present" : "Missing", statusTone: emailSecurity.dmarc.found ? .success : .warning, detail: emailSecurity.dmarc.value ?? "No record found", auxiliaryDetail: nil),
            EmailRowViewData(label: "DKIM", status: emailSecurity.dkim.found ? "Present" : "Missing", statusTone: emailSecurity.dkim.found ? .success : .warning, detail: emailSecurity.dkim.value ?? "No record found", auxiliaryDetail: emailSecurity.dkim.matchedSelector.map { "Selector: \($0)" }),
            EmailRowViewData(label: "MTA-STS", status: emailSecurity.mtaSts?.txtFound == true ? "Present" : "Missing", statusTone: emailSecurity.mtaSts?.txtFound == true ? .success : .warning, detail: emailSecurity.mtaSts?.policyMode ?? (emailSecurity.mtaSts?.txtFound == true ? "Policy unavailable" : "No record found"), auxiliaryDetail: nil),
            EmailRowViewData(label: "BIMI", status: emailSecurity.bimi.found ? "Present" : "Missing", statusTone: emailSecurity.bimi.found ? .success : .warning, detail: emailSecurity.bimi.value ?? "No record found", auxiliaryDetail: nil)
        ]
    }

    static func reachabilityRows(from snapshot: LookupSnapshot) -> [ReachabilityRowViewData] {
        snapshot.reachabilityResults.map {
            ReachabilityRowViewData(
                portLabel: "Port \($0.port)",
                latencyLabel: $0.latencyMs.map { "\($0) ms" } ?? "—",
                statusLabel: $0.reachable ? "Reachable" : "Unreachable",
                statusTone: $0.reachable ? .success : .failure
            )
        }
    }

    static func locationRows(from snapshot: LookupSnapshot) -> [InfoRowViewData] {
        guard let ipGeolocation = snapshot.ipGeolocation else { return [] }
        var rows = [InfoRowViewData(label: "IP", value: ipGeolocation.ip, tone: .primary)]
        if let org = ipGeolocation.org {
            rows.append(InfoRowViewData(label: "Org / ISP", value: org, tone: .secondary))
        }
        let location = [ipGeolocation.city, ipGeolocation.region, ipGeolocation.country_name].compactMap { $0 }.joined(separator: ", ")
        if !location.isEmpty {
            rows.append(InfoRowViewData(label: "Location", value: location, tone: .secondary))
        }
        if let latitude = ipGeolocation.latitude, let longitude = ipGeolocation.longitude {
            rows.append(InfoRowViewData(label: "Coordinates", value: "\(latitude), \(longitude)", tone: .secondary))
        }
        return rows
    }

    static func portRows(from snapshot: LookupSnapshot, kind: PortScanKind) -> [PortScanRowViewData] {
        snapshot.portScanResults
            .filter { $0.kind == kind }
            .map {
                PortScanRowViewData(
                    portLabel: "\($0.port)",
                    service: $0.service,
                    statusLabel: $0.open ? "Open" : "Closed",
                    statusTone: $0.open ? .success : .secondary,
                    banner: $0.banner,
                    durationLabel: $0.durationMs.map { "\($0) ms" }
                )
            }
    }

    static func formatExportText(from snapshot: LookupSnapshot) -> String {
        let exportDateFormatter = DateFormatter()
        exportDateFormatter.dateFormat = "yyyy-MM-dd HH:mm"

        var lines: [String] = [
            "DomainDig Export",
            "Domain: \(snapshot.domain)",
            "Date: \(exportDateFormatter.string(from: snapshot.timestamp))",
            "Mode: \(snapshot.isLive ? "Live" : "Snapshot")",
            "Resolver: \(snapshot.resolverDisplayName)",
            "Lookup Duration: \(durationLabel(snapshot.totalLookupDurationMs))"
        ]

        func appendSection(_ title: String, body: () -> Void) {
            lines.append("")
            lines.append(title)
            lines.append(String(repeating: "-", count: title.count))
            body()
        }

        appendSection("Summary") {
            for item in summaryFields(from: snapshot) {
                lines.append("  \(item.label): \(item.value)")
            }
        }

        appendSection("Domain") {
            for row in domainRows(from: snapshot) {
                lines.append("  \(row.label): \(row.value)")
            }
        }

        appendSection("DNS") {
            if let dnsError = snapshot.dnsError {
                lines.append("  Error: \(dnsError)")
            }
            if let dnssecLabel = dnssecLabel(from: snapshot) {
                lines.append("  \(dnssecLabel)")
            }
            for section in dnsRows(from: snapshot) {
                lines.append("  \(section.title)")
                if let message = section.message {
                    lines.append("    \(message.isError ? "Error" : "Info"): \(message.text)")
                }
                for row in section.rows {
                    lines.append("    \(row.value) (\(row.label))")
                }
                if let wildcardTitle = section.wildcardTitle {
                    lines.append("    \(wildcardTitle)")
                    for row in section.wildcardRows {
                        lines.append("      \(row.value) (\(row.label))")
                    }
                }
            }
            if let ptrRecord = snapshot.ptrRecord {
                lines.append("  PTR: \(ptrRecord)")
            } else if let ptrError = snapshot.ptrError {
                lines.append("  PTR Error: \(ptrError)")
            }
        }

        appendSection("Web") {
            if let sslError = snapshot.sslError {
                lines.append("  TLS Error: \(sslError)")
            } else {
                for row in webCertificateRows(from: snapshot) {
                    lines.append("  \(row.label): \(row.value)")
                }
            }

            if let httpHeadersError = snapshot.httpHeadersError {
                lines.append("  Headers Error: \(httpHeadersError)")
            } else {
                for row in webResponseRows(from: snapshot) {
                    lines.append("  \(row.label): \(row.value)")
                }
                if snapshot.httpHeaders.isEmpty {
                    lines.append("  Headers: No headers returned")
                } else {
                    lines.append("  Headers:")
                    for header in snapshot.httpHeaders {
                        lines.append("    \(header.name): \(header.value)")
                    }
                }
            }

            if let redirectChainError = snapshot.redirectChainError {
                lines.append("  Redirect Error: \(redirectChainError)")
            } else if snapshot.redirectChain.isEmpty {
                lines.append("  Redirects: No redirect data available")
            } else {
                lines.append("  Redirects:")
                for hop in redirectRows(from: snapshot) {
                    lines.append("    \(hop.stepLabel). \(hop.statusCode) \(hop.url)\(hop.isFinal ? " (final)" : "")")
                }
            }
        }

        appendSection("Email") {
            if let emailSecurityError = snapshot.emailSecurityError {
                lines.append("  Error: \(emailSecurityError)")
            } else if emailRows(from: snapshot).isEmpty {
                lines.append("  No email security records found")
            } else {
                for row in emailRows(from: snapshot) {
                    lines.append("  \(row.label): \(row.status)")
                    lines.append("    \(row.detail)")
                    if let auxiliaryDetail = row.auxiliaryDetail {
                        lines.append("    \(auxiliaryDetail)")
                    }
                }
            }
        }

        appendSection("Network") {
            if let reachabilityError = snapshot.reachabilityError {
                lines.append("  Reachability Error: \(reachabilityError)")
            } else if reachabilityRows(from: snapshot).isEmpty {
                lines.append("  Reachability: No results")
            } else {
                lines.append("  Reachability:")
                for row in reachabilityRows(from: snapshot) {
                    lines.append("    \(row.portLabel): \(row.statusLabel) \(row.latencyLabel)")
                }
            }

            if let ipGeolocationError = snapshot.ipGeolocationError, snapshot.ipGeolocation == nil {
                lines.append("  Location Error: \(ipGeolocationError)")
            } else if locationRows(from: snapshot).isEmpty {
                lines.append("  Location: No data")
            } else {
                lines.append("  Location:")
                for row in locationRows(from: snapshot) {
                    lines.append("    \(row.label): \(row.value)")
                }
            }

            if let portScanError = snapshot.portScanError, snapshot.portScanResults.isEmpty {
                lines.append("  Port Scan Error: \(portScanError)")
            }

            lines.append("  Standard Ports:")
            let standardRows = portRows(from: snapshot, kind: .standard)
            if standardRows.isEmpty {
                lines.append("    No results")
            } else {
                for row in standardRows {
                    lines.append("    \(row.portLabel) \(row.service): \(row.statusLabel)\(row.durationLabel.map { " \($0)" } ?? "")")
                    if let banner = row.banner {
                        lines.append("      Banner: \(banner)")
                    }
                }
            }

            lines.append("  Custom Ports:")
            let customRows = portRows(from: snapshot, kind: .custom)
            if customRows.isEmpty {
                lines.append("    No results")
            } else {
                for row in customRows {
                    lines.append("    \(row.portLabel) \(row.service): \(row.statusLabel)\(row.durationLabel.map { " \($0)" } ?? "")")
                    if let banner = row.banner {
                        lines.append("      Banner: \(banner)")
                    }
                }
            }
        }

        return lines.joined(separator: "\n")
    }

    private static func primaryIPAddress(from snapshot: LookupSnapshot) -> String? {
        snapshot.dnsSections.first(where: { $0.recordType == .A })?.records.first?.value
    }

    private static func finalRedirectTarget(from snapshot: LookupSnapshot) -> String? {
        snapshot.redirectChain.last?.url
    }

    private static func httpsSummary(from snapshot: LookupSnapshot) -> String {
        if snapshot.sslInfo != nil {
            return "Valid"
        }
        if let sslError = snapshot.sslError {
            return sslError.localizedCaseInsensitiveContains("certificate") ? "Invalid" : "Failed"
        }
        return "Unavailable"
    }

    private static func httpsSummaryTone(from snapshot: LookupSnapshot) -> ResultTone {
        if snapshot.sslInfo != nil {
            return .success
        }
        return snapshot.sslError == nil ? .secondary : .failure
    }

    private static func emailSummary(from snapshot: LookupSnapshot) -> String {
        guard let emailSecurity = snapshot.emailSecurity else {
            return snapshot.emailSecurityError ?? "Unavailable"
        }
        return "SPF \(emailSecurity.spf.found ? "Yes" : "No") / DMARC \(emailSecurity.dmarc.found ? "Yes" : "No")"
    }

    private static func securityGradeTone(_ grade: String) -> ResultTone {
        switch grade {
        case "A", "B":
            return .success
        case "C":
            return .warning
        case "D", "F":
            return .failure
        default:
            return .secondary
        }
    }

    private static func durationLabel(_ durationMs: Int?) -> String {
        durationMs.map { "\($0) ms" } ?? "Unavailable"
    }
}

private extension String {
    var nonEmpty: String? {
        isEmpty ? nil : self
    }

    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}
