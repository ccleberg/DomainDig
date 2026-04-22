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

struct DomainSuggestionViewData: Identifiable {
    let id: UUID
    let domain: String
    let status: String
    let tone: ResultTone
}

struct LookupSnapshot {
    let historyEntryID: UUID?
    let domain: String
    let timestamp: Date
    let trackedDomainID: UUID?
    let resolverDisplayName: String
    let resolverURLString: String
    let totalLookupDurationMs: Int?
    let dnsSections: [DNSSection]
    let dnsError: String?
    let availabilityResult: DomainAvailabilityResult?
    let suggestions: [DomainSuggestionResult]
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
    let changeSummary: DomainChangeSummary?
    let isLive: Bool
}

extension HistoryEntry {
    var snapshot: LookupSnapshot {
        LookupSnapshot(
            historyEntryID: id,
            domain: domain,
            timestamp: timestamp,
            trackedDomainID: trackedDomainID,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: totalLookupDurationMs,
            dnsSections: dnsSections,
            dnsError: nil,
            availabilityResult: availabilityResult,
            suggestions: suggestions,
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
            changeSummary: changeSummary,
            isLive: false
        )
    }
}

private struct BatchLookupPayload {
    let snapshot: LookupSnapshot
}

@MainActor
@Observable
final class DomainViewModel {
    var domain: String = ""
    var bulkInput: String = ""

    var dnsSections: [DNSSection] = []
    var dnsLoading = false
    var dnsError: String?
    var availabilityResult: DomainAvailabilityResult?
    var availabilityLoading = false
    var suggestions: [DomainSuggestionResult] = []
    var suggestionsLoading = false

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
    private(set) var currentDiffSections: [DomainDiffSection] = []
    private(set) var currentChangeSummary: DomainChangeSummary?
    private(set) var refreshingTrackedDomainID: UUID?
    private(set) var rerunNavigationToken = UUID()
    private(set) var batchResults: [BatchLookupResult] = []
    private(set) var batchLookupSource: BatchLookupSource = .manual
    private(set) var batchCurrentDomain: String?
    private(set) var batchCompletedCount = 0
    private(set) var batchTotalCount = 0
    private(set) var batchLookupRunning = false
    var latestBatchSweepSummary: BatchSweepSummary?
    private(set) var notificationsAuthorized = false

    private var lookupTask: Task<Void, Never>?
    private var customPortScanTask: Task<Void, Never>?
    private var batchTask: Task<Void, Never>?
    private var activeLookupID = UUID()
    private var lookupStartedAt: Date?
    private var activeBatchDomains: [String] = []
    private var lastBatchStartedAt: Date?

    private static let recentSearchesKey = "recentSearches"
    private static let maxRecent = 20
    var recentSearches: [String] = UserDefaults.standard.stringArray(forKey: recentSearchesKey) ?? []

    private static let savedDomainsKey = "savedDomains"
    var savedDomains: [String] = UserDefaults.standard.stringArray(forKey: savedDomainsKey) ?? []

    private static let trackedDomainsKey = "trackedDomains"
    private static let legacyWatchedDomainsKey = "watchedDomains"
    var trackedDomains: [TrackedDomain] = DomainViewModel.loadTrackedDomains()

    private static let historyKey = "lookupHistory"
    private static let maxHistory = 250
    var history: [HistoryEntry] = {
        guard let data = UserDefaults.standard.data(forKey: historyKey),
              let entries = try? JSONDecoder().decode([HistoryEntry].self, from: data) else {
            return []
        }
        return entries
    }()
    var historySearchText = ""
    var historyDateFilter: HistoryDateFilter = .all
    var historyChangeFilter: ChangeFilterOption = .all
    var historySortOption: HistorySortOption = .newest
    var watchlistSearchText = ""
    var watchlistFilter: WatchlistFilterOption = .all
    var watchlistSortOption: WatchlistSortOption = .pinned

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
            !availabilityLoading &&
            !suggestionsLoading &&
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

    var sortedTrackedDomains: [TrackedDomain] {
        sortedTrackedDomains(from: trackedDomains, using: .pinned)
    }

    var filteredHistory: [HistoryEntry] {
        let calendar = Calendar.current
        let now = Date()
        let query = historySearchText.trimmingCharacters(in: .whitespacesAndNewlines)

        return history
            .lazy
            .filter { entry in
                query.isEmpty || entry.domain.localizedCaseInsensitiveContains(query)
            }
            .filter { entry in
                switch self.historyDateFilter {
                case .today:
                    return calendar.isDate(entry.timestamp, inSameDayAs: now)
                case .last7Days:
                    guard let startDate = calendar.date(byAdding: .day, value: -7, to: now) else { return true }
                    return entry.timestamp >= startDate
                case .all:
                    return true
                }
            }
            .filter { entry in
                switch self.historyChangeFilter {
                case .all:
                    return true
                case .changed:
                    return entry.changeSummary?.hasChanges == true
                case .unchanged:
                    return entry.changeSummary?.hasChanges != true
                }
            }
            .sorted(by: historySortPredicate)
    }

    var filteredTrackedDomains: [TrackedDomain] {
        let query = watchlistSearchText.trimmingCharacters(in: .whitespacesAndNewlines)
        let filtered = trackedDomains.filter { trackedDomain in
            if !query.isEmpty, !trackedDomain.domain.localizedCaseInsensitiveContains(query) {
                return false
            }

            switch watchlistFilter {
            case .all:
                return true
            case .pinnedOnly:
                return trackedDomain.isPinned
            case .changedOnly:
                return trackedDomain.lastChangeSummary?.hasChanges == true
            }
        }

        return sortedTrackedDomains(from: filtered, using: watchlistSortOption)
    }

    var batchProgressLabel: String {
        guard batchTotalCount > 0 else { return "No active batch" }
        let domainLabel = activeBatchDomains.first ?? batchCurrentDomain ?? "Preparing"
        return "\(batchCompletedCount)/\(batchTotalCount) • \(domainLabel)"
    }

    var currentBatchResultEntries: [HistoryEntry] {
        batchResults.compactMap { result in
            guard let historyEntryID = result.historyEntryID else { return nil }
            return history.first(where: { $0.id == historyEntryID })
        }
    }

    var currentTrackedDomain: TrackedDomain? {
        guard !searchedDomain.isEmpty else { return nil }
        return trackedDomain(for: searchedDomain)
    }

    var isCurrentDomainTracked: Bool {
        currentTrackedDomain != nil
    }

    var trackingLimitMessage: String? {
        nil
    }

    var canTrackCurrentDomain: Bool {
        true
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
            historyEntryID: nil,
            domain: searchedDomain,
            timestamp: Date(),
            trackedDomainID: currentTrackedDomain?.id,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: lastLookupDurationMs,
            dnsSections: dnsSections,
            dnsError: dnsError,
            availabilityResult: availabilityResult,
            suggestions: suggestions,
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
            changeSummary: currentChangeSummary,
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

    var suggestionRows: [DomainSuggestionViewData] {
        Self.suggestionRows(from: currentSnapshot)
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

    @discardableResult
    func trackCurrentDomain() -> Bool {
        guard !searchedDomain.isEmpty else { return false }
        return trackDomain(domain: searchedDomain, availabilityStatus: availabilityResult?.status)
    }

    @discardableResult
    func trackDomain(domain: String, availabilityStatus: DomainAvailabilityStatus?) -> Bool {
        let normalizedDomain = normalizedDomain(domain)
        guard !normalizedDomain.isEmpty else { return false }

        if trackedDomain(for: normalizedDomain) != nil {
            return true
        }

        guard PremiumAccessService.canAddTrackedDomain(currentCount: trackedDomains.count) else {
            return false
        }

        trackedDomains.insert(
            TrackedDomain(
                domain: normalizedDomain,
                createdAt: Date(),
                updatedAt: Date(),
                lastKnownAvailability: availabilityStatus
            ),
            at: 0
        )
        persistTrackedDomains()
        linkTrackedDomainHistory(for: normalizedDomain)
        return true
    }

    func refreshTrackedDomain(_ trackedDomain: TrackedDomain) {
        refreshingTrackedDomainID = trackedDomain.id
        domain = trackedDomain.domain
        Task { [weak self] in
            guard let self else { return }
            self.notificationsAuthorized = await LocalNotificationService.shared.requestAuthorizationIfNeeded()
        }
        run()
    }

    func rerunInspection(for trackedDomain: TrackedDomain) {
        domain = trackedDomain.domain
        run()
        rerunNavigationToken = UUID()
    }

    func deleteTrackedDomains(at offsets: IndexSet) {
        let ids = offsets.map { sortedTrackedDomains[$0].id }
        trackedDomains.removeAll { ids.contains($0.id) }
        history.indices.forEach { index in
            if let trackedDomainID = history[index].trackedDomainID, ids.contains(trackedDomainID) {
                history[index].trackedDomainID = nil
            }
        }
        persistTrackedDomains()
        persistHistory()
    }

    func deleteTrackedDomain(_ trackedDomain: TrackedDomain) {
        trackedDomains.removeAll { $0.id == trackedDomain.id }
        history.indices.forEach { index in
            if history[index].trackedDomainID == trackedDomain.id {
                history[index].trackedDomainID = nil
            }
        }
        persistTrackedDomains()
        persistHistory()
    }

    func togglePinned(for trackedDomain: TrackedDomain) {
        guard let index = trackedDomains.firstIndex(where: { $0.id == trackedDomain.id }) else { return }
        trackedDomains[index].isPinned.toggle()
        persistTrackedDomains()
    }

    func updateNote(_ note: String, for trackedDomain: TrackedDomain) {
        guard let index = trackedDomains.firstIndex(where: { $0.id == trackedDomain.id }) else { return }
        trackedDomains[index].note = note.trimmingCharacters(in: .whitespacesAndNewlines).nilIfEmpty
        persistTrackedDomains()
    }

    func removeHistoryEntries(at offsets: IndexSet) {
        history.remove(atOffsets: offsets)
        persistHistory()
    }

    func removeHistoryEntries(withIDs ids: [UUID]) {
        history.removeAll { ids.contains($0.id) }
        persistHistory()
    }

    func clearHistory() {
        history.removeAll()
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
        rerunNavigationToken = UUID()
    }

    func reset() {
        lookupTask?.cancel()
        customPortScanTask?.cancel()
        batchTask?.cancel()
        hasRun = false
        searchedDomain = ""
        lastLookupDurationMs = nil
        currentDiffSections = []
        currentChangeSummary = nil
        refreshingTrackedDomainID = nil
        clearBatchState()
        clearLookupState()
    }

    func run() {
        let target = trimmedDomain
        guard !target.isEmpty else { return }
        clearBatchState()
        let lookupID = beginLookup(for: target)

        lookupTask = Task { [weak self] in
            guard let self else { return }
            _ = await self.performLookup(domain: target, lookupID: lookupID)
        }
    }

    func runBulkLookup() {
        let domains = parsedDomains(from: bulkInput)
        guard !domains.isEmpty else { return }
        startBatchLookup(domains: domains, source: .manual)
    }

    func refreshAllTrackedDomains() {
        startBatchLookup(domains: sortedTrackedDomains.map(\.domain), source: .watchlistRefresh)
    }

    func cancelBatchLookup() {
        batchTask?.cancel()
        batchLookupRunning = false
        batchCurrentDomain = nil
        activeBatchDomains = []
        refreshingTrackedDomainID = nil

        for index in batchResults.indices where batchResults[index].status == .pending || batchResults[index].status == .running {
            batchResults[index] = BatchLookupResult(
                id: batchResults[index].id,
                domain: batchResults[index].domain,
                historyEntryID: batchResults[index].historyEntryID,
                availability: batchResults[index].availability,
                primaryIP: batchResults[index].primaryIP,
                quickStatus: "Cancelled",
                summaryMessage: batchResults[index].summaryMessage,
                changeSeverity: batchResults[index].changeSeverity,
                certificateWarningLevel: batchResults[index].certificateWarningLevel,
                timestamp: Date(),
                status: .failed,
                errorMessage: "Lookup cancelled"
            )
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
        Self.formatExportText(
            from: currentSnapshot,
            trackedDomain: currentTrackedDomain,
            changeSummary: currentChangeSummary,
            diffSections: currentDiffSections
        )
    }

    func exportCSV() -> String {
        Self.formatCSV(from: [currentSnapshot])
    }

    func exportBatchText() -> String {
        Self.formatBatchExportText(
            title: batchLookupSource == .watchlistRefresh ? "Tracked Domains Export" : "Batch Results Export",
            entries: currentBatchResultEntries.map { entry in
                (
                    snapshot: entry.snapshot,
                    trackedDomain: trackedDomains.first(where: { tracked in
                        tracked.id == entry.trackedDomainID ||
                        tracked.domain.caseInsensitiveCompare(entry.domain) == .orderedSame
                    }),
                    changeSummary: entry.changeSummary,
                    diffSections: comparisonSnapshot(for: entry).map { DomainDiffService.diff(from: $0, to: entry.snapshot) } ?? []
                )
            }
        )
    }

    func exportBatchCSV() -> String {
        Self.formatCSV(from: currentBatchResultEntries.map(\.snapshot))
    }

    func exportTrackedDomainsCSV(domains: [TrackedDomain]) -> String {
        Self.formatCSV(from: exportSnapshots(for: domains))
    }

    func exportTrackedDomainsText(domains: [TrackedDomain]) -> String {
        let latestEntries = latestSnapshots(for: domains)
        return Self.formatBatchExportText(
            title: "Tracked Domains Export",
            entries: domains.map { trackedDomain in
                if let entry = latestEntries.first(where: { $0.trackedDomainID == trackedDomain.id || $0.domain.caseInsensitiveCompare(trackedDomain.domain) == .orderedSame }) {
                    return (
                        snapshot: entry.snapshot,
                        trackedDomain: trackedDomain,
                        changeSummary: entry.changeSummary,
                        diffSections: comparisonSnapshot(for: entry).map { DomainDiffService.diff(from: $0, to: entry.snapshot) } ?? []
                    )
                }

                return (
                    snapshot: placeholderSnapshot(for: trackedDomain),
                    trackedDomain: trackedDomain,
                    changeSummary: trackedDomain.lastChangeSummary,
                    diffSections: []
                )
            }
        )
    }

    private func performLookup(domain: String, lookupID: UUID) async -> HistoryEntry? {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.runDNS(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runAvailability(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runSSL(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runHSTSPreload(domain: domain, lookupID: lookupID) }
        }

        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.runHTTPHeaders(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runReachability(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runRedirectChain(domain: domain, lookupID: lookupID) }
            group.addTask { await self.runPortScan(domain: domain, lookupID: lookupID) }
        }

        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return nil }

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

        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return nil }

        if availabilityResult?.status == .registered {
            await runSuggestions(domain: domain, lookupID: lookupID)
        } else {
            suggestions = []
            suggestionsLoading = false
        }

        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return nil }
        lastLookupDurationMs = lookupStartedAt.map { Int(Date().timeIntervalSince($0) * 1000) }
        let entry = saveHistoryEntry(replaceLatest: false)
        refreshingTrackedDomainID = nil
        return entry
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

    private func runAvailability(domain: String, lookupID: UUID) async {
        let result = await DomainAvailabilityService.check(domain: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        availabilityResult = result
        availabilityLoading = false
        updateTrackedDomainAvailability(for: result.domain, status: result.status)
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

    private func runSuggestions(domain: String, lookupID: UUID) async {
        let results = await DomainAvailabilityService.suggestions(for: domain)
        guard !Task.isCancelled, isCurrentLookup(lookupID) else { return }
        suggestions = results
        suggestionsLoading = false
    }

    private func applyCustomPortResult(_ result: ServiceResult<[PortScanResult]>) {
        switch result {
        case let .success(results):
            customPortResults = results
            customPortScanError = nil
            _ = saveHistoryEntry(replaceLatest: true)
        case let .empty(message):
            customPortResults = []
            customPortScanError = message
        case let .error(message):
            customPortResults = []
            customPortScanError = message
        }
        customPortScanLoading = false
    }

    private static func performBatchLookup(domain: String) async -> BatchLookupPayload? {
        guard !Task.isCancelled else { return nil }

        let startedAt = Date()
        let resolverDisplayName = DNSLookupService.currentResolverDisplayName()
        let resolverURLString = DNSLookupService.currentResolverURLString()

        async let dnsResult = DNSLookupService.lookupAll(domain: domain)
        async let availabilityResult = DomainAvailabilityService.check(domain: domain)
        async let sslResult = SSLCheckService.check(domain: domain)
        async let hstsResult = SSLCheckService.checkHSTSPreload(domain: domain)
        async let httpResult = HTTPHeadersService.fetch(domain: domain)
        async let reachabilityResult = ReachabilityService.checkAll(domain: domain)
        async let redirectResult = RedirectChainService.trace(domain: domain)
        async let portScanResult = PortScanService.scanAll(domain: domain)

        let resolvedDNS = await dnsResult
        let availability = await availabilityResult
        let resolvedSSL = await sslResult
        let hsts = await hstsResult
        let http = await httpResult
        let reachability = await reachabilityResult
        let redirects = await redirectResult
        let ports = await portScanResult

        guard !Task.isCancelled else { return nil }

        let dnsSections: [DNSSection]
        let dnsError: String?
        switch resolvedDNS {
        case let .success(sections):
            dnsSections = sections
            dnsError = nil
        case let .empty(message), let .error(message):
            dnsSections = []
            dnsError = message
        }

        let sslInfo: SSLCertificateInfo?
        let sslError: String?
        switch resolvedSSL {
        case let .success(info):
            sslInfo = info
            sslError = nil
        case let .empty(message), let .error(message):
            sslInfo = nil
            sslError = message
        }

        let httpHeaders: [HTTPHeader]
        let httpSecurityGrade: String?
        let httpStatusCode: Int?
        let httpResponseTimeMs: Int?
        let httpProtocol: String?
        let http3Advertised: Bool
        let httpHeadersError: String?
        switch http {
        case let .success(result):
            httpHeaders = result.headers
            httpSecurityGrade = HTTPSecurityGrade.grade(for: result.headers).rawValue
            httpStatusCode = result.statusCode
            httpResponseTimeMs = result.responseTimeMs
            httpProtocol = result.httpProtocol
            http3Advertised = result.http3Advertised
            httpHeadersError = nil
        case let .empty(message), let .error(message):
            httpHeaders = []
            httpSecurityGrade = nil
            httpStatusCode = nil
            httpResponseTimeMs = nil
            httpProtocol = nil
            http3Advertised = false
            httpHeadersError = message
        }

        let reachabilityResults: [PortReachability]
        let reachabilityError: String?
        switch reachability {
        case let .success(results):
            reachabilityResults = results
            reachabilityError = nil
        case let .empty(message), let .error(message):
            reachabilityResults = []
            reachabilityError = message
        }

        let redirectChain: [RedirectHop]
        let redirectChainError: String?
        switch redirects {
        case let .success(hops):
            redirectChain = hops
            redirectChainError = nil
        case let .empty(message), let .error(message):
            redirectChain = []
            redirectChainError = message
        }

        let portScanResults: [PortScanResult]
        let portScanError: String?
        switch ports {
        case let .success(results):
            portScanResults = await enrichOpenPortBanners(results, domain: domain)
            portScanError = nil
        case let .empty(message), let .error(message):
            portScanResults = []
            portScanError = message
        }

        let txtRecords = dnsSections.first(where: { $0.recordType == .TXT })?.records ?? []
        let primaryIP = dnsSections.first(where: { $0.recordType == .A })?.records.first?.value

        async let emailResult = EmailSecurityService.analyze(domain: domain, txtRecords: txtRecords)
        async let suggestions = availability.status == .registered ? DomainAvailabilityService.suggestions(for: domain) : []

        let resolvedEmail = await emailResult
        let resolvedSuggestions = await suggestions
        let resolvedPTR: ServiceResult<String>?
        let resolvedGeo: ServiceResult<IPGeolocation>?
        if let primaryIP {
            resolvedPTR = await ReverseDNSService.lookup(ip: primaryIP, resolverURLString: resolverURLString)
            resolvedGeo = await IPGeolocationService.lookup(ip: primaryIP)
        } else {
            resolvedPTR = nil
            resolvedGeo = nil
        }

        guard !Task.isCancelled else { return nil }

        let emailSecurity: EmailSecurityResult?
        let emailSecurityError: String?
        switch resolvedEmail {
        case let .success(result):
            emailSecurity = result
            emailSecurityError = nil
        case let .empty(message), let .error(message):
            emailSecurity = nil
            emailSecurityError = message
        }

        let ptrRecord: String?
        let ptrError: String?
        switch resolvedPTR {
        case let .success(record):
            ptrRecord = record
            ptrError = nil
        case let .empty(message), let .error(message):
            ptrRecord = nil
            ptrError = message
        case .none:
            ptrRecord = nil
            ptrError = "No A record available"
        }

        let ipGeolocation: IPGeolocation?
        let ipGeolocationError: String?
        switch resolvedGeo {
        case let .success(result):
            ipGeolocation = result
            ipGeolocationError = nil
        case let .empty(message), let .error(message):
            ipGeolocation = nil
            ipGeolocationError = message
        case .none:
            ipGeolocation = nil
            ipGeolocationError = "No A record available"
        }

        let snapshot = LookupSnapshot(
            historyEntryID: nil,
            domain: domain,
            timestamp: Date(),
            trackedDomainID: nil,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: Int(Date().timeIntervalSince(startedAt) * 1000),
            dnsSections: dnsSections,
            dnsError: dnsError,
            availabilityResult: availability,
            suggestions: resolvedSuggestions,
            sslInfo: sslInfo,
            sslError: sslError,
            hstsPreloaded: hsts,
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
            portScanResults: portScanResults,
            portScanError: portScanError,
            changeSummary: nil,
            isLive: false
        )

        return BatchLookupPayload(snapshot: snapshot)
    }

    private static func enrichOpenPortBanners(_ results: [PortScanResult], domain: String) async -> [PortScanResult] {
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

    private func enrichOpenPortBanners(in results: [PortScanResult], domain: String) async -> [PortScanResult] {
        await Self.enrichOpenPortBanners(results, domain: domain)
    }

    @discardableResult
    private func saveHistoryEntry(replaceLatest: Bool) -> HistoryEntry? {
        guard !searchedDomain.isEmpty else { return nil }
        return saveHistoryEntry(from: currentSnapshot, replaceLatest: replaceLatest, updateCurrentState: true)
    }

    @discardableResult
    private func saveHistoryEntry(from snapshot: LookupSnapshot, replaceLatest: Bool, updateCurrentState: Bool) -> HistoryEntry? {
        let trackedDomainID = snapshot.trackedDomainID ?? trackedDomain(for: snapshot.domain)?.id
        let previousSnapshot = previousSnapshot(for: snapshot.domain, trackedDomainID: trackedDomainID, replacingLatest: replaceLatest)
        let changeSummary = previousSnapshot.map {
            DomainDiffService.summary(from: $0, to: snapshot, generatedAt: snapshot.timestamp)
        }
        let diffSections = previousSnapshot.map { DomainDiffService.diff(from: $0, to: snapshot) } ?? []

        if updateCurrentState {
            currentChangeSummary = changeSummary
            currentDiffSections = diffSections
        }

        let entry = HistoryEntry(
            domain: snapshot.domain,
            timestamp: snapshot.timestamp,
            trackedDomainID: trackedDomainID,
            dnsSections: snapshot.dnsSections,
            sslInfo: snapshot.sslInfo,
            httpHeaders: snapshot.httpHeaders,
            reachabilityResults: snapshot.reachabilityResults,
            ipGeolocation: snapshot.ipGeolocation,
            emailSecurity: snapshot.emailSecurity,
            mtaSts: snapshot.emailSecurity?.mtaSts,
            ptrRecord: snapshot.ptrRecord,
            redirectChain: snapshot.redirectChain,
            portScanResults: snapshot.portScanResults,
            hstsPreloaded: snapshot.hstsPreloaded,
            availabilityResult: snapshot.availabilityResult,
            suggestions: snapshot.suggestions,
            resolverDisplayName: snapshot.resolverDisplayName,
            resolverURLString: snapshot.resolverURLString,
            totalLookupDurationMs: snapshot.totalLookupDurationMs,
            primaryIP: Self.primaryIPAddress(from: snapshot),
            finalRedirectURL: Self.finalRedirectTarget(from: snapshot),
            tlsStatusSummary: Self.httpsSummary(from: snapshot),
            emailSecuritySummary: Self.emailSummary(from: snapshot),
            httpGradeSummary: snapshot.httpSecurityGrade ?? snapshot.httpHeadersError,
            changeSummary: changeSummary,
            sslError: snapshot.sslError,
            httpHeadersError: snapshot.httpHeadersError,
            reachabilityError: snapshot.reachabilityError,
            ipGeolocationError: snapshot.ipGeolocationError,
            emailSecurityError: snapshot.emailSecurityError,
            ptrError: snapshot.ptrError,
            redirectChainError: snapshot.redirectChainError,
            portScanError: snapshot.portScanError
        )

        if replaceLatest, !history.isEmpty, history[0].domain.caseInsensitiveCompare(snapshot.domain) == .orderedSame {
            history[0] = entry
        } else {
            history.insert(entry, at: 0)
            if history.count > Self.maxHistory {
                history = Array(history.prefix(Self.maxHistory))
            }
        }

        updateTrackedDomainSnapshotMetadata(
            domain: snapshot.domain,
            snapshotID: entry.id,
            availabilityStatus: snapshot.availabilityResult?.status,
            updatedAt: snapshot.timestamp,
            changeSummary: changeSummary,
            changeSeverity: changeSummary?.severity,
            certificateWarningLevel: DomainDiffService.certificateWarningLevel(for: snapshot),
            certificateDaysRemaining: snapshot.sslInfo?.daysUntilExpiry
        )
        persistHistory()
        notifyIfNeeded(for: entry, snapshot: snapshot, previousSnapshot: previousSnapshot)
        return entry
    }

    private func persistHistory() {
        if let data = try? JSONEncoder().encode(history) {
            UserDefaults.standard.set(data, forKey: Self.historyKey)
        }
    }

    private func persistTrackedDomains() {
        if let data = try? JSONEncoder().encode(trackedDomains) {
            UserDefaults.standard.set(data, forKey: Self.trackedDomainsKey)
        }
    }

    private func updateTrackedDomainAvailability(for domain: String, status: DomainAvailabilityStatus) {
        guard let index = trackedDomains.firstIndex(where: { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }) else {
            return
        }
        trackedDomains[index].lastKnownAvailability = status
        persistTrackedDomains()
    }

    private func updateTrackedDomainSnapshotMetadata(
        domain: String,
        snapshotID: UUID,
        availabilityStatus: DomainAvailabilityStatus?,
        updatedAt: Date,
        changeSummary: DomainChangeSummary?,
        changeSeverity: ChangeSeverity?,
        certificateWarningLevel: CertificateWarningLevel,
        certificateDaysRemaining: Int?
    ) {
        guard let index = trackedDomains.firstIndex(where: { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }) else {
            return
        }
        trackedDomains[index].lastSnapshotID = snapshotID
        trackedDomains[index].lastKnownAvailability = availabilityStatus
        trackedDomains[index].updatedAt = updatedAt
        trackedDomains[index].lastChangeSummary = changeSummary
        trackedDomains[index].lastChangeSeverity = changeSeverity
        trackedDomains[index].certificateWarningLevel = certificateWarningLevel
        trackedDomains[index].certificateDaysRemaining = certificateDaysRemaining
        persistTrackedDomains()
    }

    private func notifyIfNeeded(for entry: HistoryEntry, snapshot: LookupSnapshot, previousSnapshot: LookupSnapshot?) {
        guard notificationsAuthorized, entry.trackedDomainID != nil else { return }

        Task {
            if let summary = entry.changeSummary, summary.hasChanges {
                await LocalNotificationService.shared.notifyDomainEvent(
                    domain: entry.domain,
                    message: summary.message,
                    severity: summary.severity
                )
            }

            let certificateWarningLevel = DomainDiffService.certificateWarningLevel(for: snapshot)
            if certificateWarningLevel == .critical, let daysRemaining = snapshot.sslInfo?.daysUntilExpiry {
                await LocalNotificationService.shared.notifyCertificateWarning(
                    domain: entry.domain,
                    daysRemaining: daysRemaining
                )
            }

            if let previousStatus = previousSnapshot?.availabilityResult?.status,
               let newStatus = snapshot.availabilityResult?.status,
               previousStatus != newStatus {
                await LocalNotificationService.shared.notifyDomainEvent(
                    domain: entry.domain,
                    message: "Availability changed",
                    severity: .high
                )
            }
        }
    }

    private func previousSnapshot(for domain: String, trackedDomainID: UUID?, replacingLatest: Bool) -> LookupSnapshot? {
        let matchingEntries = history.filter { entry in
            if let trackedDomainID {
                return entry.trackedDomainID == trackedDomainID
            }
            return entry.domain.caseInsensitiveCompare(domain) == .orderedSame
        }

        if replacingLatest {
            return matchingEntries.dropFirst().first?.snapshot
        }
        return matchingEntries.first?.snapshot
    }

    private func trackedDomain(for domain: String) -> TrackedDomain? {
        trackedDomains.first { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }
    }

    private func normalizedDomain(_ domain: String) -> String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .components(separatedBy: "/")
            .first?
            .lowercased() ?? ""
    }

    private func linkTrackedDomainHistory(for domain: String) {
        guard let trackedDomain = trackedDomain(for: domain) else { return }
        var didChange = false

        for index in history.indices where history[index].domain.caseInsensitiveCompare(domain) == .orderedSame {
            if history[index].trackedDomainID != trackedDomain.id {
                history[index].trackedDomainID = trackedDomain.id
                didChange = true
            }
        }

        if didChange {
            persistHistory()
        }

        if let latestEntry = history.first(where: { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }),
           let trackedIndex = trackedDomains.firstIndex(where: { $0.id == trackedDomain.id }) {
            trackedDomains[trackedIndex].lastSnapshotID = latestEntry.id
            trackedDomains[trackedIndex].lastChangeSummary = latestEntry.changeSummary
            trackedDomains[trackedIndex].lastChangeSeverity = latestEntry.changeSummary?.severity
            trackedDomains[trackedIndex].lastKnownAvailability = latestEntry.availabilityResult?.status
            trackedDomains[trackedIndex].certificateWarningLevel = DomainDiffService.certificateWarningLevel(for: latestEntry.snapshot)
            trackedDomains[trackedIndex].certificateDaysRemaining = latestEntry.sslInfo?.daysUntilExpiry
            trackedDomains[trackedIndex].updatedAt = latestEntry.timestamp
            persistTrackedDomains()
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

    private func beginLookup(for target: String, cancelExistingTask: Bool = true) -> UUID {
        if cancelExistingTask {
            lookupTask?.cancel()
        }
        customPortScanTask?.cancel()

        let lookupID = UUID()
        activeLookupID = lookupID
        lookupStartedAt = Date()
        lastLookupDurationMs = nil
        addRecentSearch(target)
        searchedDomain = target
        hasRun = true
        currentDiffSections = []
        currentChangeSummary = nil
        clearLookupState()
        setAllLoadingStates(true)
        customPortScanLoading = false
        return lookupID
    }

    private func startBatchLookup(domains: [String], source: BatchLookupSource) {
        guard !domains.isEmpty else { return }
        guard !batchLookupRunning else { return }

        let now = Date()
        if let lastBatchStartedAt, now.timeIntervalSince(lastBatchStartedAt) < 1 {
            return
        }

        lastBatchStartedAt = now
        clearBatchState()
        batchLookupSource = source
        batchTotalCount = domains.count
        batchLookupRunning = true
        batchResults = domains.map {
            BatchLookupResult(
                domain: $0,
                historyEntryID: nil,
                availability: nil,
                primaryIP: nil,
                quickStatus: "Pending",
                timestamp: Date(),
                status: .pending
            )
        }

        lookupTask?.cancel()
        customPortScanTask?.cancel()
        batchTask?.cancel()

        batchTask = Task { [weak self] in
            guard let self else { return }
            self.notificationsAuthorized = await LocalNotificationService.shared.requestAuthorizationIfNeeded()
            await self.runBatchLookup(domains: domains, source: source)
        }
    }

    private func clearBatchState() {
        batchResults = []
        batchLookupSource = .manual
        batchCurrentDomain = nil
        batchCompletedCount = 0
        batchTotalCount = 0
        batchLookupRunning = false
        latestBatchSweepSummary = nil
        activeBatchDomains = []
        batchTask = nil
    }

    private func parsedDomains(from input: String) -> [String] {
        let separators = CharacterSet(charactersIn: ",\n")
        var seen = Set<String>()

        return input
            .components(separatedBy: separators)
            .map(normalizedDomain)
            .filter { !$0.isEmpty }
            .filter { seen.insert($0).inserted }
    }

    private func runBatchLookup(domains: [String], source: BatchLookupSource) async {
        let concurrencyLimit = min(source == .watchlistRefresh ? 4 : 3, max(domains.count, 1))
        var nextIndex = 0

        await withTaskGroup(of: (String, BatchLookupPayload?).self) { group in
            for _ in 0..<concurrencyLimit {
                guard nextIndex < domains.count else { break }
                let domain = domains[nextIndex]
                nextIndex += 1
                enqueueBatchLookup(domain: domain, source: source, group: &group)
            }

            while let (domain, payload) = await group.next() {
                completeBatchLookup(domain: domain, payload: payload)

                if nextIndex < domains.count, !Task.isCancelled {
                    let nextDomain = domains[nextIndex]
                    nextIndex += 1
                    enqueueBatchLookup(domain: nextDomain, source: source, group: &group)
                }
            }
        }

        finishBatchLookup(source: source)
    }

    private func enqueueBatchLookup(
        domain: String,
        source: BatchLookupSource,
        group: inout TaskGroup<(String, BatchLookupPayload?)>
    ) {
        activeBatchDomains.append(domain)
        batchCurrentDomain = activeBatchDomains.first
        if source == .watchlistRefresh {
            refreshingTrackedDomainID = trackedDomain(for: domain)?.id
        }
        updateBatchResult(domain: domain, status: .running, quickStatus: "Running", entry: nil, errorMessage: nil)

        group.addTask { [domain] in
            let payload = await Self.performBatchLookup(domain: domain)
            return (domain, payload)
        }
    }

    private func completeBatchLookup(domain: String, payload: BatchLookupPayload?) {
        activeBatchDomains.removeAll { $0.caseInsensitiveCompare(domain) == .orderedSame }
        batchCurrentDomain = activeBatchDomains.first

        guard let payload else {
            updateBatchResult(
                domain: domain,
                status: .failed,
                quickStatus: "Failed",
                entry: nil,
                errorMessage: "Lookup cancelled"
            )
            batchCompletedCount += 1
            return
        }

        let entry = saveHistoryEntry(from: payload.snapshot, replaceLatest: false, updateCurrentState: false)
        let certificateWarningLevel = DomainDiffService.certificateWarningLevel(for: payload.snapshot)
        let quickStatus: String
        if entry?.changeSummary?.hasChanges == true {
            quickStatus = entry?.changeSummary?.severity == .high ? "High" : "Changed"
        } else if certificateWarningLevel != .none {
            quickStatus = certificateWarningLevel == .critical ? "Critical" : "Warning"
        } else {
            quickStatus = "Unchanged"
        }

        updateBatchResult(
            domain: domain,
            status: .completed,
            quickStatus: quickStatus,
            entry: entry,
            errorMessage: nil
        )
        batchCompletedCount += 1
    }

    private func finishBatchLookup(source: BatchLookupSource) {
        batchLookupRunning = false
        batchCurrentDomain = nil
        activeBatchDomains = []
        refreshingTrackedDomainID = nil
        batchTask = nil

        let summary = BatchSweepSummary(
            source: source,
            totalDomains: batchResults.count,
            changedDomains: batchResults.filter { ($0.changeSeverity ?? .low) >= .medium }.count,
            unchangedDomains: batchResults.filter { ($0.changeSeverity ?? .low) < .medium && $0.certificateWarningLevel == .none && $0.status == .completed }.count,
            warningDomains: batchResults.filter { $0.certificateWarningLevel != .none }.count,
            results: batchResults.sorted { lhs, rhs in
                if lhs.status != rhs.status {
                    return lhs.status.rawValue < rhs.status.rawValue
                }
                return lhs.domain.localizedCaseInsensitiveCompare(rhs.domain) == .orderedAscending
            },
            generatedAt: Date()
        )
        latestBatchSweepSummary = summary

        if notificationsAuthorized {
            Task {
                await LocalNotificationService.shared.notifySweepComplete(summary: summary)
            }
        }
    }

    private func updateBatchResult(
        domain: String,
        status: BatchLookupStatus,
        quickStatus: String,
        entry: HistoryEntry?,
        errorMessage: String?
    ) {
        guard let index = batchResults.firstIndex(where: { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }) else {
            return
        }

        batchResults[index] = BatchLookupResult(
            id: batchResults[index].id,
            domain: domain,
            historyEntryID: entry?.id,
            availability: entry?.availabilityResult?.status,
            primaryIP: entry?.primaryIP,
            quickStatus: quickStatus,
            summaryMessage: entry?.changeSummary?.message,
            changeSeverity: entry?.changeSummary?.severity,
            certificateWarningLevel: entry.map { DomainDiffService.certificateWarningLevel(for: $0.snapshot) } ?? batchResults[index].certificateWarningLevel,
            timestamp: entry?.timestamp ?? Date(),
            status: status,
            errorMessage: errorMessage
        )
    }

    private func clearLookupState() {
        dnsSections = []
        dnsError = nil
        dnsLoading = false
        availabilityResult = nil
        availabilityLoading = false
        suggestions = []
        suggestionsLoading = false
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
        availabilityLoading = loading
        suggestionsLoading = loading
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

    func recentSnapshots(for trackedDomain: TrackedDomain, limit: Int = 6) -> [HistoryEntry] {
        history
            .filter { $0.trackedDomainID == trackedDomain.id || $0.domain.caseInsensitiveCompare(trackedDomain.domain) == .orderedSame }
            .sorted { $0.timestamp > $1.timestamp }
            .prefix(limit)
            .map { $0 }
    }

    func latestSnapshots(for domains: [TrackedDomain]) -> [HistoryEntry] {
        domains.compactMap { trackedDomain in
            recentSnapshots(for: trackedDomain, limit: 1).first
        }
    }

    func diffSectionsForLatestSnapshots(of trackedDomain: TrackedDomain) -> [DomainDiffSection] {
        let snapshots = recentSnapshots(for: trackedDomain, limit: 2)
        guard snapshots.count == 2 else { return [] }
        return DomainDiffService.diff(from: snapshots[1].snapshot, to: snapshots[0].snapshot)
    }

    func latestChangeSummary(for trackedDomain: TrackedDomain) -> DomainChangeSummary? {
        trackedDomain.lastChangeSummary ?? recentSnapshots(for: trackedDomain, limit: 1).first?.changeSummary
    }

    func comparisonSnapshot(for entry: HistoryEntry) -> LookupSnapshot? {
        let siblings = history.filter { candidate in
            if let trackedDomainID = entry.trackedDomainID {
                return candidate.trackedDomainID == trackedDomainID && candidate.id != entry.id
            }
            return candidate.domain.caseInsensitiveCompare(entry.domain) == .orderedSame && candidate.id != entry.id
        }
        .sorted { $0.timestamp > $1.timestamp }

        return siblings.first?.snapshot
    }

    func historyEntry(for batchResult: BatchLookupResult) -> HistoryEntry? {
        guard let historyEntryID = batchResult.historyEntryID else { return nil }
        return history.first(where: { $0.id == historyEntryID })
    }

    private func exportSnapshots(for domains: [TrackedDomain]) -> [LookupSnapshot] {
        let latestEntries = latestSnapshots(for: domains)

        return domains.map { trackedDomain in
            if let entry = latestEntries.first(where: { $0.trackedDomainID == trackedDomain.id || $0.domain.caseInsensitiveCompare(trackedDomain.domain) == .orderedSame }) {
                return entry.snapshot
            }
            return placeholderSnapshot(for: trackedDomain)
        }
    }

    private func placeholderSnapshot(for trackedDomain: TrackedDomain) -> LookupSnapshot {
        LookupSnapshot(
            historyEntryID: trackedDomain.lastSnapshotID,
            domain: trackedDomain.domain,
            timestamp: trackedDomain.updatedAt,
            trackedDomainID: trackedDomain.id,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            totalLookupDurationMs: nil,
            dnsSections: [],
            dnsError: nil,
            availabilityResult: DomainAvailabilityResult(domain: trackedDomain.domain, status: trackedDomain.lastKnownAvailability ?? .unknown),
            suggestions: [],
            sslInfo: nil,
            sslError: nil,
            hstsPreloaded: nil,
            httpHeaders: [],
            httpSecurityGrade: nil,
            httpStatusCode: nil,
            httpResponseTimeMs: nil,
            httpProtocol: nil,
            http3Advertised: false,
            httpHeadersError: nil,
            reachabilityResults: [],
            reachabilityError: nil,
            ipGeolocation: nil,
            ipGeolocationError: nil,
            emailSecurity: nil,
            emailSecurityError: nil,
            ptrRecord: nil,
            ptrError: nil,
            redirectChain: [],
            redirectChainError: nil,
            portScanResults: [],
            portScanError: nil,
            changeSummary: trackedDomain.lastChangeSummary,
            isLive: false
        )
    }

    private static func loadTrackedDomains() -> [TrackedDomain] {
        let defaults = UserDefaults.standard
        let decoder = JSONDecoder()

        if let data = defaults.data(forKey: trackedDomainsKey),
           let domains = try? decoder.decode([TrackedDomain].self, from: data) {
            return deduplicatedTrackedDomains(domains)
        }

        if let legacyData = defaults.data(forKey: legacyWatchedDomainsKey),
           let legacyDomains = try? decoder.decode([WatchedDomain].self, from: legacyData) {
            return deduplicatedTrackedDomains(
                legacyDomains.map {
                    TrackedDomain(
                        id: $0.id,
                        domain: $0.domain.lowercased(),
                        createdAt: $0.createdAt,
                        updatedAt: $0.createdAt,
                        lastKnownAvailability: $0.lastKnownAvailability
                    )
                }
            )
        }

        return []
    }

    private static func deduplicatedTrackedDomains(_ domains: [TrackedDomain]) -> [TrackedDomain] {
        var seen = Set<String>()
        return domains.filter { domain in
            let key = domain.domain.lowercased()
            return seen.insert(key).inserted
        }
    }

    private func historySortPredicate(lhs: HistoryEntry, rhs: HistoryEntry) -> Bool {
        switch historySortOption {
        case .newest:
            return lhs.timestamp > rhs.timestamp
        case .oldest:
            return lhs.timestamp < rhs.timestamp
        case .domain:
            let domainOrder = lhs.domain.localizedCaseInsensitiveCompare(rhs.domain)
            if domainOrder != .orderedSame {
                return domainOrder == .orderedAscending
            }
            return lhs.timestamp > rhs.timestamp
        }
    }

    private func sortedTrackedDomains(from domains: [TrackedDomain], using sortOption: WatchlistSortOption) -> [TrackedDomain] {
        domains.sorted { lhs, rhs in
            switch sortOption {
            case .pinned:
                if lhs.isPinned != rhs.isPinned {
                    return lhs.isPinned && !rhs.isPinned
                }
                if lhs.updatedAt != rhs.updatedAt {
                    return lhs.updatedAt > rhs.updatedAt
                }
                return lhs.domain.localizedCaseInsensitiveCompare(rhs.domain) == .orderedAscending
            case .recentlyUpdated:
                if lhs.updatedAt != rhs.updatedAt {
                    return lhs.updatedAt > rhs.updatedAt
                }
                return lhs.domain.localizedCaseInsensitiveCompare(rhs.domain) == .orderedAscending
            case .alphabetical:
                let domainOrder = lhs.domain.localizedCaseInsensitiveCompare(rhs.domain)
                if domainOrder != .orderedSame {
                    return domainOrder == .orderedAscending
                }
                return lhs.updatedAt > rhs.updatedAt
            }
        }
    }

    static func summaryFields(from snapshot: LookupSnapshot) -> [SummaryFieldViewData] {
        [
            SummaryFieldViewData(label: "Domain", value: snapshot.domain.nonEmpty ?? "Unavailable", tone: .primary),
            SummaryFieldViewData(label: "Primary IP", value: primaryIPAddress(from: snapshot) ?? "Unavailable", tone: .primary),
            SummaryFieldViewData(label: "HTTPS", value: httpsSummary(from: snapshot), tone: httpsSummaryTone(from: snapshot)),
            SummaryFieldViewData(label: "Certificate", value: certificateStatusLabel(from: snapshot), tone: certificateStatusTone(from: snapshot)),
            SummaryFieldViewData(label: "Redirect", value: finalRedirectTarget(from: snapshot) ?? "Unavailable", tone: .secondary)
        ]
    }

    static func domainRows(from snapshot: LookupSnapshot) -> [InfoRowViewData] {
        var rows = [
            InfoRowViewData(label: "Domain", value: snapshot.domain, tone: .primary),
            InfoRowViewData(label: "Resolver", value: snapshot.resolverDisplayName, tone: .secondary),
            InfoRowViewData(label: snapshot.isLive ? "Result" : "Snapshot", value: snapshot.isLive ? "Live" : "Snapshot", tone: snapshot.isLive ? .success : .warning),
            InfoRowViewData(label: "Lookup Duration", value: durationLabel(snapshot.totalLookupDurationMs), tone: .secondary)
        ]
        rows.insert(
            InfoRowViewData(
                label: "Availability",
                value: availabilityLabel(snapshot.availabilityResult?.status),
                tone: availabilityTone(snapshot.availabilityResult?.status)
            ),
            at: 1
        )
        if let certificateStatus = certificateBadgeLabel(from: snapshot) {
            rows.insert(
                InfoRowViewData(
                    label: "Certificate",
                    value: certificateStatus,
                    tone: certificateStatusTone(from: snapshot)
                ),
                at: 2
            )
        }
        return rows
    }

    static func suggestionRows(from snapshot: LookupSnapshot) -> [DomainSuggestionViewData] {
        snapshot.suggestions.map {
            DomainSuggestionViewData(
                id: $0.id,
                domain: $0.domain,
                status: availabilityLabel($0.status),
                tone: availabilityTone($0.status)
            )
        }
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
            InfoRowViewData(label: "Valid From", value: certificateDateFormatter.string(from: sslInfo.validFrom), tone: .secondary),
            InfoRowViewData(label: "Valid Until", value: certificateDateFormatter.string(from: sslInfo.validUntil), tone: .secondary),
            InfoRowViewData(label: "Days Until Expiry", value: "\(sslInfo.daysUntilExpiry)", tone: certificateTone(daysRemaining: sslInfo.daysUntilExpiry)),
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

    static func formatBatchExportText(
        title: String,
        entries: [(snapshot: LookupSnapshot, trackedDomain: TrackedDomain?, changeSummary: DomainChangeSummary?, diffSections: [DomainDiffSection])]
    ) -> String {
        guard !entries.isEmpty else {
            return "\(title)\nNo results available."
        }

        var lines = [title, String(repeating: "=", count: title.count), ""]
        for (index, entry) in entries.enumerated() {
            if index > 0 {
                lines.append("")
                lines.append(String(repeating: "=", count: 48))
                lines.append("")
            }

            lines.append(
                formatExportText(
                    from: entry.snapshot,
                    trackedDomain: entry.trackedDomain,
                    changeSummary: entry.changeSummary,
                    diffSections: entry.diffSections
                )
            )
        }
        return lines.joined(separator: "\n")
    }

    static func formatCSV(from snapshots: [LookupSnapshot]) -> String {
        let headers = [
            "domain",
            "availability",
            "primary_ip",
            "redirect_target",
            "tls_status",
            "http_status_grade",
            "email_security_summary",
            "last_updated"
        ]

        let rows = snapshots.map { snapshot in
            [
                snapshot.domain,
                availabilityLabel(snapshot.availabilityResult?.status),
                primaryIPAddress(from: snapshot) ?? "",
                finalRedirectTarget(from: snapshot) ?? "",
                httpsSummary(from: snapshot),
                httpStatusGradeSummary(from: snapshot),
                emailSummary(from: snapshot),
                csvDateFormatter.string(from: snapshot.timestamp)
            ]
        }

        return ([headers] + rows)
            .map { row in row.map(csvEscaped).joined(separator: ",") }
            .joined(separator: "\n")
    }

    static func formatExportText(
        from snapshot: LookupSnapshot,
        trackedDomain: TrackedDomain?,
        changeSummary: DomainChangeSummary?,
        diffSections: [DomainDiffSection]
    ) -> String {
        let exportDateFormatter = DateFormatter()
        exportDateFormatter.dateFormat = "yyyy-MM-dd HH:mm"

        var lines: [String] = [
            "DomainDig Export",
            "Domain: \(snapshot.domain)",
            "Date: \(exportDateFormatter.string(from: snapshot.timestamp))",
            "Mode: \(snapshot.isLive ? "Live" : "Snapshot")",
            "Resolver: \(snapshot.resolverDisplayName)",
            "Lookup Duration: \(durationLabel(snapshot.totalLookupDurationMs))",
            "Tracked: \(trackedDomain == nil ? "No" : "Yes")"
        ]

        if let note = trackedDomain?.note?.nilIfEmpty {
            lines.append("Tracking Note: \(note)")
        }

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
            if let changeSummary {
                lines.append("  Change Summary: \(changeSummary.message)")
                lines.append("  Severity: \(changeSummary.severity.title)")
                lines.append("  Changed Sections: \(changeSummary.changedSections.isEmpty ? "None" : changeSummary.changedSections.joined(separator: ", "))")
                lines.append("  Compared At: \(exportDateFormatter.string(from: changeSummary.generatedAt))")
            }
        }

        appendSection("Tracking") {
            if let trackedDomain {
                lines.append("  Pinned: \(trackedDomain.isPinned ? "Yes" : "No")")
                lines.append("  Last Refresh: \(exportDateFormatter.string(from: trackedDomain.updatedAt))")
                lines.append("  Last Known Availability: \(availabilityLabel(trackedDomain.lastKnownAvailability))")
                if let note = trackedDomain.note?.nilIfEmpty {
                    lines.append("  Note: \(note)")
                }
            } else {
                lines.append("  This domain is not currently tracked.")
            }
        }

        appendSection("Diff Summary") {
            if diffSections.isEmpty {
                lines.append("  No comparison available")
            } else {
                for section in diffSections where section.items.contains(where: { $0.changeType != .unchanged }) {
                    lines.append("  \(section.title)")
                    for item in section.items where item.changeType != .unchanged {
                        lines.append("    [\(item.changeType.rawValue.capitalized)] \(item.label): \(item.oldValue ?? "None") -> \(item.newValue ?? "None")")
                    }
                }
            }
        }

        appendSection("Domain") {
            for row in domainRows(from: snapshot) {
                lines.append("  \(row.label): \(row.value)")
            }
            if snapshot.suggestions.isEmpty {
                lines.append("  Suggestions: None")
            } else {
                lines.append("  Suggestions:")
                for suggestion in snapshot.suggestions {
                    lines.append("    \(suggestion.domain): \(availabilityLabel(suggestion.status))")
                }
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

    private static func httpStatusGradeSummary(from snapshot: LookupSnapshot) -> String {
        let parts = [snapshot.httpStatusCode.map(String.init), snapshot.httpSecurityGrade].compactMap { $0 }
        if !parts.isEmpty {
            return parts.joined(separator: " / ")
        }
        return snapshot.httpHeadersError ?? "Unavailable"
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

    private static func certificateStatusLabel(from snapshot: LookupSnapshot) -> String {
        guard let sslInfo = snapshot.sslInfo else {
            return snapshot.sslError ?? "Unavailable"
        }

        switch DomainDiffService.certificateWarningLevel(for: snapshot) {
        case .critical:
            return "Critical (\(sslInfo.daysUntilExpiry)d)"
        case .warning:
            return "Warning (\(sslInfo.daysUntilExpiry)d)"
        case .none:
            return "Healthy (\(sslInfo.daysUntilExpiry)d)"
        }
    }

    private static func certificateBadgeLabel(from snapshot: LookupSnapshot) -> String? {
        guard snapshot.sslInfo != nil else { return nil }
        return certificateStatusLabel(from: snapshot)
    }

    private static func certificateStatusTone(from snapshot: LookupSnapshot) -> ResultTone {
        guard let daysRemaining = snapshot.sslInfo?.daysUntilExpiry else {
            return snapshot.sslError == nil ? .secondary : .failure
        }
        return certificateTone(daysRemaining: daysRemaining)
    }

    private static func certificateTone(daysRemaining: Int) -> ResultTone {
        if daysRemaining < 14 {
            return .failure
        }
        if daysRemaining < 30 {
            return .warning
        }
        return .success
    }

    private static func availabilityLabel(_ status: DomainAvailabilityStatus?) -> String {
        switch status {
        case .available:
            return "Available"
        case .registered:
            return "Registered"
        case .unknown, .none:
            return "Unknown"
        }
    }

    private static func availabilityTone(_ status: DomainAvailabilityStatus?) -> ResultTone {
        switch status {
        case .available:
            return .success
        case .registered:
            return .warning
        case .unknown, .none:
            return .secondary
        }
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

    private static let certificateDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private static let csvDateFormatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    private static func csvEscaped(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
        return "\"\(escaped)\""
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
