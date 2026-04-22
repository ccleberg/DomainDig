import Foundation

@main
struct DomainDigCLI {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())

        guard let command = CommandLine.arguments.first else {
            fputs("usage: domaindig <domain> [--json] [--ownership-history] [--dns-history] [--extended-subdomains] [--pricing] [--show-usage]\n", stderr)
            Foundation.exit(1)
        }
        _ = command

        let wantsJSON = arguments.contains("--json") || arguments.contains("-j")
        let wantsOwnershipHistory = arguments.contains("--ownership-history")
        let wantsDNSHistory = arguments.contains("--dns-history")
        let wantsExtendedSubdomains = arguments.contains("--extended-subdomains")
        let wantsPricing = arguments.contains("--pricing")
        let wantsUsage = arguments.contains("--show-usage")
        let domains = arguments.filter { !$0.hasPrefix("-") }

        let requestedDomains = domains
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard !requestedDomains.isEmpty else {
            fputs("usage: domaindig <domain> [--json] [--ownership-history] [--dns-history] [--extended-subdomains] [--pricing] [--show-usage]\n", stderr)
            Foundation.exit(1)
        }

        let inspectionService = DomainInspectionService()
        let reportBuilder = DomainReportBuilder()
        var reports: [DomainReport] = []
        var seen = Set<String>()
        var usageImpact: [String] = []

        for domain in requestedDomains {
            let normalizedDomain = domain.lowercased()
            guard seen.insert(normalizedDomain).inserted else { continue }
            let snapshot = await inspectionService.inspectSnapshot(domain: domain)
            let enrichedSnapshot = await enrichSnapshot(
                snapshot,
                wantsOwnershipHistory: wantsOwnershipHistory,
                wantsDNSHistory: wantsDNSHistory,
                wantsExtendedSubdomains: wantsExtendedSubdomains,
                wantsPricing: wantsPricing,
                usageImpact: &usageImpact
            )
            reports.append(reportBuilder.build(from: enrichedSnapshot))
        }

        do {
            let data: Data
            if reports.count == 1, let report = reports.first {
                data = try DomainReportExporter.data(
                    for: report,
                    format: wantsJSON ? .json : .text
                )
            } else {
                data = try DomainReportExporter.data(
                    for: reports,
                    format: wantsJSON ? .json : .text,
                    title: "DomainDig Batch Report"
                )
            }
            if wantsUsage, !usageImpact.isEmpty {
                FileHandle.standardError.write(Data(("Data+ usage impact: " + usageImpact.joined(separator: ", ") + "\n").utf8))
            }
            FileHandle.standardOutput.write(data)
            if data.last != 0x0A {
                FileHandle.standardOutput.write(Data([0x0A]))
            }
        } catch {
            fputs("domaindig: \(error.localizedDescription)\n", stderr)
            Foundation.exit(1)
        }
    }

    private static func enrichSnapshot(
        _ snapshot: LookupSnapshot,
        wantsOwnershipHistory: Bool,
        wantsDNSHistory: Bool,
        wantsExtendedSubdomains: Bool,
        wantsPricing: Bool,
        usageImpact: inout [String]
    ) async -> LookupSnapshot {
        guard FeatureAccessService.currentTier == .dataPlus else {
            return snapshot
        }

        let historyEntries = loadHistoryEntries()
        var ownershipHistory = snapshot.ownershipHistory
        var ownershipHistoryError = snapshot.ownershipHistoryError
        var dnsHistory = snapshot.dnsHistory
        var dnsHistoryError = snapshot.dnsHistoryError
        var extendedSubdomains = snapshot.extendedSubdomains
        var extendedSubdomainsError = snapshot.extendedSubdomainsError
        var domainPricing = snapshot.domainPricing
        var domainPricingError = snapshot.domainPricingError

        if wantsOwnershipHistory,
           await UsageCreditService.shared.canUse(.ownershipHistory) {
            let outcome = await ExternalDataService.shared.ownershipHistory(
                domain: snapshot.domain,
                currentOwnership: snapshot.ownership,
                historyEntries: historyEntries
            )
            switch outcome.value {
            case let .success(events):
                ownershipHistory = events
                ownershipHistoryError = nil
                if outcome.source != .cached {
                    _ = await UsageCreditService.shared.consume(.ownershipHistory)
                    usageImpact.append("ownership history -1")
                }
            case let .empty(message):
                ownershipHistoryError = message
                if outcome.source != .cached {
                    _ = await UsageCreditService.shared.consume(.ownershipHistory)
                    usageImpact.append("ownership history -1")
                }
            case let .error(message):
                ownershipHistoryError = message
            }
        }

        if wantsDNSHistory,
           await UsageCreditService.shared.canUse(.dnsHistory) {
            let outcome = await ExternalDataService.shared.dnsHistory(
                domain: snapshot.domain,
                dnsSections: snapshot.dnsSections,
                historyEntries: historyEntries
            )
            switch outcome.value {
            case let .success(events):
                dnsHistory = events
                dnsHistoryError = nil
                if outcome.source != .cached {
                    _ = await UsageCreditService.shared.consume(.dnsHistory)
                    usageImpact.append("dns history -1")
                }
            case let .empty(message):
                dnsHistoryError = message
                if outcome.source != .cached {
                    _ = await UsageCreditService.shared.consume(.dnsHistory)
                    usageImpact.append("dns history -1")
                }
            case let .error(message):
                dnsHistoryError = message
            }
        }

        if wantsExtendedSubdomains,
           await UsageCreditService.shared.canUse(.extendedSubdomains) {
            let outcome = await ExternalDataService.shared.extendedSubdomains(
                domain: snapshot.domain,
                existing: snapshot.subdomains
            )
            switch outcome.value {
            case let .success(results):
                extendedSubdomains = results
                extendedSubdomainsError = nil
                if outcome.source != .cached {
                    _ = await UsageCreditService.shared.consume(.extendedSubdomains)
                    usageImpact.append("extended subdomains -1")
                }
            case let .empty(message):
                extendedSubdomainsError = message
                if outcome.source != .cached {
                    _ = await UsageCreditService.shared.consume(.extendedSubdomains)
                    usageImpact.append("extended subdomains -1")
                }
            case let .error(message):
                extendedSubdomainsError = message
            }
        }

        if wantsPricing {
            let outcome = await ExternalDataService.shared.pricing(domain: snapshot.domain)
            switch outcome.value {
            case let .success(pricing):
                domainPricing = pricing
                domainPricingError = nil
            case let .empty(message), let .error(message):
                domainPricingError = message
            }
        }

        return LookupSnapshot(
            historyEntryID: snapshot.historyEntryID,
            domain: snapshot.domain,
            timestamp: snapshot.timestamp,
            trackedDomainID: snapshot.trackedDomainID,
            note: snapshot.note,
            appVersion: snapshot.appVersion,
            resolverDisplayName: snapshot.resolverDisplayName,
            resolverURLString: snapshot.resolverURLString,
            dataSources: snapshot.dataSources,
            provenanceBySection: snapshot.provenanceBySection,
            availabilityConfidence: snapshot.availabilityConfidence,
            ownershipConfidence: snapshot.ownershipConfidence,
            subdomainConfidence: snapshot.subdomainConfidence,
            emailSecurityConfidence: snapshot.emailSecurityConfidence,
            geolocationConfidence: snapshot.geolocationConfidence,
            errorDetails: snapshot.errorDetails,
            isPartialSnapshot: snapshot.isPartialSnapshot,
            validationIssues: snapshot.validationIssues,
            totalLookupDurationMs: snapshot.totalLookupDurationMs,
            dnsSections: snapshot.dnsSections,
            dnsError: snapshot.dnsError,
            availabilityResult: snapshot.availabilityResult,
            suggestions: snapshot.suggestions,
            sslInfo: snapshot.sslInfo,
            sslError: snapshot.sslError,
            hstsPreloaded: snapshot.hstsPreloaded,
            httpHeaders: snapshot.httpHeaders,
            httpSecurityGrade: snapshot.httpSecurityGrade,
            httpStatusCode: snapshot.httpStatusCode,
            httpResponseTimeMs: snapshot.httpResponseTimeMs,
            httpProtocol: snapshot.httpProtocol,
            http3Advertised: snapshot.http3Advertised,
            httpHeadersError: snapshot.httpHeadersError,
            reachabilityResults: snapshot.reachabilityResults,
            reachabilityError: snapshot.reachabilityError,
            ipGeolocation: snapshot.ipGeolocation,
            ipGeolocationError: snapshot.ipGeolocationError,
            emailSecurity: snapshot.emailSecurity,
            emailSecurityError: snapshot.emailSecurityError,
            ownership: snapshot.ownership,
            ownershipError: snapshot.ownershipError,
            ownershipHistory: ownershipHistory,
            ownershipHistoryError: ownershipHistoryError,
            ptrRecord: snapshot.ptrRecord,
            ptrError: snapshot.ptrError,
            redirectChain: snapshot.redirectChain,
            redirectChainError: snapshot.redirectChainError,
            subdomains: snapshot.subdomains,
            subdomainsError: snapshot.subdomainsError,
            extendedSubdomains: extendedSubdomains,
            extendedSubdomainsError: extendedSubdomainsError,
            dnsHistory: dnsHistory,
            dnsHistoryError: dnsHistoryError,
            domainPricing: domainPricing,
            domainPricingError: domainPricingError,
            portScanResults: snapshot.portScanResults,
            portScanError: snapshot.portScanError,
            changeSummary: snapshot.changeSummary,
            resultSource: snapshot.resultSource,
            cachedSections: snapshot.cachedSections,
            statusMessage: snapshot.statusMessage
        )
    }

    private static func loadHistoryEntries() -> [HistoryEntry] {
        guard let data = UserDefaults.standard.data(forKey: "lookupHistory"),
              let entries = try? JSONDecoder().decode([HistoryEntry].self, from: data) else {
            return []
        }
        return entries
    }
}
