import Foundation

struct LookupSnapshot {
    let historyEntryID: UUID?
    let domain: String
    let timestamp: Date
    let trackedDomainID: UUID?
    let note: String?
    let appVersion: String
    let resolverDisplayName: String
    let resolverURLString: String
    let dataSources: [String]
    let provenanceBySection: [LookupSectionKind: SectionProvenance]
    let availabilityConfidence: ConfidenceLevel?
    let ownershipConfidence: ConfidenceLevel?
    let subdomainConfidence: ConfidenceLevel?
    let emailSecurityConfidence: ConfidenceLevel?
    let geolocationConfidence: ConfidenceLevel?
    let errorDetails: [LookupSectionKind: InspectionFailure]
    let isPartialSnapshot: Bool
    let validationIssues: [String]
    let totalLookupDurationMs: Int?
    let snapshotIndex: Int?
    let previousSnapshotID: UUID?
    let changeCount: Int
    let severitySummary: ChangeSeverity?
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
    let ownership: DomainOwnership?
    let ownershipError: String?
    let ownershipHistory: [DomainOwnershipHistoryEvent]
    let ownershipHistoryError: String?
    let ptrRecord: String?
    let ptrError: String?
    let redirectChain: [RedirectHop]
    let redirectChainError: String?
    let subdomains: [DiscoveredSubdomain]
    let subdomainsError: String?
    let extendedSubdomains: [DiscoveredSubdomain]
    let extendedSubdomainsError: String?
    let dnsHistory: [DNSHistoryEvent]
    let dnsHistoryError: String?
    let domainPricing: DomainPricingInsight?
    let domainPricingError: String?
    let portScanResults: [PortScanResult]
    let portScanError: String?
    let changeSummary: DomainChangeSummary?
    let resultSource: LookupResultSource
    let cachedSections: [LookupSectionKind]
    let statusMessage: String?

    var isLive: Bool {
        resultSource == .live
    }
}

extension HistoryEntry {
    var snapshot: LookupSnapshot {
        LookupSnapshot(
            historyEntryID: id,
            domain: domain,
            timestamp: timestamp,
            trackedDomainID: trackedDomainID,
            note: note,
            appVersion: appVersion,
            resolverDisplayName: resolverDisplayName,
            resolverURLString: resolverURLString,
            dataSources: dataSources,
            provenanceBySection: provenanceBySection,
            availabilityConfidence: availabilityConfidence,
            ownershipConfidence: ownershipConfidence,
            subdomainConfidence: subdomainConfidence,
            emailSecurityConfidence: emailSecurityConfidence,
            geolocationConfidence: geolocationConfidence,
            errorDetails: errorDetails,
            isPartialSnapshot: isPartialSnapshot,
            validationIssues: validationIssues,
            totalLookupDurationMs: totalLookupDurationMs,
            snapshotIndex: snapshotIndex,
            previousSnapshotID: previousSnapshotID,
            changeCount: changeCount,
            severitySummary: severitySummary,
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
            ownership: ownership,
            ownershipError: ownershipError,
            ownershipHistory: ownershipHistory,
            ownershipHistoryError: ownershipHistoryError,
            ptrRecord: ptrRecord,
            ptrError: ptrError,
            redirectChain: redirectChain,
            redirectChainError: redirectChainError,
            subdomains: subdomains,
            subdomainsError: subdomainsError,
            extendedSubdomains: extendedSubdomains,
            extendedSubdomainsError: extendedSubdomainsError,
            dnsHistory: dnsHistory,
            dnsHistoryError: dnsHistoryError,
            domainPricing: domainPricing,
            domainPricingError: domainPricingError,
            portScanResults: portScanResults,
            portScanError: portScanError,
            changeSummary: changeSummary,
            resultSource: resultSource,
            cachedSections: [],
            statusMessage: nil
        )
    }
}
