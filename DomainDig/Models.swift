import Foundation

enum ServiceResult<Value> {
    case success(Value)
    case empty(String)
    case error(String)
}

enum ConfidenceLevel: String, Codable {
    case high
    case medium
    case low

    var title: String {
        rawValue.capitalized
    }
}

enum InspectionErrorKind: String, Codable {
    case network
    case timeout
    case rateLimited
    case parsing
    case unsupported
    case unavailable
    case unknown

    var title: String {
        switch self {
        case .network:
            return "Network"
        case .timeout:
            return "Timeout"
        case .rateLimited:
            return "Rate limited"
        case .parsing:
            return "Parsing"
        case .unsupported:
            return "Unsupported"
        case .unavailable:
            return "Unavailable"
        case .unknown:
            return "Unknown"
        }
    }
}

struct InspectionFailure: Codable, Equatable {
    let kind: InspectionErrorKind
    let message: String
    let details: String?
}

struct SectionProvenance: Codable, Equatable {
    let source: String
    let collectedAt: Date
    let provider: String?
    let resolver: String?
    let resultSource: LookupResultSource
}

enum LookupResultSource: String, Codable {
    case live
    case cached
    case mixed
    case snapshot

    var label: String {
        switch self {
        case .live:
            return "Live"
        case .cached:
            return "Cached"
        case .mixed:
            return "Mixed"
        case .snapshot:
            return "Snapshot"
        }
    }
}

enum LookupSectionKind: String, Codable, CaseIterable {
    case dns
    case availability
    case ssl
    case hsts
    case httpHeaders
    case reachability
    case ipGeolocation
    case emailSecurity
    case ownership
    case ptr
    case redirectChain
    case subdomains
    case portScan
    case suggestions
}

enum DomainAvailabilityStatus: String, Codable {
    case available
    case registered
    case unknown
}

struct DomainAvailabilityResult: Codable {
    let domain: String
    let status: DomainAvailabilityStatus
}

struct DomainSuggestionResult: Identifiable, Codable {
    let id: UUID
    let domain: String
    let status: DomainAvailabilityStatus

    init(id: UUID = UUID(), domain: String, status: DomainAvailabilityStatus) {
        self.id = id
        self.domain = domain
        self.status = status
    }
}

struct WatchedDomain: Codable, Identifiable {
    let id: UUID
    let domain: String
    let createdAt: Date
    var lastKnownAvailability: DomainAvailabilityStatus?

    init(
        id: UUID = UUID(),
        domain: String,
        createdAt: Date = Date(),
        lastKnownAvailability: DomainAvailabilityStatus? = nil
    ) {
        self.id = id
        self.domain = domain
        self.createdAt = createdAt
        self.lastKnownAvailability = lastKnownAvailability
    }
}

enum ChangeSeverity: Int, Codable, CaseIterable, Comparable {
    case low
    case medium
    case high

    static func < (lhs: ChangeSeverity, rhs: ChangeSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var title: String {
        switch self {
        case .low:
            return "Low"
        case .medium:
            return "Medium"
        case .high:
            return "High"
        }
    }
}

enum CertificateWarningLevel: String, Codable {
    case none
    case warning
    case critical

    var title: String {
        switch self {
        case .none:
            return "Healthy"
        case .warning:
            return "Warning"
        case .critical:
            return "Critical"
        }
    }
}

struct DomainChangeSummary: Codable, Equatable {
    let hasChanges: Bool
    let changedSections: [String]
    let message: String
    let severity: ChangeSeverity
    let impactClassification: ChangeImpactClassification
    let generatedAt: Date
    let observedFacts: [String]
    let inferredConclusions: [String]
    let contextNote: String?
    let riskAssessment: DomainRiskAssessment?
    let insights: [String]
    let riskScoreDelta: Int?

    init(
        hasChanges: Bool,
        changedSections: [String],
        message: String,
        severity: ChangeSeverity,
        impactClassification: ChangeImpactClassification,
        generatedAt: Date,
        observedFacts: [String] = [],
        inferredConclusions: [String] = [],
        contextNote: String? = nil,
        riskAssessment: DomainRiskAssessment? = nil,
        insights: [String] = [],
        riskScoreDelta: Int? = nil
    ) {
        self.hasChanges = hasChanges
        self.changedSections = changedSections
        self.message = message
        self.severity = severity
        self.impactClassification = impactClassification
        self.generatedAt = generatedAt
        self.observedFacts = observedFacts
        self.inferredConclusions = inferredConclusions
        self.contextNote = contextNote
        self.riskAssessment = riskAssessment
        self.insights = insights
        self.riskScoreDelta = riskScoreDelta
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        hasChanges = try container.decodeIfPresent(Bool.self, forKey: .hasChanges) ?? false
        changedSections = try container.decodeIfPresent([String].self, forKey: .changedSections) ?? []
        generatedAt = try container.decode(Date.self, forKey: .generatedAt)
        severity = try container.decodeIfPresent(ChangeSeverity.self, forKey: .severity) ?? (hasChanges ? .medium : .low)
        impactClassification = try container.decodeIfPresent(ChangeImpactClassification.self, forKey: .impactClassification)
            ?? (severity == .high ? .critical : (hasChanges ? .warning : .informational))
        message = try container.decodeIfPresent(String.self, forKey: .message)
            ?? (changedSections.isEmpty ? "No meaningful changes" : changedSections.joined(separator: " • "))
        observedFacts = try container.decodeIfPresent([String].self, forKey: .observedFacts) ?? []
        inferredConclusions = try container.decodeIfPresent([String].self, forKey: .inferredConclusions) ?? []
        contextNote = try container.decodeIfPresent(String.self, forKey: .contextNote)
        riskAssessment = try container.decodeIfPresent(DomainRiskAssessment.self, forKey: .riskAssessment)
        insights = try container.decodeIfPresent([String].self, forKey: .insights) ?? []
        riskScoreDelta = try container.decodeIfPresent(Int.self, forKey: .riskScoreDelta)
    }
}

enum BatchLookupSource: String, Codable {
    case manual
    case watchlistRefresh
    case workflow
}

enum BatchLookupStatus: String, Codable {
    case pending
    case running
    case completed
    case failed
}

struct BatchLookupResult: Identifiable, Codable, Equatable {
    let id: UUID
    let domain: String
    let historyEntryID: UUID?
    let resultSource: LookupResultSource
    let availability: DomainAvailabilityStatus?
    let primaryIP: String?
    let quickStatus: String
    let summaryMessage: String?
    let changeSeverity: ChangeSeverity?
    let changeClassification: ChangeImpactClassification?
    let certificateWarningLevel: CertificateWarningLevel
    let riskScore: Int?
    let riskLevel: RiskLevel?
    let timestamp: Date
    let status: BatchLookupStatus
    let errorMessage: String?

    init(
        id: UUID = UUID(),
        domain: String,
        historyEntryID: UUID?,
        resultSource: LookupResultSource = .live,
        availability: DomainAvailabilityStatus?,
        primaryIP: String?,
        quickStatus: String,
        summaryMessage: String? = nil,
        changeSeverity: ChangeSeverity? = nil,
        changeClassification: ChangeImpactClassification? = nil,
        certificateWarningLevel: CertificateWarningLevel = .none,
        riskScore: Int? = nil,
        riskLevel: RiskLevel? = nil,
        timestamp: Date,
        status: BatchLookupStatus,
        errorMessage: String? = nil
    ) {
        self.id = id
        self.domain = domain
        self.historyEntryID = historyEntryID
        self.resultSource = resultSource
        self.availability = availability
        self.primaryIP = primaryIP
        self.quickStatus = quickStatus
        self.summaryMessage = summaryMessage
        self.changeSeverity = changeSeverity
        self.changeClassification = changeClassification
        self.certificateWarningLevel = certificateWarningLevel
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.timestamp = timestamp
        self.status = status
        self.errorMessage = errorMessage
    }

    var hasMeaningfulChange: Bool {
        quickStatus == "Changed"
            || quickStatus == "High"
            || quickStatus == "Critical"
            || certificateWarningLevel != .none
            || riskLevel == .high
            || status == .failed
    }
}

struct BatchSweepSummary: Identifiable, Equatable {
    let id = UUID()
    let source: BatchLookupSource
    let totalDomains: Int
    let changedDomains: Int
    let unchangedDomains: Int
    let warningDomains: Int
    let results: [BatchLookupResult]
    let generatedAt: Date
}

struct DomainWorkflow: Codable, Identifiable, Equatable {
    let id: UUID
    var name: String
    var domains: [String]
    var createdAt: Date
    var updatedAt: Date
    var notes: String?
    var collaboration: CollaborationMetadata?

    init(
        id: UUID = UUID(),
        name: String,
        domains: [String],
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        notes: String? = nil,
        collaboration: CollaborationMetadata? = nil
    ) {
        self.id = id
        self.name = name
        self.domains = domains
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.notes = notes
        self.collaboration = collaboration
    }
}

struct WorkflowRunSummary: Identifiable, Equatable {
    let id = UUID()
    let workflowID: UUID
    let workflowName: String
    let totalDomains: Int
    let changedDomains: Int
    let unchangedDomains: Int
    let warningDomains: Int
    let results: [BatchLookupResult]
    let workflowInsights: [WorkflowInsight]
    let generatedAt: Date
}

enum DataCapability: String, Codable {
    case ownershipHistory
    case dnsHistory
    case extendedSubdomains
    case domainPricing
}

enum UsageCreditFeature: String, Codable, CaseIterable, Identifiable, Sendable {
    case ownershipHistory
    case dnsHistory
    case extendedSubdomains

    nonisolated var id: String { rawValue }

    nonisolated var title: String {
        switch self {
        case .ownershipHistory:
            return "Ownership history"
        case .dnsHistory:
            return "DNS history"
        case .extendedSubdomains:
            return "Extended subdomains"
        }
    }

    nonisolated var defaultAllowance: Int {
        switch self {
        case .ownershipHistory, .dnsHistory:
            return 8
        case .extendedSubdomains:
            return 12
        }
    }
}

struct UsageCreditStatus: Codable, Equatable, Sendable {
    let feature: UsageCreditFeature
    let remaining: Int
    let total: Int
    let resetContext: String

    nonisolated var summary: String {
        "\(remaining) uses remaining"
    }

    nonisolated var isExhausted: Bool {
        remaining <= 0
    }
}

struct DomainOwnershipHistoryEvent: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let date: Date
    let summary: String
    let registrar: String?
    let registrant: String?
    let nameservers: [String]
    let source: String
    let isExternal: Bool

    nonisolated init(
        id: UUID = UUID(),
        date: Date,
        summary: String,
        registrar: String? = nil,
        registrant: String? = nil,
        nameservers: [String] = [],
        source: String,
        isExternal: Bool
    ) {
        self.id = id
        self.date = date
        self.summary = summary
        self.registrar = registrar
        self.registrant = registrant
        self.nameservers = nameservers
        self.source = source
        self.isExternal = isExternal
    }
}

struct DNSHistoryEvent: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let date: Date
    let summary: String
    let aRecords: [String]
    let nameservers: [String]
    let source: String
    let isExternal: Bool

    nonisolated init(
        id: UUID = UUID(),
        date: Date,
        summary: String,
        aRecords: [String] = [],
        nameservers: [String] = [],
        source: String,
        isExternal: Bool
    ) {
        self.id = id
        self.date = date
        self.summary = summary
        self.aRecords = aRecords
        self.nameservers = nameservers
        self.source = source
        self.isExternal = isExternal
    }
}

struct DomainPricingInsight: Codable, Equatable, Sendable {
    let estimatedPrice: String?
    let premiumIndicator: Bool?
    let resaleSignal: String?
    let auctionSignal: String?
    let source: String
    let collectedAt: Date
}

enum HistoryDateFilter: String, CaseIterable, Identifiable {
    case today
    case last7Days
    case all

    var id: String { rawValue }

    var title: String {
        switch self {
        case .today:
            return "Today"
        case .last7Days:
            return "Last 7 Days"
        case .all:
            return "All"
        }
    }
}

enum ChangeFilterOption: String, CaseIterable, Identifiable {
    case all
    case changed
    case unchanged

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all:
            return "All"
        case .changed:
            return "Changed"
        case .unchanged:
            return "Unchanged"
        }
    }
}

enum HistorySortOption: String, CaseIterable, Identifiable {
    case newest
    case oldest
    case domain

    var id: String { rawValue }

    var title: String {
        switch self {
        case .newest:
            return "Newest"
        case .oldest:
            return "Oldest"
        case .domain:
            return "Domain A-Z"
        }
    }
}

enum TimelineGroupingOption: String, CaseIterable, Identifiable {
    case none
    case relativeDay

    var id: String { rawValue }

    var title: String {
        switch self {
        case .none:
            return "Ungrouped"
        case .relativeDay:
            return "Today / Yesterday / Older"
        }
    }
}

enum HistoryAutoPruneOption: String, CaseIterable, Codable, Identifiable {
    case keep50
    case keep100
    case unlimited

    var id: String { rawValue }

    var title: String {
        switch self {
        case .keep50:
            return "Keep Last 50"
        case .keep100:
            return "Keep Last 100"
        case .unlimited:
            return "Unlimited"
        }
    }

    var keepCount: Int? {
        switch self {
        case .keep50:
            return 50
        case .keep100:
            return 100
        case .unlimited:
            return nil
        }
    }
}

struct SnapshotSummary: Identifiable, Codable, Equatable {
    let id: UUID
    let domain: String
    let timestamp: Date
    let trackedDomainID: UUID?
    let snapshotIndex: Int?
    let previousSnapshotID: UUID?
    let changeCount: Int
    let severitySummary: ChangeSeverity?
    let changeSummaryMessage: String?
    let availability: DomainAvailabilityStatus?
    let primaryIP: String?
    let tlsStatus: String?
    let riskScore: Int?
    let historyEntryID: UUID

    var hasChanges: Bool {
        changeCount > 0
    }
}

struct FullSnapshot: Codable {
    let historyEntry: HistoryEntry
}

struct TimelineSection: Identifiable, Equatable {
    let id: String
    let title: String
    let entries: [SnapshotSummary]
}

enum WatchlistFilterOption: String, CaseIterable, Identifiable {
    case all
    case pinnedOnly
    case changedOnly

    var id: String { rawValue }

    var title: String {
        switch self {
        case .all:
            return "All"
        case .pinnedOnly:
            return "Pinned Only"
        case .changedOnly:
            return "Changed Only"
        }
    }
}

enum WatchlistSortOption: String, CaseIterable, Identifiable {
    case pinned
    case recentlyUpdated
    case alphabetical

    var id: String { rawValue }

    var title: String {
        switch self {
        case .pinned:
            return "Pinned"
        case .recentlyUpdated:
            return "Recently Updated"
        case .alphabetical:
            return "Alphabetical"
        }
    }
}

enum PremiumCapability: String, Codable {
    case unlimitedTrackedDomains
    case automatedMonitoring
    case pushAlerts
    case batchTracking
    case advancedExports
}

enum CollaborationPermission: String, Codable, Equatable {
    case readOnly
    case editable

    var title: String {
        switch self {
        case .readOnly:
            return "Read only"
        case .editable:
            return "Editable"
        }
    }
}

enum CollaborationOwnership: String, Codable, Equatable {
    case owner
    case participant

    var title: String {
        switch self {
        case .owner:
            return "Owned by you"
        case .participant:
            return "Shared with you"
        }
    }
}

enum CollaborationScope: String, Codable, Equatable {
    case privateDatabase
    case sharedDatabase
}

struct CollaborationMetadata: Codable, Equatable {
    var scope: CollaborationScope
    var ownership: CollaborationOwnership
    var permission: CollaborationPermission
    var shareRecordName: String?

    init(
        scope: CollaborationScope,
        ownership: CollaborationOwnership,
        permission: CollaborationPermission,
        shareRecordName: String? = nil
    ) {
        self.scope = scope
        self.ownership = ownership
        self.permission = permission
        self.shareRecordName = shareRecordName
    }

    var isShared: Bool {
        shareRecordName != nil || scope == .sharedDatabase
    }

    var canEdit: Bool {
        permission == .editable
    }

    var isOwner: Bool {
        ownership == .owner
    }
}

struct TrackedDomain: Codable, Identifiable, Equatable {
    let id: UUID
    var domain: String
    var createdAt: Date
    var updatedAt: Date
    var note: String?
    var isPinned: Bool
    var monitoringEnabled: Bool
    var lastKnownAvailability: DomainAvailabilityStatus?
    var lastSnapshotID: UUID?
    var lastChangeSummary: DomainChangeSummary?
    var lastChangeSeverity: ChangeSeverity?
    var certificateWarningLevel: CertificateWarningLevel
    var certificateDaysRemaining: Int?
    var lastMonitoredAt: Date?
    var lastAlertAt: Date?
    var collaboration: CollaborationMetadata?

    init(
        id: UUID = UUID(),
        domain: String,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        note: String? = nil,
        isPinned: Bool = false,
        monitoringEnabled: Bool = true,
        lastKnownAvailability: DomainAvailabilityStatus? = nil,
        lastSnapshotID: UUID? = nil,
        lastChangeSummary: DomainChangeSummary? = nil,
        lastChangeSeverity: ChangeSeverity? = nil,
        certificateWarningLevel: CertificateWarningLevel = .none,
        certificateDaysRemaining: Int? = nil,
        lastMonitoredAt: Date? = nil,
        lastAlertAt: Date? = nil,
        collaboration: CollaborationMetadata? = nil
    ) {
        self.id = id
        self.domain = domain
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.note = note
        self.isPinned = isPinned
        self.monitoringEnabled = monitoringEnabled
        self.lastKnownAvailability = lastKnownAvailability
        self.lastSnapshotID = lastSnapshotID
        self.lastChangeSummary = lastChangeSummary
        self.lastChangeSeverity = lastChangeSeverity
        self.certificateWarningLevel = certificateWarningLevel
        self.certificateDaysRemaining = certificateDaysRemaining
        self.lastMonitoredAt = lastMonitoredAt
        self.lastAlertAt = lastAlertAt
        self.collaboration = collaboration
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        domain = try container.decode(String.self, forKey: .domain)
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? createdAt
        note = try container.decodeIfPresent(String.self, forKey: .note)
        isPinned = try container.decodeIfPresent(Bool.self, forKey: .isPinned) ?? false
        monitoringEnabled = try container.decodeIfPresent(Bool.self, forKey: .monitoringEnabled) ?? true
        lastKnownAvailability = try container.decodeIfPresent(DomainAvailabilityStatus.self, forKey: .lastKnownAvailability)
        lastSnapshotID = try container.decodeIfPresent(UUID.self, forKey: .lastSnapshotID)
        lastChangeSummary = try container.decodeIfPresent(DomainChangeSummary.self, forKey: .lastChangeSummary)
        lastChangeSeverity = try container.decodeIfPresent(ChangeSeverity.self, forKey: .lastChangeSeverity) ?? lastChangeSummary?.severity
        certificateWarningLevel = try container.decodeIfPresent(CertificateWarningLevel.self, forKey: .certificateWarningLevel) ?? .none
        certificateDaysRemaining = try container.decodeIfPresent(Int.self, forKey: .certificateDaysRemaining)
        lastMonitoredAt = try container.decodeIfPresent(Date.self, forKey: .lastMonitoredAt)
        lastAlertAt = try container.decodeIfPresent(Date.self, forKey: .lastAlertAt)
        collaboration = try container.decodeIfPresent(CollaborationMetadata.self, forKey: .collaboration)
    }
}

enum MonitoringFrequency: String, Codable, CaseIterable, Identifiable {
    case daily
    case twiceDaily

    var id: String { rawValue }

    var title: String {
        switch self {
        case .daily:
            return "Daily"
        case .twiceDaily:
            return "Twice Daily"
        }
    }

    var schedulingInterval: TimeInterval {
        switch self {
        case .daily:
            return 24 * 60 * 60
        case .twiceDaily:
            return 12 * 60 * 60
        }
    }
}

enum MonitoringScope: String, Codable, CaseIterable, Identifiable {
    case allTracked
    case selectedOnly

    var id: String { rawValue }

    var title: String {
        switch self {
        case .allTracked:
            return "All Tracked"
        case .selectedOnly:
            return "Selected Only"
        }
    }
}

enum MonitoringAlertSeverity: Int, Codable, CaseIterable, Comparable {
    case info
    case warning
    case critical

    static func < (lhs: MonitoringAlertSeverity, rhs: MonitoringAlertSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var title: String {
        switch self {
        case .info:
            return "Info"
        case .warning:
            return "Warning"
        case .critical:
            return "Critical"
        }
    }
}

enum MonitoringAlertFilter: String, Codable, CaseIterable, Identifiable {
    case criticalOnly
    case criticalAndWarnings
    case allChanges

    var id: String { rawValue }

    var title: String {
        switch self {
        case .criticalOnly:
            return "Critical Only"
        case .criticalAndWarnings:
            return "Critical + Warnings"
        case .allChanges:
            return "All Changes"
        }
    }

    var minimumSeverity: MonitoringAlertSeverity {
        switch self {
        case .criticalOnly:
            return .critical
        case .criticalAndWarnings:
            return .warning
        case .allChanges:
            return .info
        }
    }
}

enum MonitoringRunTrigger: String, Codable {
    case manual
    case background
    case cli

    var title: String {
        switch self {
        case .manual:
            return "Manual"
        case .background:
            return "Background"
        case .cli:
            return "CLI"
        }
    }
}

struct MonitoringSettings: Codable, Equatable {
    var isEnabled: Bool
    var frequency: MonitoringFrequency
    var scope: MonitoringScope
    var selectedDomainIDs: [UUID]
    var alertFilter: MonitoringAlertFilter
    var alertsEnabled: Bool

    init(
        isEnabled: Bool = false,
        frequency: MonitoringFrequency = .daily,
        scope: MonitoringScope = .allTracked,
        selectedDomainIDs: [UUID] = [],
        alertFilter: MonitoringAlertFilter = .criticalAndWarnings,
        alertsEnabled: Bool = false
    ) {
        self.isEnabled = isEnabled
        self.frequency = frequency
        self.scope = scope
        self.selectedDomainIDs = selectedDomainIDs
        self.alertFilter = alertFilter
        self.alertsEnabled = alertsEnabled
    }
}

struct MonitoringDomainResult: Codable, Identifiable, Equatable {
    let id: UUID
    let domain: String
    let historyEntryID: UUID?
    let checkedAt: Date
    let didChange: Bool
    let summaryMessage: String
    let alertSeverity: MonitoringAlertSeverity?
    let certificateWarningLevel: CertificateWarningLevel
    let resultSource: LookupResultSource
    let errorMessage: String?

    init(
        id: UUID = UUID(),
        domain: String,
        historyEntryID: UUID?,
        checkedAt: Date,
        didChange: Bool,
        summaryMessage: String,
        alertSeverity: MonitoringAlertSeverity?,
        certificateWarningLevel: CertificateWarningLevel,
        resultSource: LookupResultSource,
        errorMessage: String? = nil
    ) {
        self.id = id
        self.domain = domain
        self.historyEntryID = historyEntryID
        self.checkedAt = checkedAt
        self.didChange = didChange
        self.summaryMessage = summaryMessage
        self.alertSeverity = alertSeverity
        self.certificateWarningLevel = certificateWarningLevel
        self.resultSource = resultSource
        self.errorMessage = errorMessage
    }
}

struct MonitoringLog: Codable, Identifiable, Equatable {
    let id: UUID
    let timestamp: Date
    let trigger: MonitoringRunTrigger
    let domainsChecked: Int
    let changesFound: Int
    let alertsTriggered: Int
    let checkedDomains: [MonitoringDomainResult]
    let errors: [String]

    init(
        id: UUID = UUID(),
        timestamp: Date,
        trigger: MonitoringRunTrigger,
        domainsChecked: Int,
        changesFound: Int,
        alertsTriggered: Int,
        checkedDomains: [MonitoringDomainResult],
        errors: [String] = []
    ) {
        self.id = id
        self.timestamp = timestamp
        self.trigger = trigger
        self.domainsChecked = domainsChecked
        self.changesFound = changesFound
        self.alertsTriggered = alertsTriggered
        self.checkedDomains = checkedDomains
        self.errors = errors
    }

    var summary: String {
        if errors.isEmpty {
            return "\(changesFound) changes across \(domainsChecked) domains"
        }
        return "\(changesFound) changes, \(errors.count) errors"
    }
}

// MARK: - DNS Models

enum DNSRecordType: String, CaseIterable, Codable {
    case A
    case AAAA
    case MX
    case NS
    case TXT
    case CNAME
    case SOA
    case SRV
    case CAA
    case DS
    case PTR

    var queryType: Int {
        switch self {
        case .A: return 1
        case .AAAA: return 28
        case .MX: return 15
        case .NS: return 2
        case .TXT: return 16
        case .CNAME: return 5
        case .SOA: return 6
        case .SRV: return 33
        case .CAA: return 257
        case .DS: return 43
        case .PTR: return 12
        }
    }

    var usesRawDataValue: Bool {
        switch self {
        case .TXT, .SOA, .DS:
            return true
        default:
            return false
        }
    }
}

struct DNSRecord: Identifiable, Codable {
    var id = UUID()
    let value: String
    let ttl: Int
}

struct DNSSection: Identifiable, Codable {
    var id = UUID()
    let recordType: DNSRecordType
    var records: [DNSRecord]
    var wildcardRecords: [DNSRecord] = []
    var dnssecSigned: Bool?
    var error: String?
}

// MARK: - SSL Models

struct SSLCertificateInfo: Codable {
    struct CertChainEntry: Codable {
        let subject: String
        let issuer: String
    }

    let commonName: String
    let subjectAltNames: [String]
    let issuer: String
    let validFrom: Date
    let validUntil: Date
    let daysUntilExpiry: Int
    let chainDepth: Int
    let tlsVersion: String?
    let cipherSuite: String?
    let chain: [CertChainEntry]

    init(
        commonName: String,
        subjectAltNames: [String],
        issuer: String,
        validFrom: Date,
        validUntil: Date,
        daysUntilExpiry: Int,
        chainDepth: Int,
        tlsVersion: String? = nil,
        cipherSuite: String? = nil,
        chain: [CertChainEntry] = []
    ) {
        self.commonName = commonName
        self.subjectAltNames = subjectAltNames
        self.issuer = issuer
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.daysUntilExpiry = daysUntilExpiry
        self.chainDepth = chainDepth
        self.tlsVersion = tlsVersion
        self.cipherSuite = cipherSuite
        self.chain = chain
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        commonName = try container.decode(String.self, forKey: .commonName)
        subjectAltNames = try container.decode([String].self, forKey: .subjectAltNames)
        issuer = try container.decode(String.self, forKey: .issuer)
        validFrom = try container.decode(Date.self, forKey: .validFrom)
        validUntil = try container.decode(Date.self, forKey: .validUntil)
        daysUntilExpiry = try container.decode(Int.self, forKey: .daysUntilExpiry)
        chainDepth = try container.decode(Int.self, forKey: .chainDepth)
        tlsVersion = try container.decodeIfPresent(String.self, forKey: .tlsVersion)
        cipherSuite = try container.decodeIfPresent(String.self, forKey: .cipherSuite)
        chain = try container.decodeIfPresent([CertChainEntry].self, forKey: .chain) ?? []
    }
}

// MARK: - HTTP Headers Models

struct HTTPHeader: Identifiable, Codable {
    var id = UUID()
    let name: String
    let value: String

    static let securityHeaders: Set<String> = [
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy"
    ]

    var isSecurityHeader: Bool {
        Self.securityHeaders.contains(name.lowercased())
    }
}

// MARK: - Reachability Models

struct PortReachability: Identifiable, Codable {
    var id = UUID()
    let port: UInt16
    let reachable: Bool
    let latencyMs: Int?
}

// MARK: - IP Geolocation Models

struct IPGeolocation: Codable {
    let ip: String
    let city: String?
    let region: String?
    let country_name: String?
    let org: String?
    let latitude: Double?
    let longitude: Double?
}

// MARK: - Ownership Models

struct DomainOwnership: Codable, Equatable {
    let registrar: String?
    let registrant: String?
    let createdDate: Date?
    let expirationDate: Date?
    let status: [String]
    let nameservers: [String]
    let abuseEmail: String?

    init(
        registrar: String? = nil,
        registrant: String? = nil,
        createdDate: Date? = nil,
        expirationDate: Date? = nil,
        status: [String] = [],
        nameservers: [String] = [],
        abuseEmail: String? = nil
    ) {
        self.registrar = registrar
        self.registrant = registrant
        self.createdDate = createdDate
        self.expirationDate = expirationDate
        self.status = status
        self.nameservers = nameservers
        self.abuseEmail = abuseEmail
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        registrar = try container.decodeIfPresent(String.self, forKey: .registrar)
        registrant = try container.decodeIfPresent(String.self, forKey: .registrant)
        createdDate = try container.decodeIfPresent(Date.self, forKey: .createdDate)
        expirationDate = try container.decodeIfPresent(Date.self, forKey: .expirationDate)
        status = try container.decodeIfPresent([String].self, forKey: .status) ?? []
        nameservers = try container.decodeIfPresent([String].self, forKey: .nameservers) ?? []
        abuseEmail = try container.decodeIfPresent(String.self, forKey: .abuseEmail)
    }
}

struct DiscoveredSubdomain: Codable, Equatable, Hashable, Identifiable, Sendable {
    var id: String { hostname }
    let hostname: String
    let source: String?
    let isExtended: Bool

    nonisolated init(hostname: String, source: String? = nil, isExtended: Bool = false) {
        self.hostname = hostname
        self.source = source
        self.isExtended = isExtended
    }
}

// MARK: - Email Security Models

struct EmailSecurityResult: Codable {
    let spf: EmailSecurityRecord
    let dmarc: EmailSecurityRecord
    let dkim: EmailSecurityRecord
    let bimi: EmailSecurityRecord
    let mtaSts: MTASTSResult?

    init(
        spf: EmailSecurityRecord,
        dmarc: EmailSecurityRecord,
        dkim: EmailSecurityRecord,
        bimi: EmailSecurityRecord = EmailSecurityRecord(found: false, value: nil),
        mtaSts: MTASTSResult? = nil
    ) {
        self.spf = spf
        self.dmarc = dmarc
        self.dkim = dkim
        self.bimi = bimi
        self.mtaSts = mtaSts
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        spf = try container.decode(EmailSecurityRecord.self, forKey: .spf)
        dmarc = try container.decode(EmailSecurityRecord.self, forKey: .dmarc)
        dkim = try container.decode(EmailSecurityRecord.self, forKey: .dkim)
        bimi = try container.decodeIfPresent(EmailSecurityRecord.self, forKey: .bimi)
            ?? EmailSecurityRecord(found: false, value: nil)
        mtaSts = try container.decodeIfPresent(MTASTSResult.self, forKey: .mtaSts)
    }
}

struct EmailSecurityRecord: Codable {
    let found: Bool
    let value: String?
    let matchedSelector: String?

    init(found: Bool, value: String?, matchedSelector: String? = nil) {
        self.found = found
        self.value = value
        self.matchedSelector = matchedSelector
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        found = try container.decode(Bool.self, forKey: .found)
        value = try container.decodeIfPresent(String.self, forKey: .value)
        matchedSelector = try container.decodeIfPresent(String.self, forKey: .matchedSelector)
    }
}

struct MTASTSResult: Codable {
    let txtFound: Bool
    let policyMode: String?
}

// MARK: - Redirect Chain Models

struct RedirectHop: Identifiable, Codable {
    var id = UUID()
    let stepNumber: Int
    let statusCode: Int
    let url: String
    let isFinal: Bool
}

// MARK: - Port Scan Models

enum PortScanKind: String, Codable {
    case standard
    case custom
}

struct PortScanResult: Identifiable, Codable {
    var id = UUID()
    let port: UInt16
    let service: String
    let open: Bool
    var banner: String?
    let kind: PortScanKind
    let durationMs: Int?

    nonisolated init(
        port: UInt16,
        service: String,
        open: Bool,
        banner: String? = nil,
        kind: PortScanKind = .standard,
        durationMs: Int? = nil
    ) {
        self.port = port
        self.service = service
        self.open = open
        self.banner = banner
        self.kind = kind
        self.durationMs = durationMs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        port = try container.decode(UInt16.self, forKey: .port)
        service = try container.decode(String.self, forKey: .service)
        open = try container.decode(Bool.self, forKey: .open)
        banner = try container.decodeIfPresent(String.self, forKey: .banner)
        kind = try container.decodeIfPresent(PortScanKind.self, forKey: .kind) ?? .standard
        durationMs = try container.decodeIfPresent(Int.self, forKey: .durationMs)
    }
}

// MARK: - History Models

struct HistoryEntry: Identifiable, Codable {
    var id = UUID()
    let domain: String
    let timestamp: Date
    var trackedDomainID: UUID?
    var note: String?
    let dnsSections: [DNSSection]
    let sslInfo: SSLCertificateInfo?
    let httpHeaders: [HTTPHeader]
    let reachabilityResults: [PortReachability]
    let ipGeolocation: IPGeolocation?
    var emailSecurity: EmailSecurityResult?
    var mtaSts: MTASTSResult?
    var ownership: DomainOwnership?
    var ownershipHistory: [DomainOwnershipHistoryEvent]
    var ptrRecord: String?
    var redirectChain: [RedirectHop]
    var subdomains: [DiscoveredSubdomain]
    var extendedSubdomains: [DiscoveredSubdomain]
    var dnsHistory: [DNSHistoryEvent]
    var domainPricing: DomainPricingInsight?
    var portScanResults: [PortScanResult]
    var hstsPreloaded: Bool?
    var availabilityResult: DomainAvailabilityResult?
    var suggestions: [DomainSuggestionResult]
    var appVersion: String
    var resultSource: LookupResultSource
    var dataSources: [String]
    var provenanceBySection: [LookupSectionKind: SectionProvenance]
    var availabilityConfidence: ConfidenceLevel?
    var ownershipConfidence: ConfidenceLevel?
    var subdomainConfidence: ConfidenceLevel?
    var emailSecurityConfidence: ConfidenceLevel?
    var geolocationConfidence: ConfidenceLevel?
    var errorDetails: [LookupSectionKind: InspectionFailure]
    var isPartialSnapshot: Bool
    var validationIssues: [String]
    var resolverDisplayName: String
    var resolverURLString: String
    var totalLookupDurationMs: Int?
    var primaryIP: String?
    var finalRedirectURL: String?
    var tlsStatusSummary: String?
    var emailSecuritySummary: String?
    var httpGradeSummary: String?
    var changeSummary: DomainChangeSummary?
    var snapshotIndex: Int?
    var previousSnapshotID: UUID?
    var changeCount: Int
    var severitySummary: ChangeSeverity?
    var sslError: String?
    var httpHeadersError: String?
    var reachabilityError: String?
    var ipGeolocationError: String?
    var emailSecurityError: String?
    var ownershipError: String?
    var ownershipHistoryError: String?
    var ptrError: String?
    var redirectChainError: String?
    var subdomainsError: String?
    var extendedSubdomainsError: String?
    var dnsHistoryError: String?
    var domainPricingError: String?
    var portScanError: String?

    init(domain: String, timestamp: Date, trackedDomainID: UUID? = nil, note: String? = nil, dnsSections: [DNSSection],
         sslInfo: SSLCertificateInfo?, httpHeaders: [HTTPHeader],
         reachabilityResults: [PortReachability], ipGeolocation: IPGeolocation?,
         emailSecurity: EmailSecurityResult? = nil, mtaSts: MTASTSResult? = nil, ownership: DomainOwnership? = nil,
         ownershipHistory: [DomainOwnershipHistoryEvent] = [],
         ptrRecord: String? = nil, redirectChain: [RedirectHop] = [], subdomains: [DiscoveredSubdomain] = [],
         extendedSubdomains: [DiscoveredSubdomain] = [], dnsHistory: [DNSHistoryEvent] = [],
         domainPricing: DomainPricingInsight? = nil,
         portScanResults: [PortScanResult] = [],
         hstsPreloaded: Bool? = nil, availabilityResult: DomainAvailabilityResult? = nil,
         suggestions: [DomainSuggestionResult] = [], appVersion: String = "2.7.0",
         resultSource: LookupResultSource = .snapshot, dataSources: [String] = [],
         provenanceBySection: [LookupSectionKind: SectionProvenance] = [:],
         availabilityConfidence: ConfidenceLevel? = nil, ownershipConfidence: ConfidenceLevel? = nil,
         subdomainConfidence: ConfidenceLevel? = nil, emailSecurityConfidence: ConfidenceLevel? = nil,
         geolocationConfidence: ConfidenceLevel? = nil,
         errorDetails: [LookupSectionKind: InspectionFailure] = [:], isPartialSnapshot: Bool = false,
         validationIssues: [String] = [], resolverDisplayName: String, resolverURLString: String,
         totalLookupDurationMs: Int? = nil, primaryIP: String? = nil, finalRedirectURL: String? = nil,
         tlsStatusSummary: String? = nil, emailSecuritySummary: String? = nil, httpGradeSummary: String? = nil,
         changeSummary: DomainChangeSummary? = nil, snapshotIndex: Int? = nil, previousSnapshotID: UUID? = nil,
         changeCount: Int = 0, severitySummary: ChangeSeverity? = nil, sslError: String? = nil, httpHeadersError: String? = nil,
         reachabilityError: String? = nil, ipGeolocationError: String? = nil,
         emailSecurityError: String? = nil, ownershipError: String? = nil, ownershipHistoryError: String? = nil,
         ptrError: String? = nil, redirectChainError: String? = nil, subdomainsError: String? = nil,
         extendedSubdomainsError: String? = nil, dnsHistoryError: String? = nil,
         domainPricingError: String? = nil, portScanError: String? = nil) {
        self.domain = domain
        self.timestamp = timestamp
        self.trackedDomainID = trackedDomainID
        self.note = note
        self.dnsSections = dnsSections
        self.sslInfo = sslInfo
        self.httpHeaders = httpHeaders
        self.reachabilityResults = reachabilityResults
        self.ipGeolocation = ipGeolocation
        self.emailSecurity = emailSecurity
        self.mtaSts = mtaSts ?? emailSecurity?.mtaSts
        self.ownership = ownership
        self.ownershipHistory = ownershipHistory
        self.ptrRecord = ptrRecord
        self.redirectChain = redirectChain
        self.subdomains = subdomains
        self.extendedSubdomains = extendedSubdomains
        self.dnsHistory = dnsHistory
        self.domainPricing = domainPricing
        self.portScanResults = portScanResults
        self.hstsPreloaded = hstsPreloaded
        self.availabilityResult = availabilityResult
        self.suggestions = suggestions
        self.appVersion = appVersion
        self.resultSource = resultSource
        self.dataSources = dataSources
        self.provenanceBySection = provenanceBySection
        self.availabilityConfidence = availabilityConfidence
        self.ownershipConfidence = ownershipConfidence
        self.subdomainConfidence = subdomainConfidence
        self.emailSecurityConfidence = emailSecurityConfidence
        self.geolocationConfidence = geolocationConfidence
        self.errorDetails = errorDetails
        self.isPartialSnapshot = isPartialSnapshot
        self.validationIssues = validationIssues
        self.resolverDisplayName = resolverDisplayName
        self.resolverURLString = resolverURLString
        self.totalLookupDurationMs = totalLookupDurationMs
        self.primaryIP = primaryIP
        self.finalRedirectURL = finalRedirectURL
        self.tlsStatusSummary = tlsStatusSummary
        self.emailSecuritySummary = emailSecuritySummary
        self.httpGradeSummary = httpGradeSummary
        self.changeSummary = changeSummary
        self.snapshotIndex = snapshotIndex
        self.previousSnapshotID = previousSnapshotID
        self.changeCount = changeCount
        self.severitySummary = severitySummary
        self.sslError = sslError
        self.httpHeadersError = httpHeadersError
        self.reachabilityError = reachabilityError
        self.ipGeolocationError = ipGeolocationError
        self.emailSecurityError = emailSecurityError
        self.ownershipError = ownershipError
        self.ownershipHistoryError = ownershipHistoryError
        self.ptrError = ptrError
        self.redirectChainError = redirectChainError
        self.subdomainsError = subdomainsError
        self.extendedSubdomainsError = extendedSubdomainsError
        self.dnsHistoryError = dnsHistoryError
        self.domainPricingError = domainPricingError
        self.portScanError = portScanError
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        domain = try container.decodeIfPresent(String.self, forKey: .domain) ?? "unknown-domain"
        timestamp = try container.decodeIfPresent(Date.self, forKey: .timestamp) ?? .distantPast
        trackedDomainID = try container.decodeIfPresent(UUID.self, forKey: .trackedDomainID)
        note = try container.decodeIfPresent(String.self, forKey: .note)
        dnsSections = try container.decodeIfPresent([DNSSection].self, forKey: .dnsSections) ?? []
        sslInfo = try container.decodeIfPresent(SSLCertificateInfo.self, forKey: .sslInfo)
        httpHeaders = try container.decodeIfPresent([HTTPHeader].self, forKey: .httpHeaders) ?? []
        reachabilityResults = try container.decodeIfPresent([PortReachability].self, forKey: .reachabilityResults) ?? []
        ipGeolocation = try container.decodeIfPresent(IPGeolocation.self, forKey: .ipGeolocation)
        emailSecurity = try container.decodeIfPresent(EmailSecurityResult.self, forKey: .emailSecurity)
        mtaSts = try container.decodeIfPresent(MTASTSResult.self, forKey: .mtaSts) ?? emailSecurity?.mtaSts
        ownership = try container.decodeIfPresent(DomainOwnership.self, forKey: .ownership)
        ownershipHistory = try container.decodeIfPresent([DomainOwnershipHistoryEvent].self, forKey: .ownershipHistory) ?? []
        ptrRecord = try container.decodeIfPresent(String.self, forKey: .ptrRecord)
        redirectChain = try container.decodeIfPresent([RedirectHop].self, forKey: .redirectChain) ?? []
        subdomains = try container.decodeIfPresent([DiscoveredSubdomain].self, forKey: .subdomains) ?? []
        extendedSubdomains = try container.decodeIfPresent([DiscoveredSubdomain].self, forKey: .extendedSubdomains) ?? []
        dnsHistory = try container.decodeIfPresent([DNSHistoryEvent].self, forKey: .dnsHistory) ?? []
        domainPricing = try container.decodeIfPresent(DomainPricingInsight.self, forKey: .domainPricing)
        portScanResults = try container.decodeIfPresent([PortScanResult].self, forKey: .portScanResults) ?? []
        hstsPreloaded = try container.decodeIfPresent(Bool.self, forKey: .hstsPreloaded)
        availabilityResult = try container.decodeIfPresent(DomainAvailabilityResult.self, forKey: .availabilityResult)
        suggestions = try container.decodeIfPresent([DomainSuggestionResult].self, forKey: .suggestions) ?? []
        appVersion = try container.decodeIfPresent(String.self, forKey: .appVersion) ?? "2.6.0"
        resultSource = try container.decodeIfPresent(LookupResultSource.self, forKey: .resultSource) ?? .snapshot
        dataSources = try container.decodeIfPresent([String].self, forKey: .dataSources) ?? []
        provenanceBySection = try container.decodeIfPresent([LookupSectionKind: SectionProvenance].self, forKey: .provenanceBySection) ?? [:]
        availabilityConfidence = try container.decodeIfPresent(ConfidenceLevel.self, forKey: .availabilityConfidence)
        ownershipConfidence = try container.decodeIfPresent(ConfidenceLevel.self, forKey: .ownershipConfidence)
        subdomainConfidence = try container.decodeIfPresent(ConfidenceLevel.self, forKey: .subdomainConfidence)
        emailSecurityConfidence = try container.decodeIfPresent(ConfidenceLevel.self, forKey: .emailSecurityConfidence)
        geolocationConfidence = try container.decodeIfPresent(ConfidenceLevel.self, forKey: .geolocationConfidence)
        errorDetails = try container.decodeIfPresent([LookupSectionKind: InspectionFailure].self, forKey: .errorDetails) ?? [:]
        validationIssues = try container.decodeIfPresent([String].self, forKey: .validationIssues) ?? HistoryEntry.defaultValidationIssues(domain: domain, timestamp: timestamp)
        isPartialSnapshot = try container.decodeIfPresent(Bool.self, forKey: .isPartialSnapshot) ?? !validationIssues.isEmpty
        resolverDisplayName = try container.decodeIfPresent(String.self, forKey: .resolverDisplayName) ?? "Cloudflare"
        resolverURLString = try container.decodeIfPresent(String.self, forKey: .resolverURLString) ?? DNSResolverOption.defaultURLString
        totalLookupDurationMs = try container.decodeIfPresent(Int.self, forKey: .totalLookupDurationMs)
        primaryIP = try container.decodeIfPresent(String.self, forKey: .primaryIP)
        finalRedirectURL = try container.decodeIfPresent(String.self, forKey: .finalRedirectURL)
        tlsStatusSummary = try container.decodeIfPresent(String.self, forKey: .tlsStatusSummary)
        emailSecuritySummary = try container.decodeIfPresent(String.self, forKey: .emailSecuritySummary)
        httpGradeSummary = try container.decodeIfPresent(String.self, forKey: .httpGradeSummary)
        changeSummary = try container.decodeIfPresent(DomainChangeSummary.self, forKey: .changeSummary)
        snapshotIndex = try container.decodeIfPresent(Int.self, forKey: .snapshotIndex)
        previousSnapshotID = try container.decodeIfPresent(UUID.self, forKey: .previousSnapshotID)
        changeCount = try container.decodeIfPresent(Int.self, forKey: .changeCount)
            ?? changeSummary?.changedSections.count
            ?? 0
        severitySummary = try container.decodeIfPresent(ChangeSeverity.self, forKey: .severitySummary)
            ?? changeSummary?.severity
        sslError = try container.decodeIfPresent(String.self, forKey: .sslError)
        httpHeadersError = try container.decodeIfPresent(String.self, forKey: .httpHeadersError)
        reachabilityError = try container.decodeIfPresent(String.self, forKey: .reachabilityError)
        ipGeolocationError = try container.decodeIfPresent(String.self, forKey: .ipGeolocationError)
        emailSecurityError = try container.decodeIfPresent(String.self, forKey: .emailSecurityError)
        ownershipError = try container.decodeIfPresent(String.self, forKey: .ownershipError)
        ownershipHistoryError = try container.decodeIfPresent(String.self, forKey: .ownershipHistoryError)
        ptrError = try container.decodeIfPresent(String.self, forKey: .ptrError)
        redirectChainError = try container.decodeIfPresent(String.self, forKey: .redirectChainError)
        subdomainsError = try container.decodeIfPresent(String.self, forKey: .subdomainsError)
        extendedSubdomainsError = try container.decodeIfPresent(String.self, forKey: .extendedSubdomainsError)
        dnsHistoryError = try container.decodeIfPresent(String.self, forKey: .dnsHistoryError)
        domainPricingError = try container.decodeIfPresent(String.self, forKey: .domainPricingError)
        portScanError = try container.decodeIfPresent(String.self, forKey: .portScanError)
    }

    private static func defaultValidationIssues(domain: String, timestamp: Date) -> [String] {
        var issues: [String] = []
        if domain == "unknown-domain" {
            issues.append("Missing domain in stored snapshot")
        }
        if timestamp == .distantPast {
            issues.append("Missing collection timestamp in stored snapshot")
        }
        return issues
    }

    var snapshotSummary: SnapshotSummary {
        SnapshotSummary(
            id: id,
            domain: domain,
            timestamp: timestamp,
            trackedDomainID: trackedDomainID,
            snapshotIndex: snapshotIndex,
            previousSnapshotID: previousSnapshotID,
            changeCount: changeCount,
            severitySummary: severitySummary ?? changeSummary?.severity,
            changeSummaryMessage: changeSummary?.message,
            availability: availabilityResult?.status,
            primaryIP: primaryIP,
            tlsStatus: tlsStatusSummary,
            riskScore: changeSummary?.riskAssessment?.score,
            historyEntryID: id
        )
    }
}

// MARK: - Cloudflare DNS-over-HTTPS Response

struct CloudflareDNSResponse: Decodable {
    let Status: Int
    let AD: Bool?
    let Answer: [CloudflareDNSAnswer]?

    struct CloudflareDNSAnswer: Decodable {
        let name: String
        let type: Int
        let TTL: Int
        let data: String
    }
}
