import Foundation

enum FeatureTier: String, Codable, CaseIterable, Identifiable {
    case free
    case pro
    case dataPlus

    var id: String { rawValue }

    var title: String {
        switch self {
        case .free:
            return "Free"
        case .pro:
            return "Pro"
        case .dataPlus:
            return "Data+"
        }
    }
}

enum FeatureCapability: String, CaseIterable, Identifiable {
    case singleLookup
    case basicHistory
    case limitedTracking
    case workflows
    case batchOperations
    case advancedExports
    case ownershipHistory
    case dnsHistory
    case extendedSubdomains

    var id: String { rawValue }

    var title: String {
        switch self {
        case .singleLookup:
            return "Single lookup"
        case .basicHistory:
            return "Basic history"
        case .limitedTracking:
            return "Limited tracking"
        case .workflows:
            return "Workflows"
        case .batchOperations:
            return "Batch operations"
        case .advancedExports:
            return "Advanced exports"
        case .ownershipHistory:
            return "Ownership history"
        case .dnsHistory:
            return "DNS history"
        case .extendedSubdomains:
            return "Extended subdomains"
        }
    }
}

struct FeatureEntitlements: Equatable {
    let tier: FeatureTier
    let capabilities: Set<FeatureCapability>
    let trackedDomainLimit: Int
    let workflowLimit: Int?
    let batchSizeLimit: Int?
}

enum FeatureAccessService {
    static let currentTier: FeatureTier = .free

    static var entitlements: FeatureEntitlements {
        switch currentTier {
        case .free:
            return FeatureEntitlements(
                tier: .free,
                capabilities: [.singleLookup, .basicHistory, .limitedTracking],
                trackedDomainLimit: 3,
                workflowLimit: 0,
                batchSizeLimit: 0
            )
        case .pro:
            return FeatureEntitlements(
                tier: .pro,
                capabilities: [.singleLookup, .basicHistory, .limitedTracking, .workflows, .batchOperations, .advancedExports],
                trackedDomainLimit: 250,
                workflowLimit: 50,
                batchSizeLimit: 100
            )
        case .dataPlus:
            return FeatureEntitlements(
                tier: .dataPlus,
                capabilities: Set(FeatureCapability.allCases),
                trackedDomainLimit: 1_000,
                workflowLimit: 200,
                batchSizeLimit: 250
            )
        }
    }

    static func hasAccess(to capability: FeatureCapability) -> Bool {
        entitlements.capabilities.contains(capability)
    }

    static func canAddTrackedDomain(currentCount: Int) -> Bool {
        currentCount < entitlements.trackedDomainLimit
    }

    static func trackedDomainLimitMessage(currentCount: Int) -> String? {
        guard currentTier == .free else { return nil }
        return currentCount >= entitlements.trackedDomainLimit
            ? "Free includes up to \(entitlements.trackedDomainLimit) tracked domains."
            : "Free includes up to \(entitlements.trackedDomainLimit) tracked domains."
    }

    static func canCreateWorkflow(currentCount: Int) -> Bool {
        guard hasAccess(to: .workflows) else { return false }
        guard let limit = entitlements.workflowLimit else { return true }
        return currentCount < limit
    }

    static func canRunBatch(domainCount: Int) -> Bool {
        guard hasAccess(to: .batchOperations) else { return false }
        guard let limit = entitlements.batchSizeLimit else { return true }
        return domainCount <= limit
    }

    static func upgradeMessage(for capability: FeatureCapability) -> String {
        switch capability {
        case .workflows, .batchOperations, .advancedExports:
            return "Available in Pro"
        case .ownershipHistory, .dnsHistory, .extendedSubdomains:
            return "Available in Data+"
        case .limitedTracking:
            return "Tracking is limited on Free"
        case .singleLookup, .basicHistory:
            return "Included in Free"
        }
    }

    static func workflowLimitMessage(currentCount: Int) -> String? {
        guard hasAccess(to: .workflows) else {
            return upgradeMessage(for: .workflows)
        }
        guard let limit = entitlements.workflowLimit, currentCount >= limit else { return nil }
        return "Workflow limit reached."
    }

    static func batchLimitMessage(domainCount: Int) -> String? {
        guard hasAccess(to: .batchOperations) else {
            return upgradeMessage(for: .batchOperations)
        }
        guard let limit = entitlements.batchSizeLimit, domainCount > limit else { return nil }
        return "Batch limit is \(limit) domains on \(currentTier.title)."
    }

    static func enabledFeatureLabels() -> [String] {
        FeatureCapability.allCases
            .filter { hasAccess(to: $0) }
            .map(\.title)
    }
}
