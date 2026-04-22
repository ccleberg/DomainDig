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

struct UpgradePromptContext: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let message: String
    let capability: FeatureCapability
}

enum FeatureAccessService {
    private static let effectivelyUnlimitedTrackedDomains = 5_000

    static var currentTier: FeatureTier {
        PurchaseService.cachedTier
    }

    static var entitlements: FeatureEntitlements {
        switch currentTier {
        case .free:
            return FeatureEntitlements(
                tier: .free,
                capabilities: [.singleLookup, .basicHistory, .limitedTracking, .workflows, .batchOperations],
                trackedDomainLimit: 5,
                workflowLimit: 1,
                batchSizeLimit: 10
            )
        case .pro:
            return FeatureEntitlements(
                tier: .pro,
                capabilities: [.singleLookup, .basicHistory, .limitedTracking, .workflows, .batchOperations, .advancedExports],
                trackedDomainLimit: effectivelyUnlimitedTrackedDomains,
                workflowLimit: nil,
                batchSizeLimit: nil
            )
        case .dataPlus:
            return FeatureEntitlements(
                tier: .dataPlus,
                capabilities: Set(FeatureCapability.allCases),
                trackedDomainLimit: effectivelyUnlimitedTrackedDomains,
                workflowLimit: nil,
                batchSizeLimit: nil
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
        if currentCount >= entitlements.trackedDomainLimit {
            return "Free includes up to \(entitlements.trackedDomainLimit) tracked domains. Available in Pro."
        }
        return "Free includes up to \(entitlements.trackedDomainLimit) tracked domains."
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
        guard let limit = entitlements.workflowLimit, currentCount >= limit else { return nil }
        return "Free includes up to \(limit) workflow."
    }

    static func batchLimitMessage(domainCount: Int) -> String? {
        guard let limit = entitlements.batchSizeLimit, domainCount > limit else { return nil }
        return "Free runs batches up to \(limit) domains."
    }

    static func workflowAllowanceSummary(currentCount: Int) -> String? {
        guard currentTier == .free, let limit = entitlements.workflowLimit else { return nil }
        if currentCount >= limit {
            return "Free includes up to \(limit) workflow. Available in Pro."
        }
        return "Free includes up to \(limit) workflow."
    }

    static func batchAllowanceSummary() -> String? {
        guard currentTier == .free, let limit = entitlements.batchSizeLimit else { return nil }
        return "Free runs batches up to \(limit) domains."
    }

    static func upgradePromptForTrackedDomains(currentCount: Int) -> UpgradePromptContext? {
        guard currentCount >= entitlements.trackedDomainLimit else { return nil }
        return UpgradePromptContext(
            title: "Available in Pro",
            message: "Free includes up to \(entitlements.trackedDomainLimit) tracked domains. You can keep your current watchlist, but adding more requires Pro.",
            capability: .limitedTracking
        )
    }

    static func upgradePromptForWorkflows(currentCount: Int) -> UpgradePromptContext? {
        guard let limit = entitlements.workflowLimit, currentCount >= limit else { return nil }
        return UpgradePromptContext(
            title: "Available in Pro",
            message: "Free includes up to \(limit) workflow. You can keep your current workflows, but creating more requires Pro.",
            capability: .workflows
        )
    }

    static func upgradePromptForBatch(domainCount: Int) -> UpgradePromptContext? {
        guard let limit = entitlements.batchSizeLimit, domainCount > limit else { return nil }
        return UpgradePromptContext(
            title: "Available in Pro",
            message: "Free runs batches up to \(limit) domains at a time. You can continue with smaller batches or upgrade to Pro.",
            capability: .batchOperations
        )
    }

    static func upgradePrompt(for capability: FeatureCapability) -> UpgradePromptContext {
        UpgradePromptContext(
            title: "Available in Pro",
            message: upgradeMessage(for: capability),
            capability: capability
        )
    }

    static func enabledFeatureLabels() -> [String] {
        FeatureCapability.allCases
            .filter { hasAccess(to: $0) }
            .map(\.title)
    }
}
