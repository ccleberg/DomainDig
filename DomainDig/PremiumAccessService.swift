import Foundation

enum PremiumAccessService {
    static let freeTrackedDomainLimit = 3

    static func hasAccess(to capability: PremiumCapability) -> Bool {
        switch capability {
        case .unlimitedTrackedDomains,
             .automatedMonitoring,
             .pushAlerts,
             .batchTracking,
             .advancedExports:
            return false
        }
    }

    static func trackedDomainLimitMessage(currentCount: Int) -> String? {
        guard currentCount >= freeTrackedDomainLimit, !hasAccess(to: .unlimitedTrackedDomains) else {
            return nil
        }
        return "More tracked domains will be available in a future Pro upgrade."
    }

    static func canAddTrackedDomain(currentCount: Int) -> Bool {
        hasAccess(to: .unlimitedTrackedDomains) || currentCount < freeTrackedDomainLimit
    }
}
