import Foundation

enum DataAccessService {
    static func hasAccess(to capability: DataCapability) -> Bool {
        switch capability {
        case .ownershipHistory:
            return FeatureAccessService.hasAccess(to: .ownershipHistory)
        case .dnsHistory:
            return FeatureAccessService.hasAccess(to: .dnsHistory)
        case .extendedSubdomains:
            return FeatureAccessService.hasAccess(to: .extendedSubdomains)
        case .domainPricing:
            return FeatureAccessService.hasAccess(to: .domainPricing)
        }
    }
}
