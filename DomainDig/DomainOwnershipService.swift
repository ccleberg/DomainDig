import Foundation

enum DomainOwnershipService {
    static func lookup(domain: String) async -> ServiceResult<DomainOwnership> {
        await RDAPService.ownership(for: domain)
    }
}
