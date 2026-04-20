import Foundation

struct ReverseDNSService {
    static func lookup(ip: String, resolverURLString: String) async -> ServiceResult<String> {
        let octets = ip.split(separator: ".")
        guard octets.count == 4 else {
            return .error("Invalid IPv4 address")
        }

        let reversed = octets.reversed().joined(separator: ".")
        let ptrDomain = "\(reversed).in-addr.arpa"

        do {
            let records = try await DNSLookupService.lookup(
                domain: ptrDomain,
                recordType: .PTR,
                resolverURLString: resolverURLString
            )
            if let record = records.first?.value {
                return .success(record)
            }
            return .empty("No PTR record found")
        } catch {
            return .error(error.localizedDescription)
        }
    }
}
