import Foundation

enum SubdomainDiscoveryService {
    static func discover(for domain: String, limit: Int = 25) async -> ServiceResult<[DiscoveredSubdomain]> {
        let normalizedDomain = normalize(domain)
        guard !normalizedDomain.isEmpty else {
            return .empty("No passive subdomains found")
        }

        return await fetchSubdomains(for: normalizedDomain, limit: limit)
    }

    private static func normalize(_ domain: String) -> String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private static func fetchSubdomains(for domain: String, limit: Int) async -> ServiceResult<[DiscoveredSubdomain]> {
        let startedAt = DomainDebugLog.signpostStart("SubdomainDiscovery.fetch", domain: domain)
        var components = URLComponents(string: "https://crt.sh/")!
        components.queryItems = [
            URLQueryItem(name: "q", value: "%.\(domain)"),
            URLQueryItem(name: "output", value: "json")
        ]

        guard let url = components.url else {
            return .error("Subdomain discovery unavailable")
        }

        do {
            let request = URLRequest(url: url, timeoutInterval: 10)
            DomainDebugLog.debug("SubdomainDiscovery.request url=\(url.absoluteString) timeout=10")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                DomainDebugLog.error("SubdomainDiscovery.badResponse domain=\(domain)")
                return .error("Subdomain discovery unavailable")
            }

            let entries = try JSONDecoder().decode([CRTShEntry].self, from: data)
            let subdomains = parseSubdomains(from: entries, domain: domain, limit: limit)
            DomainDebugLog.signpostEnd(
                "SubdomainDiscovery.fetch",
                start: startedAt,
                domain: domain,
                extra: "entries=\(entries.count) subdomains=\(subdomains.count)"
            )
            return subdomains.isEmpty ? .empty("No passive subdomains found") : .success(subdomains)
        } catch {
            DomainDebugLog.error("SubdomainDiscovery.error domain=\(domain) error=\(error.localizedDescription)")
            DomainDebugLog.signpostEnd("SubdomainDiscovery.fetch", start: startedAt, domain: domain, extra: "error")
            return .error(error.localizedDescription)
        }
    }

    private static func parseSubdomains(from entries: [CRTShEntry], domain: String, limit: Int) -> [DiscoveredSubdomain] {
        var seen = Set<String>()
        var results: [DiscoveredSubdomain] = []

        for entry in entries {
            let names = entry.nameValue
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }

            for name in names {
                let sanitized = name.hasPrefix("*.") ? String(name.dropFirst(2)) : name
                guard sanitized != domain, sanitized.hasSuffix(".\(domain)") else {
                    continue
                }
                guard seen.insert(sanitized).inserted else {
                    continue
                }
                results.append(DiscoveredSubdomain(hostname: sanitized, source: "crt.sh"))
                if results.count == limit {
                    return results
                }
            }
        }

        return results
    }
}

private struct CRTShEntry: Decodable {
    let nameValue: String

    enum CodingKeys: String, CodingKey {
        case nameValue = "name_value"
    }
}
