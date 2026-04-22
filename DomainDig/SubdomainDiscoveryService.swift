import Foundation

enum SubdomainDiscoveryService {
    static func discover(for domain: String, limit: Int = 25) async -> ServiceResult<[DiscoveredSubdomain]> {
        let normalizedDomain = normalize(domain)
        guard !normalizedDomain.isEmpty else {
            return .empty("No passive subdomains found")
        }

        return await cache.subdomains(for: normalizedDomain, limit: limit)
    }

    private static let cache = SubdomainDiscoveryCache()

    private static func normalize(_ domain: String) -> String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }
}

private actor SubdomainDiscoveryCache {
    private var cachedResults: [String: ServiceResult<[DiscoveredSubdomain]>] = [:]
    private var inFlightTasks: [String: Task<ServiceResult<[DiscoveredSubdomain]>, Never>] = [:]
    private var lastRequestAt: Date?

    func subdomains(for domain: String, limit: Int) async -> ServiceResult<[DiscoveredSubdomain]> {
        if let cachedResult = cachedResults[domain] {
            return cachedResult
        }

        if let inFlightTask = inFlightTasks[domain] {
            return await inFlightTask.value
        }

        let task = Task<ServiceResult<[DiscoveredSubdomain]>, Never> {
            await enforceRateLimit()
            return await fetchSubdomains(for: domain, limit: limit)
        }
        inFlightTasks[domain] = task

        let result = await task.value
        cachedResults[domain] = result
        inFlightTasks[domain] = nil
        return result
    }

    private func enforceRateLimit() async {
        if let lastRequestAt {
            let delay = max(0, 0.75 - Date().timeIntervalSince(lastRequestAt))
            if delay > 0 {
                try? await Task.sleep(for: .seconds(delay))
            }
        }
        lastRequestAt = Date()
    }

    private func fetchSubdomains(for domain: String, limit: Int) async -> ServiceResult<[DiscoveredSubdomain]> {
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
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                return .error("Subdomain discovery unavailable")
            }

            let entries = try JSONDecoder().decode([CRTShEntry].self, from: data)
            let subdomains = parseSubdomains(from: entries, domain: domain, limit: limit)
            return subdomains.isEmpty ? .empty("No passive subdomains found") : .success(subdomains)
        } catch {
            return .error(error.localizedDescription)
        }
    }

    private func parseSubdomains(from entries: [CRTShEntry], domain: String, limit: Int) -> [DiscoveredSubdomain] {
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
                results.append(DiscoveredSubdomain(hostname: sanitized))
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
