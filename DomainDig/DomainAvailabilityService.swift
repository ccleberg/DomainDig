import Foundation

struct DomainAvailabilityService {
    private static let suggestionTLDs = ["net", "io", "dev", "app", "co", "org"]

    static func check(domain: String) async -> DomainAvailabilityResult {
        let normalizedDomain = normalize(domain)
        guard !normalizedDomain.isEmpty else {
            return DomainAvailabilityResult(domain: domain, status: .unknown)
        }

        if await checkViaRDAP(domain: normalizedDomain) == .registered {
            debugLog("rdap", domain: normalizedDomain, status: .registered)
            return DomainAvailabilityResult(domain: normalizedDomain, status: .registered)
        }

        let fallbackStatus = await checkViaDNSFallback(domain: normalizedDomain)
        let method = fallbackStatus == .registered ? "dns" : "fallback"
        debugLog(method, domain: normalizedDomain, status: fallbackStatus)
        return DomainAvailabilityResult(domain: normalizedDomain, status: fallbackStatus)
    }

    static func suggestions(for domain: String, limit: Int = 6) async -> [DomainSuggestionResult] {
        let normalizedDomain = normalize(domain)
        let candidates = suggestionCandidates(for: normalizedDomain, limit: limit)
        guard !candidates.isEmpty else { return [] }

        var results: [DomainSuggestionResult] = []
        for candidate in candidates {
            if Task.isCancelled { break }
            let result = await check(domain: candidate)
            results.append(DomainSuggestionResult(domain: result.domain, status: result.status))
        }
        return results
    }

    private static func checkViaRDAP(domain: String) async -> DomainAvailabilityStatus? {
        guard let url = URL(string: "https://rdap.org/domain/\(domain)") else {
            return nil
        }

        do {
            var request = URLRequest(url: url, timeoutInterval: 8)
            request.setValue("application/rdap+json, application/json", forHTTPHeaderField: "Accept")

            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                return nil
            }

            switch httpResponse.statusCode {
            case 200:
                return isValidRDAPDomainResponse(data) ? .registered : nil
            case 404:
                debugLog("rdap-not-found", domain: domain, details: "Ignoring not-found response from rdap.org")
                return nil
            default:
                return nil
            }
        } catch {
            debugLog("rdap-error", domain: domain, details: error.localizedDescription)
            return nil
        }
    }

    private static func checkViaDNSFallback(domain: String) async -> DomainAvailabilityStatus {
        do {
            let aRecords = try await DNSLookupService.lookup(domain: domain, recordType: .A)
            if !aRecords.isEmpty {
                return .registered
            }
        } catch {
            debugLog("dns-a-error", domain: domain, details: error.localizedDescription)
        }

        do {
            let nsRecords = try await DNSLookupService.lookup(domain: domain, recordType: .NS)
            if !nsRecords.isEmpty {
                return .registered
            }
            return .unknown
        } catch {
            debugLog("dns-ns-error", domain: domain, details: error.localizedDescription)
            return .unknown
        }
    }

    private static func isValidRDAPDomainResponse(_ data: Data) -> Bool {
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return false
        }

        if object["ldhName"] as? String != nil {
            return true
        }

        if object["objectClassName"] as? String == "domain" {
            return true
        }

        if object["handle"] as? String != nil, object["unicodeName"] as? String != nil {
            return true
        }

        return false
    }

    private static func suggestionCandidates(for domain: String, limit: Int) -> [String] {
        let parts = domain.split(separator: ".")
        guard parts.count >= 2 else { return [] }

        let base = parts.dropLast().joined(separator: ".")
        let tld = String(parts.last ?? "")

        var candidates: [String] = []
        for suggestionTLD in suggestionTLDs where suggestionTLD != tld {
            candidates.append("\(base).\(suggestionTLD)")
            if candidates.count == limit {
                return candidates
            }
        }

        if !base.contains("-"), base.count >= 6, candidates.count < limit {
            let midpoint = base.index(base.startIndex, offsetBy: base.count / 2)
            let hyphenated = "\(base[..<midpoint])-\(base[midpoint...]).\(tld)"
            if hyphenated != domain {
                candidates.append(hyphenated)
            }
        }

        return Array(candidates.prefix(limit))
    }

    private static func normalize(_ domain: String) -> String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private static func debugLog(_ method: String, domain: String, status: DomainAvailabilityStatus) {
        #if DEBUG
        print("[Availability] \(domain) -> \(status.rawValue) via \(method)")
        #endif
    }

    private static func debugLog(_ method: String, domain: String, details: String) {
        #if DEBUG
        print("[Availability] \(domain) -> \(method): \(details)")
        #endif
    }
}
