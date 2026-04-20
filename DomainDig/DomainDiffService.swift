import Foundation

enum DiffChangeType: String, Codable {
    case added
    case removed
    case changed
    case unchanged
}

struct DomainDiffItem: Identifiable, Equatable {
    let id = UUID()
    let label: String
    let changeType: DiffChangeType
    let oldValue: String?
    let newValue: String?
}

struct DomainDiffSection: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let items: [DomainDiffItem]
}

enum DomainDiffService {
    static func diff(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> [DomainDiffSection] {
        [
            section(title: "Availability", item: compare(
                label: "Status",
                oldValue: availabilityLabel(oldSnapshot.availabilityResult?.status),
                newValue: availabilityLabel(newSnapshot.availabilityResult?.status)
            )),
            section(title: "Primary IP", item: compare(
                label: "Address",
                oldValue: primaryIP(from: oldSnapshot),
                newValue: primaryIP(from: newSnapshot)
            )),
            dnsSection(from: oldSnapshot, to: newSnapshot),
            section(title: "Redirect", item: compare(
                label: "Final Target",
                oldValue: finalRedirectURL(from: oldSnapshot),
                newValue: finalRedirectURL(from: newSnapshot)
            )),
            tlsSection(from: oldSnapshot, to: newSnapshot),
            httpSection(from: oldSnapshot, to: newSnapshot),
            emailSection(from: oldSnapshot, to: newSnapshot)
        ]
        .filter { !$0.items.isEmpty }
    }

    static func summary(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot, generatedAt: Date = Date()) -> DomainChangeSummary {
        let changedSections = diff(from: oldSnapshot, to: newSnapshot)
            .filter { $0.items.contains(where: { $0.changeType != .unchanged }) }
            .map(\.title)

        return DomainChangeSummary(
            hasChanges: !changedSections.isEmpty,
            changedSections: changedSections,
            generatedAt: generatedAt
        )
    }

    private static func section(title: String, item: DomainDiffItem?) -> DomainDiffSection {
        DomainDiffSection(title: title, items: item.map { [$0] } ?? [])
    }

    private static func dnsSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        let oldValue = normalizedDNSSummary(from: oldSnapshot)
        let newValue = normalizedDNSSummary(from: newSnapshot)
        return section(title: "DNS Records", item: compare(label: "Records", oldValue: oldValue, newValue: newValue))
    }

    private static func tlsSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        var items: [DomainDiffItem] = []
        if let item = compare(label: "Issuer", oldValue: normalized(oldSnapshot.sslInfo?.issuer), newValue: normalized(newSnapshot.sslInfo?.issuer)) {
            items.append(item)
        }
        if let item = compare(label: "Certificate", oldValue: tlsSummary(from: oldSnapshot), newValue: tlsSummary(from: newSnapshot)) {
            items.append(item)
        }
        return DomainDiffSection(title: "TLS Certificate", items: items)
    }

    private static func httpSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        var items: [DomainDiffItem] = []
        if let item = compare(label: "HTTP Status", oldValue: httpStatusSummary(from: oldSnapshot), newValue: httpStatusSummary(from: newSnapshot)) {
            items.append(item)
        }
        if let item = compare(label: "Security Grade", oldValue: normalized(oldSnapshot.httpSecurityGrade), newValue: normalized(newSnapshot.httpSecurityGrade)) {
            items.append(item)
        }
        return DomainDiffSection(title: "HTTP", items: items)
    }

    private static func emailSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        section(
            title: "Email Security",
            item: compare(
                label: "Summary",
                oldValue: normalized(emailSummary(from: oldSnapshot)),
                newValue: normalized(emailSummary(from: newSnapshot))
            )
        )
    }

    private static func compare(label: String, oldValue: String?, newValue: String?) -> DomainDiffItem? {
        let oldValue = normalized(oldValue)
        let newValue = normalized(newValue)

        guard oldValue != nil || newValue != nil else {
            return nil
        }

        let changeType: DiffChangeType
        switch (oldValue, newValue) {
        case let (old?, new?) where old == new:
            changeType = .unchanged
        case (nil, _?):
            changeType = .added
        case (_?, nil):
            changeType = .removed
        default:
            changeType = .changed
        }

        return DomainDiffItem(label: label, changeType: changeType, oldValue: oldValue, newValue: newValue)
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }
        return value.lowercased()
    }

    private static func availabilityLabel(_ status: DomainAvailabilityStatus?) -> String? {
        switch status {
        case .available:
            return "available"
        case .registered:
            return "registered"
        case .unknown:
            return "unknown"
        case .none:
            return nil
        }
    }

    private static func primaryIP(from snapshot: LookupSnapshot) -> String? {
        snapshot.dnsSections.first(where: { $0.recordType == .A })?.records.first?.value
    }

    private static func finalRedirectURL(from snapshot: LookupSnapshot) -> String? {
        snapshot.redirectChain.last?.url
    }

    private static func tlsSummary(from snapshot: LookupSnapshot) -> String? {
        if let sslInfo = snapshot.sslInfo {
            return "\(sslInfo.commonName) | \(sslInfo.validUntil.formatted(date: .abbreviated, time: .omitted))"
        }
        return snapshot.sslError
    }

    private static func httpStatusSummary(from snapshot: LookupSnapshot) -> String? {
        if let httpStatusCode = snapshot.httpStatusCode {
            return "\(httpStatusCode)"
        }
        return snapshot.httpHeadersError
    }

    private static func emailSummary(from snapshot: LookupSnapshot) -> String? {
        if let emailSecurity = snapshot.emailSecurity {
            return [
                "spf:\(emailSecurity.spf.found)",
                "dmarc:\(emailSecurity.dmarc.found)",
                "dkim:\(emailSecurity.dkim.found)",
                "bimi:\(emailSecurity.bimi.found)",
                "mta-sts:\(emailSecurity.mtaSts?.txtFound == true)"
            ].joined(separator: "|")
        }
        return snapshot.emailSecurityError
    }

    private static func normalizedDNSSummary(from snapshot: LookupSnapshot) -> String? {
        let parts = snapshot.dnsSections
            .sorted { $0.recordType.rawValue < $1.recordType.rawValue }
            .map { section in
                let values = (section.records + section.wildcardRecords)
                    .map(\.value)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                    .sorted()
                    .joined(separator: ",")
                return "\(section.recordType.rawValue):\(values)"
            }
            .filter { !$0.hasSuffix(":") }
        return parts.isEmpty ? nil : parts.joined(separator: "|")
    }
}
