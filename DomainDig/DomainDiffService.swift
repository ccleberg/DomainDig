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
    let severity: ChangeSeverity

    var hasChanges: Bool {
        changeType != .unchanged
    }

    var isMeaningful: Bool {
        hasChanges && severity >= .medium
    }
}

struct DomainDiffSection: Identifiable, Equatable {
    let id = UUID()
    let title: String
    let items: [DomainDiffItem]

    var hasChanges: Bool {
        items.contains(where: \.hasChanges)
    }

    var severity: ChangeSeverity {
        items.map(\.severity).max() ?? .low
    }
}

enum DomainDiffService {
    static func diff(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> [DomainDiffSection] {
        [
            availabilitySection(from: oldSnapshot, to: newSnapshot),
            primaryIPSection(from: oldSnapshot, to: newSnapshot),
            ownershipSection(from: oldSnapshot, to: newSnapshot),
            dnsSection(from: oldSnapshot, to: newSnapshot),
            redirectSection(from: oldSnapshot, to: newSnapshot),
            tlsSection(from: oldSnapshot, to: newSnapshot),
            httpSection(from: oldSnapshot, to: newSnapshot),
            emailSection(from: oldSnapshot, to: newSnapshot),
            subdomainSection(from: oldSnapshot, to: newSnapshot)
        ]
        .filter { !$0.items.isEmpty }
    }

    static func summary(
        from oldSnapshot: LookupSnapshot,
        to newSnapshot: LookupSnapshot,
        generatedAt: Date = Date(),
        riskAssessment: DomainRiskAssessment? = nil,
        insights: [String]? = nil
    ) -> DomainChangeSummary {
        let sections = diff(from: oldSnapshot, to: newSnapshot)
        let allChangedItems = sections
            .flatMap(\.items)
            .filter(\.hasChanges)

        let highlights = summaryHighlights(from: allChangedItems)
        let severity = allChangedItems.map(\.severity).max() ?? .low
        let message = summaryMessage(from: allChangedItems, highlights: highlights)
        let observedFacts = observedFacts(from: allChangedItems)
        let inferredConclusions = highlights.isEmpty ? [] : [message]
        let contextNote = comparisonContextNote(from: oldSnapshot, to: newSnapshot)
        let newAnalysis = DomainInsightEngine.analyze(snapshot: newSnapshot, previousSnapshot: oldSnapshot)
        let currentRiskAssessment = riskAssessment ?? newAnalysis.riskAssessment
        let currentInsights = insights ?? newAnalysis.insights
        let oldRiskAssessment = DomainInsightEngine.analyze(snapshot: oldSnapshot).riskAssessment
        let riskScoreDelta = currentRiskAssessment.score - oldRiskAssessment.score
        let impactClassification = DomainInsightEngine.impactClassification(
            severity: severity,
            riskDelta: riskScoreDelta,
            changedSections: highlights
        )

        return DomainChangeSummary(
            hasChanges: !allChangedItems.isEmpty,
            changedSections: highlights,
            message: message,
            severity: severity,
            impactClassification: impactClassification,
            generatedAt: generatedAt,
            observedFacts: observedFacts,
            inferredConclusions: inferredConclusions,
            contextNote: contextNote,
            riskAssessment: currentRiskAssessment,
            insights: currentInsights,
            riskScoreDelta: riskScoreDelta
        )
    }

    static func comparisonContextNote(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> String? {
        var notes: [String] = []
        if oldSnapshot.resolverURLString != newSnapshot.resolverURLString {
            notes.append("Compared snapshots used different DNS resolvers.")
        }
        if oldSnapshot.resultSource != newSnapshot.resultSource {
            notes.append("Compared snapshots came from different collection modes.")
        }
        return notes.isEmpty ? nil : notes.joined(separator: " ")
    }

    static func certificateWarningLevel(for snapshot: LookupSnapshot) -> CertificateWarningLevel {
        guard let days = snapshot.sslInfo?.daysUntilExpiry else {
            return .none
        }
        if days < 14 {
            return .critical
        }
        if days < 30 {
            return .warning
        }
        return .none
    }

    private static func availabilitySection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        DomainDiffSection(
            title: "Availability",
            items: [
                compare(
                    label: "Availability",
                    oldValue: availabilityLabel(oldSnapshot.availabilityResult?.status),
                    newValue: availabilityLabel(newSnapshot.availabilityResult?.status),
                    severity: .high
                )
            ].compactMap { $0 }
        )
    }

    private static func primaryIPSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        DomainDiffSection(
            title: "Primary IP",
            items: [
                compare(
                    label: "Primary IP",
                    oldValue: primaryIP(from: oldSnapshot),
                    newValue: primaryIP(from: newSnapshot),
                    severity: .high
                )
            ].compactMap { $0 }
        )
    }

    private static func dnsSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        let oldSections = Dictionary(uniqueKeysWithValues: oldSnapshot.dnsSections.map { ($0.recordType, $0) })
        let newSections = Dictionary(uniqueKeysWithValues: newSnapshot.dnsSections.map { ($0.recordType, $0) })
        let types = Set(oldSections.keys).union(newSections.keys).sorted { $0.rawValue < $1.rawValue }

        var items: [DomainDiffItem] = []
        for type in types {
            let oldSection = oldSections[type]
            let newSection = newSections[type]

            if let recordChange = compare(
                label: "\(type.rawValue) Records",
                oldValue: normalizedRecordValues(for: oldSection),
                newValue: normalizedRecordValues(for: newSection),
                severity: .medium
            ) {
                items.append(recordChange)
            }

            if let ttlChange = compare(
                label: "\(type.rawValue) TTL",
                oldValue: normalizedTTLValues(for: oldSection),
                newValue: normalizedTTLValues(for: newSection),
                severity: .low
            ), let oldSection, let newSection,
               normalizedRecordValues(for: oldSection) == normalizedRecordValues(for: newSection) {
                items.append(ttlChange)
            }
        }

        return DomainDiffSection(title: "DNS", items: items)
    }

    private static func ownershipSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        DomainDiffSection(
            title: "Ownership",
            items: [
                compare(
                    label: "Registrar",
                    oldValue: normalized(oldSnapshot.ownership?.registrar),
                    newValue: normalized(newSnapshot.ownership?.registrar),
                    severity: .high
                ),
                compare(
                    label: "Registration Date",
                    oldValue: ownershipDateLabel(oldSnapshot.ownership?.createdDate),
                    newValue: ownershipDateLabel(newSnapshot.ownership?.createdDate),
                    severity: .low
                ),
                compare(
                    label: "Expiration Date",
                    oldValue: ownershipDateLabel(oldSnapshot.ownership?.expirationDate),
                    newValue: ownershipDateLabel(newSnapshot.ownership?.expirationDate),
                    severity: .low
                ),
                compare(
                    label: "Ownership Status",
                    oldValue: ownershipList(oldSnapshot.ownership?.status),
                    newValue: ownershipList(newSnapshot.ownership?.status),
                    severity: .low
                ),
                compare(
                    label: "Nameservers",
                    oldValue: ownershipList(oldSnapshot.ownership?.nameservers),
                    newValue: ownershipList(newSnapshot.ownership?.nameservers),
                    severity: .medium
                ),
                compare(
                    label: "Abuse Contact",
                    oldValue: normalized(oldSnapshot.ownership?.abuseEmail),
                    newValue: normalized(newSnapshot.ownership?.abuseEmail),
                    severity: .low
                )
            ].compactMap { $0 }
        )
    }

    private static func redirectSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        DomainDiffSection(
            title: "Redirect",
            items: [
                compare(
                    label: "Redirect Target",
                    oldValue: finalRedirectURL(from: oldSnapshot),
                    newValue: finalRedirectURL(from: newSnapshot),
                    severity: .high
                )
            ].compactMap { $0 }
        )
    }

    private static func tlsSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        var items: [DomainDiffItem] = []

        if let issuerChange = compare(
            label: "TLS Issuer",
            oldValue: normalized(oldSnapshot.sslInfo?.issuer),
            newValue: normalized(newSnapshot.sslInfo?.issuer),
            severity: .medium
        ) {
            items.append(issuerChange)
        }

        if let expiryChange = compare(
            label: "TLS Expiration",
            oldValue: expirationLabel(oldSnapshot.sslInfo),
            newValue: expirationLabel(newSnapshot.sslInfo),
            severity: .medium
        ) {
            items.append(expiryChange)
        }

        let oldWarning = certificateWarningLevel(for: oldSnapshot)
        let newWarning = certificateWarningLevel(for: newSnapshot)
        if oldWarning != newWarning, newWarning != .none {
            let days = newSnapshot.sslInfo?.daysUntilExpiry ?? 0
            items.append(
                DomainDiffItem(
                    label: "Certificate Warning",
                    changeType: .changed,
                    oldValue: oldWarning.title,
                    newValue: "Certificate expires in \(days) days",
                    severity: newWarning == .critical ? .high : .medium
                )
            )
        }

        return DomainDiffSection(title: "TLS", items: items)
    }

    private static func httpSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        var items: [DomainDiffItem] = []

        if let statusChange = compare(
            label: "HTTP Status",
            oldValue: httpStatusSummary(from: oldSnapshot),
            newValue: httpStatusSummary(from: newSnapshot),
            severity: .medium
        ) {
            items.append(statusChange)
        }

        if let gradeChange = compare(
            label: "Security Grade",
            oldValue: normalized(oldSnapshot.httpSecurityGrade),
            newValue: normalized(newSnapshot.httpSecurityGrade),
            severity: .low
        ) {
            items.append(gradeChange)
        }

        if let headerChange = compare(
            label: "Headers",
            oldValue: normalizedHeaders(from: oldSnapshot),
            newValue: normalizedHeaders(from: newSnapshot),
            severity: .low
        ) {
            items.append(headerChange)
        }

        return DomainDiffSection(title: "HTTP", items: items)
    }

    private static func emailSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        DomainDiffSection(
            title: "Email Security",
            items: [
                compare(
                    label: "Email Security",
                    oldValue: normalized(emailSummary(from: oldSnapshot)),
                    newValue: normalized(emailSummary(from: newSnapshot)),
                    severity: .medium
                )
            ].compactMap { $0 }
        )
    }

    private static func subdomainSection(from oldSnapshot: LookupSnapshot, to newSnapshot: LookupSnapshot) -> DomainDiffSection {
        DomainDiffSection(
            title: "Subdomains",
            items: [
                compare(
                    label: "Passive Subdomains",
                    oldValue: subdomainList(from: oldSnapshot),
                    newValue: subdomainList(from: newSnapshot),
                    severity: .low
                )
            ].compactMap { $0 }
        )
    }

    private static func compare(
        label: String,
        oldValue: String?,
        newValue: String?,
        severity: ChangeSeverity
    ) -> DomainDiffItem? {
        let oldValue = normalized(oldValue)
        let newValue = normalized(newValue)
        let normalizedOldValue = comparisonValue(oldValue)
        let normalizedNewValue = comparisonValue(newValue)

        guard oldValue != nil || newValue != nil else {
            return nil
        }

        let changeType: DiffChangeType
        switch (normalizedOldValue, normalizedNewValue) {
        case let (old?, new?) where old == new:
            changeType = .unchanged
        case (nil, _?):
            changeType = .added
        case (_?, nil):
            changeType = .removed
        default:
            changeType = .changed
        }

        return DomainDiffItem(
            label: label,
            changeType: changeType,
            oldValue: oldValue,
            newValue: newValue,
            severity: severity
        )
    }

    private static func summaryHighlights(from items: [DomainDiffItem]) -> [String] {
        var highlights: [String] = []

        let labels = Set(items.map(\.label))
        if labels.contains("Availability") {
            highlights.append("Availability changed")
        }
        if labels.contains("Primary IP"), labels.contains(where: { $0.hasSuffix("Records") }) {
            highlights.append("IP changed")
            highlights.append("DNS changed")
            return highlights
        }
        if labels.contains("Primary IP") {
            highlights.append("IP changed")
        }
        if labels.contains("Redirect Target") {
            highlights.append("Redirect target changed")
        }
        if labels.contains("Registrar") {
            highlights.append("Registrar changed")
        } else if labels.contains("Nameservers") {
            highlights.append("Nameservers changed")
        } else if labels.contains("Expiration Date") || labels.contains("Registration Date") || labels.contains("Ownership Status") || labels.contains("Abuse Contact") {
            highlights.append("Ownership metadata changed")
        }
        if let certificateItem = items.first(where: { $0.label == "Certificate Warning" }),
           let message = certificateItem.newValue {
            highlights.append(message)
        } else if labels.contains("TLS Issuer") {
            highlights.append("TLS issuer changed")
        } else if labels.contains("TLS Expiration") {
            highlights.append("Certificate expiration changed")
        }
        if labels.contains(where: { $0.hasSuffix("Records") }) {
            highlights.append("DNS changed")
        }
        if labels.contains("HTTP Status") {
            highlights.append("HTTP status changed")
        }
        if labels.contains("Email Security") {
            highlights.append("Email security changed")
        }
        if labels.contains("Passive Subdomains") {
            highlights.append("Subdomains changed")
        }

        var deduplicated: [String] = []
        for highlight in highlights where !deduplicated.contains(highlight) {
            deduplicated.append(highlight)
        }
        return deduplicated
    }

    private static func summaryMessage(from items: [DomainDiffItem], highlights: [String]) -> String {
        guard !items.isEmpty, !highlights.isEmpty else {
            return "No meaningful changes"
        }

        if highlights.count == 1 {
            return highlights[0]
        }

        return "\(highlights[0]) and \(highlights[1].lowercased())"
    }

    private static func observedFacts(from items: [DomainDiffItem]) -> [String] {
        items.prefix(3).map { item in
            let oldValue = item.oldValue ?? "none"
            let newValue = item.newValue ?? "none"
            return "\(item.label): \(oldValue) -> \(newValue)"
        }
    }

    private static func normalized(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }
        return value
    }

    private static func comparisonValue(_ value: String?) -> String? {
        value?.lowercased()
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

    private static func expirationLabel(_ sslInfo: SSLCertificateInfo?) -> String? {
        guard let sslInfo else { return nil }
        return "\(sslInfo.validUntil.formatted(date: .abbreviated, time: .omitted)) (\(sslInfo.daysUntilExpiry)d)"
    }

    private static func ownershipDateLabel(_ date: Date?) -> String? {
        date?.formatted(date: .abbreviated, time: .omitted)
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

    private static func normalizedRecordValues(for section: DNSSection?) -> String? {
        guard let section else { return nil }
        let values = (section.records + section.wildcardRecords)
            .map(\.value)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .sorted()
        return values.isEmpty ? nil : values.joined(separator: ",")
    }

    private static func normalizedTTLValues(for section: DNSSection?) -> String? {
        guard let section else { return nil }
        let values = (section.records + section.wildcardRecords)
            .map { "\($0.value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()):\($0.ttl)" }
            .sorted()
        return values.isEmpty ? nil : values.joined(separator: ",")
    }

    private static func normalizedHeaders(from snapshot: LookupSnapshot) -> String? {
        let headers = snapshot.httpHeaders
            .map { "\($0.name.lowercased()):\($0.value.trimmingCharacters(in: .whitespacesAndNewlines))" }
            .sorted()
        return headers.isEmpty ? nil : headers.joined(separator: "|")
    }

    private static func ownershipList(_ values: [String]?) -> String? {
        guard let values else { return nil }
        let normalizedValues = values
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
            .sorted()
        return normalizedValues.isEmpty ? nil : normalizedValues.joined(separator: ",")
    }

    private static func subdomainList(from snapshot: LookupSnapshot) -> String? {
        let values = snapshot.subdomains
            .map(\.hostname)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .sorted()
        return values.isEmpty ? nil : values.joined(separator: ",")
    }
}
