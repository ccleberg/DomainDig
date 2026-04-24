import Foundation

struct DomainReport: Codable {
    let domain: String
    let timestamp: Date
    let provenance: DomainReportProvenance
    let appVersion: String
    let resolverDisplayName: String
    let resolverURLString: String
    let dataSources: [String]
    let resultSource: LookupResultSource
    let sectionProvenance: [LookupSectionKind: SectionProvenance]
    let errorDetails: [LookupSectionKind: InspectionFailure]
    let isPartialSnapshot: Bool
    let validationIssues: [String]
    let auditNote: String?
    let availability: DomainAvailabilityStatus
    let availabilityConfidence: ConfidenceLevel?
    let ownershipConfidence: ConfidenceLevel?
    let subdomainConfidence: ConfidenceLevel?
    let emailConfidence: ConfidenceLevel?
    let geolocationConfidence: ConfidenceLevel?
    let ownership: DomainOwnership?
    let ownershipHistory: [DomainOwnershipHistoryEvent]
    let dns: DNSResultSummary
    let web: WebResultSummary
    let email: EmailSecuritySummary
    let network: NetworkSummary
    let subdomains: [String]
    let extendedSubdomains: [String]
    let dnsHistory: [DNSHistoryEvent]
    let domainPricing: DomainPricingInsight?
    let subdomainGroups: [SubdomainGroup]
    let riskAssessment: DomainRiskAssessment
    let insights: [String]
    let changeSummary: DomainChangeSummary?
    let workflowContext: DomainWorkflowContext?
    let metadata: DomainReportMetadata
}

struct DomainReportProvenance: Codable {
    let collectedAt: Date
    let source: LookupResultSource
    let sections: [LookupSectionKind: SectionProvenance]
    let dataSources: [String]
}

struct DomainWorkflowContext: Codable {
    let workflowID: UUID?
    let workflowName: String?
    let source: String
}

struct DomainReportMetadata: Codable {
    let schemaVersion: String
    let resolverDisplayName: String
    let resolverURLString: String
    let appVersion: String
    let cachedSections: [LookupSectionKind]
    let auditNote: String?
    let validationIssues: [String]
    let isPartialSnapshot: Bool
    let errorDetails: [LookupSectionKind: InspectionFailure]
    let statusMessage: String?
    let snapshotIndex: Int?
    let previousSnapshotID: UUID?
    let changeCount: Int
    let severitySummary: ChangeSeverity?
}

struct DNSResultSummary: Codable {
    let resolverDisplayName: String
    let resolverURLString: String
    let lookupDurationMs: Int?
    let recordSections: [DNSSection]
    let primaryIP: String?
    let ptrRecord: String?
    let dnssecSigned: Bool?
    let patternSummary: DNSPatternSummary
    let error: String?
    let ptrError: String?
}

struct WebResultSummary: Codable {
    let tls: SSLCertificateInfo?
    let tlsStatus: String
    let tlsGrade: TLSGrade
    let tlsHighlights: [String]
    let certificateWarningLevel: CertificateWarningLevel
    let hstsPreloaded: Bool?
    let headers: [HTTPHeader]
    let headerCount: Int
    let securityGrade: String?
    let statusCode: Int?
    let responseTimeMs: Int?
    let httpProtocol: String?
    let http3Advertised: Bool
    let redirectChain: [RedirectHop]
    let finalURL: String?
    let tlsError: String?
    let headersError: String?
    let redirectError: String?
}

struct EmailSecuritySummary: Codable {
    let records: EmailSecurityResult?
    let grade: EmailSecurityGrade?
    let reasons: [String]
    let summary: String
    let error: String?
}

struct NetworkSummary: Codable {
    let primaryIP: String?
    let reachability: [PortReachability]
    let reachabilitySummary: String
    let reachabilityError: String?
    let geolocation: IPGeolocation?
    let geolocationSummary: String
    let geolocationError: String?
    let portScan: [PortScanResult]
    let openPorts: [UInt16]
    let portScanError: String?
}

struct DomainReportBuilder {
    func build(
        from snapshot: LookupSnapshot,
        previousSnapshot: LookupSnapshot? = nil,
        workflowContext: DomainWorkflowContext? = nil,
        deriveChangeSummary: Bool = true
    ) -> DomainReport {
        let buildStartedAt = DomainDebugLog.signpostStart("DomainReportBuilder.build", domain: snapshot.domain)
        let primaryIP = primaryIPAddress(from: snapshot)
        let analysis = DomainInsightEngine.analyze(snapshot: snapshot, previousSnapshot: previousSnapshot)
        let changeSummary: DomainChangeSummary?
        if let existingChangeSummary = snapshot.changeSummary, existingChangeSummary.riskAssessment != nil {
            changeSummary = existingChangeSummary
        } else if deriveChangeSummary, let previousSnapshot {
            let previousReport = build(
                from: previousSnapshot,
                workflowContext: workflowContext,
                deriveChangeSummary: false
            )
            let currentReport = buildBaseReport(
                from: snapshot,
                previousSnapshot: previousSnapshot,
                workflowContext: workflowContext,
                analysis: analysis,
                primaryIP: primaryIP,
                changeSummary: nil as DomainChangeSummary?
            )
            let diff = DiffService.compare(from: previousReport, to: currentReport)
            let changedItems = diff.sections.flatMap { $0.items }.filter { $0.hasChanges }
            let highlights = diff.changedSectionTitles
            let severity = changedItems.map { $0.severity }.max() ?? .low
            let message = DiffService.summaryMessage(from: highlights, changeCount: changedItems.count)
            let observedFacts = changedItems.prefix(4).map { item in
                "\(item.label): \(item.oldValue ?? "none") -> \(item.newValue ?? "none")"
            }
            let previousRiskScore = previousReport.riskAssessment.score
            let riskScoreDelta = analysis.riskAssessment.score - previousRiskScore
            let impactClassification = DomainInsightEngine.impactClassification(
                severity: severity,
                riskDelta: riskScoreDelta,
                changedSections: highlights
            )

            changeSummary = DomainChangeSummary(
                hasChanges: !changedItems.isEmpty,
                changedSections: highlights,
                message: message,
                severity: severity,
                impactClassification: impactClassification,
                generatedAt: snapshot.timestamp,
                observedFacts: observedFacts,
                inferredConclusions: highlights.isEmpty ? [] : [message],
                contextNote: diff.contextNote,
                riskAssessment: analysis.riskAssessment,
                insights: analysis.insights,
                riskScoreDelta: riskScoreDelta
            )
        } else {
            changeSummary = nil
        }

        let report = buildBaseReport(
            from: snapshot,
            previousSnapshot: previousSnapshot,
            workflowContext: workflowContext,
            analysis: analysis,
            primaryIP: primaryIP,
            changeSummary: changeSummary
        )
        DomainDebugLog.signpostEnd(
            "DomainReportBuilder.build",
            start: buildStartedAt,
            domain: snapshot.domain,
            extra: "risk=\(report.riskAssessment.score) insights=\(report.insights.count)"
        )
        return report
    }

    func build(
        from entry: HistoryEntry,
        previousSnapshot: LookupSnapshot? = nil,
        workflowContext: DomainWorkflowContext? = nil,
        deriveChangeSummary: Bool = true
    ) -> DomainReport {
        build(
            from: entry.snapshot,
            previousSnapshot: previousSnapshot,
            workflowContext: workflowContext,
            deriveChangeSummary: deriveChangeSummary
        )
    }

    private func buildBaseReport(
        from snapshot: LookupSnapshot,
        previousSnapshot: LookupSnapshot?,
        workflowContext: DomainWorkflowContext?,
        analysis: DomainAnalysisBundle,
        primaryIP: String?,
        changeSummary: DomainChangeSummary?
    ) -> DomainReport {
        DomainReport(
            domain: snapshot.domain,
            timestamp: snapshot.timestamp,
            provenance: DomainReportProvenance(
                collectedAt: snapshot.timestamp,
                source: snapshot.resultSource,
                sections: snapshot.provenanceBySection,
                dataSources: snapshot.dataSources
            ),
            appVersion: snapshot.appVersion,
            resolverDisplayName: snapshot.resolverDisplayName,
            resolverURLString: snapshot.resolverURLString,
            dataSources: snapshot.dataSources,
            resultSource: snapshot.resultSource,
            sectionProvenance: snapshot.provenanceBySection,
            errorDetails: snapshot.errorDetails,
            isPartialSnapshot: snapshot.isPartialSnapshot,
            validationIssues: snapshot.validationIssues,
            auditNote: snapshot.note,
            availability: snapshot.availabilityResult?.status ?? .unknown,
            availabilityConfidence: snapshot.availabilityConfidence,
            ownershipConfidence: snapshot.ownershipConfidence,
            subdomainConfidence: snapshot.subdomainConfidence,
            emailConfidence: snapshot.emailSecurityConfidence,
            geolocationConfidence: snapshot.geolocationConfidence,
            ownership: snapshot.ownership,
            ownershipHistory: snapshot.ownershipHistory,
            dns: DNSResultSummary(
                resolverDisplayName: snapshot.resolverDisplayName,
                resolverURLString: snapshot.resolverURLString,
                lookupDurationMs: snapshot.totalLookupDurationMs,
                recordSections: snapshot.dnsSections,
                primaryIP: primaryIP,
                ptrRecord: snapshot.ptrRecord,
                dnssecSigned: dnssecSigned(from: snapshot),
                patternSummary: analysis.dnsPatterns,
                error: snapshot.dnsError,
                ptrError: snapshot.ptrError
            ),
            web: WebResultSummary(
                tls: snapshot.sslInfo,
                tlsStatus: tlsStatus(from: snapshot),
                tlsGrade: analysis.tlsAssessment.grade,
                tlsHighlights: analysis.tlsAssessment.highlights,
                certificateWarningLevel: DomainDiffService.certificateWarningLevel(for: snapshot),
                hstsPreloaded: snapshot.hstsPreloaded,
                headers: snapshot.httpHeaders,
                headerCount: snapshot.httpHeaders.count,
                securityGrade: snapshot.httpSecurityGrade,
                statusCode: snapshot.httpStatusCode,
                responseTimeMs: snapshot.httpResponseTimeMs,
                httpProtocol: snapshot.httpProtocol,
                http3Advertised: snapshot.http3Advertised,
                redirectChain: snapshot.redirectChain,
                finalURL: snapshot.redirectChain.last?.url,
                tlsError: snapshot.sslError,
                headersError: snapshot.httpHeadersError,
                redirectError: snapshot.redirectChainError
            ),
            email: EmailSecuritySummary(
                records: snapshot.emailSecurity,
                grade: analysis.emailAssessment?.grade,
                reasons: analysis.emailAssessment?.reasons ?? [],
                summary: emailSummary(from: snapshot, assessment: analysis.emailAssessment),
                error: snapshot.emailSecurityError
            ),
            network: NetworkSummary(
                primaryIP: primaryIP,
                reachability: snapshot.reachabilityResults,
                reachabilitySummary: reachabilitySummary(from: snapshot),
                reachabilityError: snapshot.reachabilityError,
                geolocation: snapshot.ipGeolocation,
                geolocationSummary: geolocationSummary(from: snapshot),
                geolocationError: snapshot.ipGeolocationError,
                portScan: snapshot.portScanResults,
                openPorts: snapshot.portScanResults.filter(\.open).map(\.port),
                portScanError: snapshot.portScanError
            ),
            subdomains: snapshot.subdomains.map(\.hostname),
            extendedSubdomains: snapshot.extendedSubdomains.map(\.hostname),
            dnsHistory: snapshot.dnsHistory,
            domainPricing: snapshot.domainPricing,
            subdomainGroups: analysis.subdomainGroups,
            riskAssessment: analysis.riskAssessment,
            insights: analysis.insights,
            changeSummary: changeSummary,
            workflowContext: workflowContext,
            metadata: DomainReportMetadata(
                schemaVersion: "3.7.0",
                resolverDisplayName: snapshot.resolverDisplayName,
                resolverURLString: snapshot.resolverURLString,
                appVersion: snapshot.appVersion,
                cachedSections: snapshot.cachedSections,
                auditNote: snapshot.note,
                validationIssues: snapshot.validationIssues,
                isPartialSnapshot: snapshot.isPartialSnapshot,
                errorDetails: snapshot.errorDetails,
                statusMessage: snapshot.statusMessage,
                snapshotIndex: snapshot.snapshotIndex,
                previousSnapshotID: snapshot.previousSnapshotID ?? previousSnapshot?.historyEntryID,
                changeCount: snapshot.changeCount == 0 ? (changeSummary?.changedSections.count ?? 0) : snapshot.changeCount,
                severitySummary: snapshot.severitySummary ?? changeSummary?.severity
            )
        )
    }

    private func primaryIPAddress(from snapshot: LookupSnapshot) -> String? {
        snapshot.dnsSections.first(where: { $0.recordType == .A })?.records.first?.value
    }

    private func dnssecSigned(from snapshot: LookupSnapshot) -> Bool? {
        snapshot.dnsSections.compactMap(\.dnssecSigned).first
    }

    private func tlsStatus(from snapshot: LookupSnapshot) -> String {
        if snapshot.sslInfo != nil {
            return "valid"
        }
        if let sslError = snapshot.sslError {
            return sslError.localizedCaseInsensitiveContains("certificate") ? "invalid" : "failed"
        }
        return "unavailable"
    }

    private func emailSummary(from snapshot: LookupSnapshot, assessment: EmailSecurityAssessment?) -> String {
        guard let emailSecurity = snapshot.emailSecurity else {
            return snapshot.emailSecurityError ?? "Unavailable"
        }

        return [
            "Grade \(assessment?.grade.rawValue ?? "?")",
            "SPF \(emailSecurity.spf.found ? "Yes" : "No")",
            "DMARC \(emailSecurity.dmarc.found ? "Yes" : "No")",
            "DKIM \(emailSecurity.dkim.found ? "Yes" : "No")",
            "BIMI \(emailSecurity.bimi.found ? "Yes" : "No")",
            "MTA-STS \(emailSecurity.mtaSts?.txtFound == true ? "Yes" : "No")"
        ].joined(separator: " / ")
    }

    private func reachabilitySummary(from snapshot: LookupSnapshot) -> String {
        guard !snapshot.reachabilityResults.isEmpty else {
            return snapshot.reachabilityError ?? "Unavailable"
        }

        return snapshot.reachabilityResults
            .sorted { $0.port < $1.port }
            .map { "\($0.port):\($0.reachable ? "open" : "closed")" }
            .joined(separator: ", ")
    }

    private func geolocationSummary(from snapshot: LookupSnapshot) -> String {
        guard let geolocation = snapshot.ipGeolocation else {
            return snapshot.ipGeolocationError ?? "Unavailable"
        }

        let parts = [geolocation.city, geolocation.region, geolocation.country_name]
            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        if !parts.isEmpty {
            return parts.joined(separator: ", ")
        }

        return geolocation.ip
    }
}
