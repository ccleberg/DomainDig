import Foundation

@main
struct DomainDigCLI {
    static func main() async {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let wantsJSON = arguments.contains("--json") || arguments.contains("-j")

        guard let command = CommandLine.arguments.first else {
            fputs(usageText, stderr)
            Foundation.exit(1)
        }
        _ = command

        if arguments.first == "backup" {
            runBackupCommand(arguments: Array(arguments.dropFirst()), wantsJSON: wantsJSON)
            return
        }

        if arguments.first == "history" {
            runHistoryCommand(arguments: Array(arguments.dropFirst()), wantsJSON: wantsJSON)
            return
        }

        if arguments.first == "diff" {
            runDiffCommand(arguments: Array(arguments.dropFirst()), wantsJSON: wantsJSON)
            return
        }

        if arguments.first == "monitor" {
            await runMonitorCommand(wantsJSON: wantsJSON)
            return
        }

        let wantsOwnershipHistory = arguments.contains("--ownership-history")
        let wantsDNSHistory = arguments.contains("--dns-history")
        let wantsExtendedSubdomains = arguments.contains("--extended-subdomains")
        let wantsPricing = arguments.contains("--pricing")
        let domains = arguments.filter { !$0.hasPrefix("-") }

        let requestedDomains = domains
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        guard !requestedDomains.isEmpty else {
            fputs(usageText, stderr)
            Foundation.exit(1)
        }

        let inspectionService = DomainInspectionService()
        let reportBuilder = DomainReportBuilder()
        var reports: [DomainReport] = []
        var seen = Set<String>()
        for domain in requestedDomains {
            let normalizedDomain = domain.lowercased()
            guard seen.insert(normalizedDomain).inserted else { continue }
            let snapshot = await inspectionService.inspectSnapshot(domain: domain)
            let enrichedSnapshot = await enrichSnapshot(
                snapshot,
                wantsOwnershipHistory: wantsOwnershipHistory,
                wantsDNSHistory: wantsDNSHistory,
                wantsExtendedSubdomains: wantsExtendedSubdomains,
                wantsPricing: wantsPricing
            )
            reports.append(reportBuilder.build(from: enrichedSnapshot))
        }

        do {
            let data: Data
            if reports.count == 1, let report = reports.first {
                data = try DomainReportExporter.data(
                    for: report,
                    format: wantsJSON ? .json : .text
                )
            } else {
                data = try DomainReportExporter.data(
                    for: reports,
                    format: wantsJSON ? .json : .text,
                    title: "DomainDig Batch Report"
                )
            }
            FileHandle.standardOutput.write(data)
            if data.last != 0x0A {
                FileHandle.standardOutput.write(Data([0x0A]))
            }
        } catch {
            fputs("domaindig: \(error.localizedDescription)\n", stderr)
            Foundation.exit(1)
        }
    }

    private static func enrichSnapshot(
        _ snapshot: LookupSnapshot,
        wantsOwnershipHistory: Bool,
        wantsDNSHistory: Bool,
        wantsExtendedSubdomains: Bool,
        wantsPricing: Bool
    ) async -> LookupSnapshot {
        guard FeatureAccessService.currentTier == .proPlus else {
            return snapshot
        }

        let historyEntries = loadHistoryEntries()
        var ownershipHistory = snapshot.ownershipHistory
        var ownershipHistoryError = snapshot.ownershipHistoryError
        var dnsHistory = snapshot.dnsHistory
        var dnsHistoryError = snapshot.dnsHistoryError
        var extendedSubdomains = snapshot.extendedSubdomains
        var extendedSubdomainsError = snapshot.extendedSubdomainsError
        var domainPricing = snapshot.domainPricing
        var domainPricingError = snapshot.domainPricingError

        if wantsOwnershipHistory {
            let outcome = await ExternalDataService.shared.ownershipHistory(
                domain: snapshot.domain,
                currentOwnership: snapshot.ownership,
                historyEntries: historyEntries
            )
            switch outcome.value {
            case let .success(events):
                ownershipHistory = events
                ownershipHistoryError = nil
            case let .empty(message):
                ownershipHistoryError = message
            case let .error(message):
                ownershipHistoryError = message
            }
        }

        if wantsDNSHistory {
            let outcome = await ExternalDataService.shared.dnsHistory(
                domain: snapshot.domain,
                dnsSections: snapshot.dnsSections,
                historyEntries: historyEntries
            )
            switch outcome.value {
            case let .success(events):
                dnsHistory = events
                dnsHistoryError = nil
            case let .empty(message):
                dnsHistoryError = message
            case let .error(message):
                dnsHistoryError = message
            }
        }

        if wantsExtendedSubdomains {
            let outcome = await ExternalDataService.shared.extendedSubdomains(
                domain: snapshot.domain,
                existing: snapshot.subdomains
            )
            switch outcome.value {
            case let .success(results):
                extendedSubdomains = results
                extendedSubdomainsError = nil
            case let .empty(message):
                extendedSubdomainsError = message
            case let .error(message):
                extendedSubdomainsError = message
            }
        }

        if wantsPricing {
            let outcome = await ExternalDataService.shared.pricing(domain: snapshot.domain)
            switch outcome.value {
            case let .success(pricing):
                domainPricing = pricing
                domainPricingError = nil
            case let .empty(message), let .error(message):
                domainPricingError = message
            }
        }

        return LookupSnapshot(
            historyEntryID: snapshot.historyEntryID,
            domain: snapshot.domain,
            timestamp: snapshot.timestamp,
            trackedDomainID: snapshot.trackedDomainID,
            note: snapshot.note,
            appVersion: snapshot.appVersion,
            resolverDisplayName: snapshot.resolverDisplayName,
            resolverURLString: snapshot.resolverURLString,
            dataSources: snapshot.dataSources,
            provenanceBySection: snapshot.provenanceBySection,
            availabilityConfidence: snapshot.availabilityConfidence,
            ownershipConfidence: snapshot.ownershipConfidence,
            subdomainConfidence: snapshot.subdomainConfidence,
            emailSecurityConfidence: snapshot.emailSecurityConfidence,
            geolocationConfidence: snapshot.geolocationConfidence,
            errorDetails: snapshot.errorDetails,
            isPartialSnapshot: snapshot.isPartialSnapshot,
            validationIssues: snapshot.validationIssues,
            totalLookupDurationMs: snapshot.totalLookupDurationMs,
            snapshotIndex: snapshot.snapshotIndex,
            previousSnapshotID: snapshot.previousSnapshotID,
            changeCount: snapshot.changeCount,
            severitySummary: snapshot.severitySummary,
            dnsSections: snapshot.dnsSections,
            dnsError: snapshot.dnsError,
            availabilityResult: snapshot.availabilityResult,
            suggestions: snapshot.suggestions,
            sslInfo: snapshot.sslInfo,
            sslError: snapshot.sslError,
            hstsPreloaded: snapshot.hstsPreloaded,
            httpHeaders: snapshot.httpHeaders,
            httpSecurityGrade: snapshot.httpSecurityGrade,
            httpStatusCode: snapshot.httpStatusCode,
            httpResponseTimeMs: snapshot.httpResponseTimeMs,
            httpProtocol: snapshot.httpProtocol,
            http3Advertised: snapshot.http3Advertised,
            httpHeadersError: snapshot.httpHeadersError,
            reachabilityResults: snapshot.reachabilityResults,
            reachabilityError: snapshot.reachabilityError,
            ipGeolocation: snapshot.ipGeolocation,
            ipGeolocationError: snapshot.ipGeolocationError,
            emailSecurity: snapshot.emailSecurity,
            emailSecurityError: snapshot.emailSecurityError,
            ownership: snapshot.ownership,
            ownershipError: snapshot.ownershipError,
            ownershipHistory: ownershipHistory,
            ownershipHistoryError: ownershipHistoryError,
            ptrRecord: snapshot.ptrRecord,
            ptrError: snapshot.ptrError,
            redirectChain: snapshot.redirectChain,
            redirectChainError: snapshot.redirectChainError,
            subdomains: snapshot.subdomains,
            subdomainsError: snapshot.subdomainsError,
            extendedSubdomains: extendedSubdomains,
            extendedSubdomainsError: extendedSubdomainsError,
            dnsHistory: dnsHistory,
            dnsHistoryError: dnsHistoryError,
            domainPricing: domainPricing,
            domainPricingError: domainPricingError,
            portScanResults: snapshot.portScanResults,
            portScanError: snapshot.portScanError,
            changeSummary: snapshot.changeSummary,
            resultSource: snapshot.resultSource,
            cachedSections: snapshot.cachedSections,
            statusMessage: snapshot.statusMessage
        )
    }

    private static func loadHistoryEntries() -> [HistoryEntry] {
        DomainDataPortabilityService.loadHistoryEntries()
    }

    private static func runHistoryCommand(arguments: [String], wantsJSON: Bool) {
        guard let domain = arguments.first(where: { !$0.hasPrefix("-") }) else {
            fputs("usage: domaindig history <domain> [--json]\n", stderr)
            Foundation.exit(1)
        }

        let entries = loadHistoryEntries()
            .filter { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }
            .sorted { $0.timestamp > $1.timestamp }

        if wantsJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let payload = entries.map { entry in
                [
                    "id": entry.id.uuidString,
                    "timestamp": ISO8601DateFormatter().string(from: entry.timestamp),
                    "changeSummary": entry.changeSummary?.message ?? "No change summary",
                    "changeCount": "\(entry.changeCount)",
                    "severity": entry.severitySummary?.title ?? "N/A"
                ]
            }
            if let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]) {
                FileHandle.standardOutput.write(data)
                FileHandle.standardOutput.write(Data([0x0A]))
                return
            }
        }

        let lines = entries.map { entry in
            [
                entry.id.uuidString,
                entry.timestamp.formatted(date: .abbreviated, time: .shortened),
                entry.changeSummary?.message ?? "No change summary"
            ].joined(separator: " | ")
        }

        FileHandle.standardOutput.write(Data((lines.isEmpty ? "No history found.\n" : lines.joined(separator: "\n") + "\n").utf8))
    }

    private static func runDiffCommand(arguments: [String], wantsJSON: Bool) {
        guard let domain = arguments.first(where: { !$0.hasPrefix("-") }) else {
            fputs("usage: domaindig diff <domain> --from <id> --to <id> [--json]\n", stderr)
            Foundation.exit(1)
        }

        guard let fromID = optionValue(named: "--from", in: arguments),
              let toID = optionValue(named: "--to", in: arguments),
              let fromUUID = UUID(uuidString: fromID),
              let toUUID = UUID(uuidString: toID) else {
            fputs("domaindig diff: --from and --to must be valid snapshot IDs\n", stderr)
            Foundation.exit(1)
        }

        let entries = loadHistoryEntries().filter { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }
        guard let fromEntry = entries.first(where: { $0.id == fromUUID }),
              let toEntry = entries.first(where: { $0.id == toUUID }) else {
            fputs("domaindig diff: snapshots not found for domain\n", stderr)
            Foundation.exit(1)
        }

        let orderedEntries = [fromEntry, toEntry].sorted { $0.timestamp < $1.timestamp }
        let diff = DiffService.compare(from: orderedEntries[0].snapshot, to: orderedEntries[1].snapshot)

        if wantsJSON {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            if let data = try? encoder.encode(diff) {
                FileHandle.standardOutput.write(data)
                FileHandle.standardOutput.write(Data([0x0A]))
                return
            }
        }

        var lines = [
            "DomainDig Diff",
            "Domain: \(domain)",
            "From: \(orderedEntries[0].id.uuidString)",
            "To: \(orderedEntries[1].id.uuidString)"
        ]

        for section in diff.sections where section.hasChanges {
            lines.append("")
            lines.append(section.title)
            for item in section.items where item.hasChanges {
                lines.append("\(item.changeType.marker) \(item.label): \(item.oldValue ?? "none") -> \(item.newValue ?? "none")")
            }
        }

        FileHandle.standardOutput.write(Data((lines.joined(separator: "\n") + "\n").utf8))
    }

    private static func optionValue(named name: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: name), arguments.indices.contains(index + 1) else {
            return nil
        }
        return arguments[index + 1]
    }

    private static func runBackupCommand(arguments: [String], wantsJSON: Bool) {
        guard let subcommand = arguments.first else {
            fputs(usageText, stderr)
            Foundation.exit(1)
        }

        switch subcommand {
        case "export":
            do {
                let data = try DomainDataPortabilityService.backupData()
                let outputPath = arguments.dropFirst().first(where: { !$0.hasPrefix("-") })
                if let outputPath {
                    try data.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
                } else {
                    FileHandle.standardOutput.write(data)
                    if data.last != 0x0A {
                        FileHandle.standardOutput.write(Data([0x0A]))
                    }
                }
            } catch {
                fputs("domaindig backup export: \(error.localizedDescription)\n", stderr)
                Foundation.exit(1)
            }
        case "validate":
            guard let path = arguments.dropFirst().first(where: { !$0.hasPrefix("-") }) else {
                fputs("usage: domaindig backup validate <path>\n", stderr)
                Foundation.exit(1)
            }

            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: path))
                let report = try DomainDataPortabilityService.validateBackup(data: data, fileName: URL(fileURLWithPath: path).lastPathComponent)
                if wantsJSON {
                    let payload = [
                        "warnings": report.warnings,
                        "errors": report.errors
                    ]
                    let encoded = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
                    FileHandle.standardOutput.write(encoded)
                } else {
                    let lines = [
                        "Warnings: \(report.warnings.count)",
                        "Errors: \(report.errors.count)"
                    ] + report.warnings.map { "warning: \($0)" } + report.errors.map { "error: \($0)" }
                    FileHandle.standardOutput.write(Data(lines.joined(separator: "\n").utf8))
                }
                FileHandle.standardOutput.write(Data([0x0A]))
                if !report.errors.isEmpty {
                    Foundation.exit(1)
                }
            } catch {
                fputs("domaindig backup validate: \(error.localizedDescription)\n", stderr)
                Foundation.exit(1)
            }
        case "import":
            guard let path = arguments.dropFirst().first(where: { !$0.hasPrefix("-") }) else {
                fputs("usage: domaindig backup import <path> [--replace]\n", stderr)
                Foundation.exit(1)
            }

            let mode: DataPortabilityImportMode = arguments.contains("--replace") ? .replace : .merge

            do {
                let fileURL = URL(fileURLWithPath: path)
                let data = try Data(contentsOf: fileURL)
                let preview = try DomainDataPortabilityService.prepareImport(
                    data: data,
                    fileName: fileURL.lastPathComponent,
                    mode: mode
                )
                guard preview.kind == .backup else {
                    fputs("domaindig backup import: expected a full backup file\n", stderr)
                    Foundation.exit(1)
                }
                let result = try DomainDataPortabilityService.applyImport(preview, mode: mode)
                let lines = [result.summary] + result.warnings.map { "warning: \($0)" }
                FileHandle.standardOutput.write(Data(lines.joined(separator: "\n").utf8))
                FileHandle.standardOutput.write(Data([0x0A]))
            } catch {
                fputs("domaindig backup import: \(error.localizedDescription)\n", stderr)
                Foundation.exit(1)
            }
        default:
            fputs(usageText, stderr)
            Foundation.exit(1)
        }
    }

    private static func runMonitorCommand(wantsJSON: Bool) async {
        guard FeatureAccessService.hasAccess(to: .automatedMonitoring) else {
            fputs("domaindig monitor: monitoring requires Pro\n", stderr)
            Foundation.exit(1)
        }

        let outcome = await DomainMonitoringService.shared.performMonitoring(
            trigger: .cli,
            requireEnabledSetting: false
        )

        guard let log = outcome.log else {
            fputs("domaindig monitor: \(outcome.message)\n", stderr)
            Foundation.exit(1)
        }

        do {
            let output: Data
            if wantsJSON {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                output = try encoder.encode(log)
            } else {
                output = Data(monitoringTextSummary(for: log).utf8)
            }
            FileHandle.standardOutput.write(output)
            if output.last != 0x0A {
                FileHandle.standardOutput.write(Data([0x0A]))
            }
            if !outcome.success {
                Foundation.exit(1)
            }
        } catch {
            fputs("domaindig monitor: \(error.localizedDescription)\n", stderr)
            Foundation.exit(1)
        }
    }

    private static func monitoringTextSummary(for log: MonitoringLog) -> String {
        var lines = [
            "DomainDig Monitoring",
            "====================",
            "Trigger: \(log.trigger.title)",
            "Timestamp: \(log.timestamp.formatted(date: .abbreviated, time: .shortened))",
            "Checked: \(log.domainsChecked)",
            "Changes: \(log.changesFound)",
            "Alerts: \(log.alertsTriggered)",
            ""
        ]

        if log.checkedDomains.isEmpty {
            lines.append("No domains were checked.")
        } else {
            for result in log.checkedDomains {
                let severity = result.alertSeverity?.title ?? "None"
                lines.append("\(result.domain): \(result.summaryMessage) [alert: \(severity)]")
            }
        }

        if !log.errors.isEmpty {
            lines.append("")
            lines.append("Errors:")
            lines.append(contentsOf: log.errors.map { "- \($0)" })
        }

        return lines.joined(separator: "\n")
    }

    private static var usageText: String {
        """
        usage: domaindig <domain> [--json] [--ownership-history] [--dns-history] [--extended-subdomains] [--pricing]
               domaindig history <domain> [--json]
               domaindig diff <domain> --from <id> --to <id> [--json]
               domaindig monitor [--json]
               domaindig backup export [path]
               domaindig backup import <path> [--replace]
               domaindig backup validate <path> [--json]
        
        note: the CLI remains local-only and does not sync with iCloud yet.
        """
    }
}
