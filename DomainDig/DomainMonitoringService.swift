import Foundation
import UserNotifications

#if canImport(BackgroundTasks)
import BackgroundTasks
#endif

#if canImport(UIKit)
import UIKit
#endif

enum MonitoringStorage {
    static let settingsKey = "monitoring.settings"
    static let logsKey = "monitoring.logs"
    static let trackedDomainsKey = "trackedDomains"
    static let historyKey = "lookupHistory"
    static let maxLogs = 40

    static func loadSettings() -> MonitoringSettings {
        DataMigrationService.migrateIfNeeded()
        return DomainDataPortabilityService.loadMonitoringSettings()
    }

    static func saveSettings(_ settings: MonitoringSettings) {
        DomainDataPortabilityService.saveMonitoringSettings(settings)
    }

    static func loadLogs() -> [MonitoringLog] {
        DataMigrationService.migrateIfNeeded()
        return DomainDataPortabilityService.loadMonitoringLogs()
    }

    static func saveLogs(_ logs: [MonitoringLog]) {
        DomainDataPortabilityService.saveMonitoringLogs(Array(logs.prefix(maxLogs)))
    }

    static func loadTrackedDomains() -> [TrackedDomain] {
        DataMigrationService.migrateIfNeeded()
        return DomainDataPortabilityService.loadTrackedDomains()
    }

    static func saveTrackedDomains(_ domains: [TrackedDomain]) {
        DomainDataPortabilityService.saveTrackedDomains(domains)
    }

    static func loadHistoryEntries() -> [HistoryEntry] {
        DataMigrationService.migrateIfNeeded()
        return DomainDataPortabilityService.loadHistoryEntries()
    }

    static func saveHistoryEntries(_ entries: [HistoryEntry]) {
        DomainDataPortabilityService.saveHistoryEntries(entries)
    }

    static func sanitizeSettings(_ settings: MonitoringSettings, trackedDomains: [TrackedDomain]) -> MonitoringSettings {
        let validIDs = Set(trackedDomains.map(\.id))
        var sanitized = settings
        sanitized.selectedDomainIDs = sanitized.selectedDomainIDs.filter { validIDs.contains($0) }
        return sanitized
    }

    static func monitoredDomains(settings: MonitoringSettings, trackedDomains: [TrackedDomain]) -> [TrackedDomain] {
        let sanitized = sanitizeSettings(settings, trackedDomains: trackedDomains)
        switch sanitized.scope {
        case .allTracked:
            return trackedDomains.filter(\.monitoringEnabled)
        case .selectedOnly:
            let selected = Set(sanitized.selectedDomainIDs)
            return trackedDomains.filter { selected.contains($0.id) && $0.monitoringEnabled }
        }
    }
}

struct MonitoringRunOutcome {
    let success: Bool
    let message: String
    let log: MonitoringLog?
}

@MainActor
final class DomainMonitoringScheduler {
    static let shared = DomainMonitoringScheduler()
    static let taskIdentifier = "net.cleberg.DomainDig.monitor.refresh"

    private var isRegistered = false

    private init() {}

    func registerBackgroundTask() {
        #if canImport(BackgroundTasks)
        guard !isRegistered else { return }
        isRegistered = BGTaskScheduler.shared.register(forTaskWithIdentifier: Self.taskIdentifier, using: nil) { task in
            guard let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            self.handleAppRefresh(task: refreshTask)
        }
        #endif
    }

    func backgroundRefreshStatusDescription() -> String {
        #if canImport(UIKit)
        switch UIApplication.shared.backgroundRefreshStatus {
        case .available:
            return "Available"
        case .denied:
            return "Disabled in Settings"
        case .restricted:
            return "Restricted by the system"
        @unknown default:
            return "Unknown"
        }
        #else
        return "Unavailable on this platform"
        #endif
    }

    @discardableResult
    func syncSchedule() -> String? {
        #if canImport(BackgroundTasks)
        let settings = MonitoringStorage.loadSettings()
        guard settings.isEnabled, FeatureAccessService.hasAccess(to: .automatedMonitoring) else {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
            return nil
        }

        #if canImport(UIKit)
        guard UIApplication.shared.backgroundRefreshStatus == .available else {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
            return "Background refresh is unavailable."
        }
        #endif

        let request = BGAppRefreshTaskRequest(identifier: Self.taskIdentifier)
        request.earliestBeginDate = Date(
            timeIntervalSinceNow: max(settings.frequency.schedulingInterval, 15 * 60)
        )

        do {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: Self.taskIdentifier)
            try BGTaskScheduler.shared.submit(request)
            return nil
        } catch {
            return "Could not schedule monitoring."
        }
        #else
        return "Background monitoring is unavailable on this platform."
        #endif
    }

#if canImport(BackgroundTasks)
    private func handleAppRefresh(task: BGAppRefreshTask) {
        _ = syncSchedule()

        let worker = Task {
            let outcome = await DomainMonitoringService.shared.performMonitoring(
                trigger: .background,
                requireEnabledSetting: true
            )
            task.setTaskCompleted(success: outcome.success)
        }

        task.expirationHandler = {
            worker.cancel()
        }
    }
#endif
}

@MainActor
final class DomainMonitoringService {
    static let shared = DomainMonitoringService()

    private let inspectionService = DomainInspectionService()
    private let maxHistoryEntries = 250

    func performMonitoring(
        trigger: MonitoringRunTrigger,
        requireEnabledSetting: Bool
    ) async -> MonitoringRunOutcome {
        let trackedDomains = MonitoringStorage.loadTrackedDomains()
        var settings = MonitoringStorage.sanitizeSettings(MonitoringStorage.loadSettings(), trackedDomains: trackedDomains)
        MonitoringStorage.saveSettings(settings)

        guard FeatureAccessService.hasAccess(to: .automatedMonitoring) else {
            if settings.isEnabled {
                settings.isEnabled = false
                MonitoringStorage.saveSettings(settings)
                await MainActor.run {
                    _ = DomainMonitoringScheduler.shared.syncSchedule()
                }
            }
            return MonitoringRunOutcome(success: false, message: "Monitoring requires Pro.", log: nil)
        }

        if requireEnabledSetting, !settings.isEnabled {
            return MonitoringRunOutcome(success: false, message: "Monitoring is disabled.", log: nil)
        }

        var history = MonitoringStorage.loadHistoryEntries()
        var mutableTrackedDomains = trackedDomains
        let eligibleDomains = MonitoringStorage.monitoredDomains(settings: settings, trackedDomains: mutableTrackedDomains)

        guard !eligibleDomains.isEmpty else {
            let log = MonitoringLog(
                timestamp: Date(),
                trigger: trigger,
                domainsChecked: 0,
                changesFound: 0,
                alertsTriggered: 0,
                checkedDomains: [],
                errors: ["No tracked domains are configured for monitoring."]
            )
            saveLog(log)
            return MonitoringRunOutcome(success: false, message: "No domains selected for monitoring.", log: log)
        }

        let notificationsAuthorized: Bool
        if settings.alertsEnabled {
            notificationsAuthorized = await LocalNotificationService.shared.isAuthorizedForAlerts()
        } else {
            notificationsAuthorized = false
        }
        var results: [MonitoringDomainResult] = []
        var errors: [String] = []
        var alertsTriggered = 0

        for trackedDomain in eligibleDomains {
            guard !Task.isCancelled else {
                return MonitoringRunOutcome(success: false, message: "Monitoring cancelled.", log: nil)
            }

            let previousSnapshot = latestSnapshot(for: trackedDomain, history: history)
            let inspectedSnapshot = await inspectionService.inspectSnapshot(
                domain: trackedDomain.domain,
                previousSnapshot: previousSnapshot
            )
            let snapshot = Self.resolvedSnapshotAfterFallback(inspectedSnapshot, previousSnapshot: previousSnapshot)
            let savedEntry: HistoryEntry?
            if snapshot.statusMessage == nil {
                savedEntry = persistSnapshot(
                    snapshot,
                    trackedDomainID: trackedDomain.id,
                    trackedDomains: &mutableTrackedDomains,
                    history: &history
                )
            } else {
                savedEntry = history.first(where: { $0.id == snapshot.historyEntryID })
            }

            let alertDescriptor = alertDescriptor(
                previousSnapshot: previousSnapshot,
                snapshot: snapshot,
                entry: savedEntry
            )

            if let index = mutableTrackedDomains.firstIndex(where: { $0.id == trackedDomain.id }) {
                mutableTrackedDomains[index].lastMonitoredAt = Date()
            }

            if notificationsAuthorized,
               let alertDescriptor,
               alertDescriptor.severity >= settings.alertFilter.minimumSeverity {
                await LocalNotificationService.shared.notifyMonitoringAlert(
                    domain: trackedDomain.domain,
                    message: alertDescriptor.message,
                    severity: alertDescriptor.severity
                )
                alertsTriggered += 1
                if let index = mutableTrackedDomains.firstIndex(where: { $0.id == trackedDomain.id }) {
                    mutableTrackedDomains[index].lastAlertAt = Date()
                }
            }

            let result = MonitoringDomainResult(
                domain: trackedDomain.domain,
                historyEntryID: savedEntry?.id ?? snapshot.historyEntryID,
                checkedAt: Date(),
                didChange: snapshot.statusMessage == nil && savedEntry?.changeSummary?.hasChanges == true,
                summaryMessage: snapshot.statusMessage
                    ?? savedEntry?.changeSummary?.message
                    ?? "No meaningful changes",
                alertSeverity: alertDescriptor?.severity,
                certificateWarningLevel: DomainDiffService.certificateWarningLevel(for: snapshot),
                resultSource: snapshot.resultSource,
                errorMessage: snapshot.statusMessage
            )
            results.append(result)

            if let errorMessage = result.errorMessage {
                errors.append("\(trackedDomain.domain): \(errorMessage)")
            }
        }

        MonitoringStorage.saveTrackedDomains(mutableTrackedDomains)
        MonitoringStorage.saveHistoryEntries(history)

        let log = MonitoringLog(
            timestamp: Date(),
            trigger: trigger,
            domainsChecked: results.count,
            changesFound: results.filter(\.didChange).count,
            alertsTriggered: alertsTriggered,
            checkedDomains: results.sorted {
                $0.domain.localizedCaseInsensitiveCompare($1.domain) == .orderedAscending
            },
            errors: errors
        )
        saveLog(log)

        return MonitoringRunOutcome(
            success: errors.count < results.count,
            message: log.summary,
            log: log
        )
    }

    private func saveLog(_ log: MonitoringLog) {
        var logs = MonitoringStorage.loadLogs()
        logs.insert(log, at: 0)
        MonitoringStorage.saveLogs(logs)
    }

    private func latestSnapshot(for trackedDomain: TrackedDomain, history: [HistoryEntry]) -> LookupSnapshot? {
        history.first(where: { entry in
            if let trackedDomainID = entry.trackedDomainID {
                return trackedDomainID == trackedDomain.id
            }
            return entry.domain.caseInsensitiveCompare(trackedDomain.domain) == .orderedSame
        })?.snapshot
    }

    private func persistSnapshot(
        _ snapshot: LookupSnapshot,
        trackedDomainID: UUID,
        trackedDomains: inout [TrackedDomain],
        history: inout [HistoryEntry]
    ) -> HistoryEntry? {
        let previousSnapshot = latestSnapshot(
            for: trackedDomains.first(where: { $0.id == trackedDomainID }) ?? TrackedDomain(domain: snapshot.domain),
            history: history
        )
        let analysis = DomainInsightEngine.analyze(snapshot: snapshot, previousSnapshot: previousSnapshot)
        let changeSummary = previousSnapshot.map {
            DomainDiffService.summary(
                from: $0,
                to: snapshot,
                generatedAt: snapshot.timestamp,
                riskAssessment: analysis.riskAssessment,
                insights: analysis.insights
            )
        }

        let entry = HistoryEntry(
            domain: snapshot.domain,
            timestamp: snapshot.timestamp,
            trackedDomainID: trackedDomainID,
            note: trackedDomains.first(where: { $0.id == trackedDomainID })?.note,
            dnsSections: snapshot.dnsSections,
            sslInfo: snapshot.sslInfo,
            httpHeaders: snapshot.httpHeaders,
            reachabilityResults: snapshot.reachabilityResults,
            ipGeolocation: snapshot.ipGeolocation,
            emailSecurity: snapshot.emailSecurity,
            mtaSts: snapshot.emailSecurity?.mtaSts,
            ownership: snapshot.ownership,
            ownershipHistory: snapshot.ownershipHistory,
            ptrRecord: snapshot.ptrRecord,
            redirectChain: snapshot.redirectChain,
            subdomains: snapshot.subdomains,
            extendedSubdomains: snapshot.extendedSubdomains,
            dnsHistory: snapshot.dnsHistory,
            domainPricing: snapshot.domainPricing,
            portScanResults: snapshot.portScanResults,
            hstsPreloaded: snapshot.hstsPreloaded,
            availabilityResult: snapshot.availabilityResult,
            suggestions: snapshot.suggestions,
            appVersion: snapshot.appVersion,
            resultSource: snapshot.resultSource,
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
            resolverDisplayName: snapshot.resolverDisplayName,
            resolverURLString: snapshot.resolverURLString,
            totalLookupDurationMs: snapshot.totalLookupDurationMs,
            primaryIP: Self.primaryIPAddress(from: snapshot),
            finalRedirectURL: snapshot.redirectChain.last?.url,
            tlsStatusSummary: Self.tlsSummary(from: snapshot),
            emailSecuritySummary: Self.emailSummary(from: snapshot),
            httpGradeSummary: snapshot.httpSecurityGrade ?? snapshot.httpHeadersError,
            changeSummary: changeSummary,
            sslError: snapshot.sslError,
            httpHeadersError: snapshot.httpHeadersError,
            reachabilityError: snapshot.reachabilityError,
            ipGeolocationError: snapshot.ipGeolocationError,
            emailSecurityError: snapshot.emailSecurityError,
            ownershipError: snapshot.ownershipError,
            ownershipHistoryError: snapshot.ownershipHistoryError,
            ptrError: snapshot.ptrError,
            redirectChainError: snapshot.redirectChainError,
            subdomainsError: snapshot.subdomainsError,
            extendedSubdomainsError: snapshot.extendedSubdomainsError,
            dnsHistoryError: snapshot.dnsHistoryError,
            domainPricingError: snapshot.domainPricingError,
            portScanError: snapshot.portScanError
        )

        history.insert(entry, at: 0)
        if history.count > maxHistoryEntries {
            history = Array(history.prefix(maxHistoryEntries))
        }

        if let index = trackedDomains.firstIndex(where: { $0.id == trackedDomainID }) {
            trackedDomains[index].lastSnapshotID = entry.id
            trackedDomains[index].lastKnownAvailability = snapshot.availabilityResult?.status
            trackedDomains[index].updatedAt = snapshot.timestamp
            trackedDomains[index].lastChangeSummary = changeSummary
            trackedDomains[index].lastChangeSeverity = changeSummary?.severity
            trackedDomains[index].certificateWarningLevel = DomainDiffService.certificateWarningLevel(for: snapshot)
            trackedDomains[index].certificateDaysRemaining = snapshot.sslInfo?.daysUntilExpiry
        }

        return entry
    }

    private func alertDescriptor(
        previousSnapshot: LookupSnapshot?,
        snapshot: LookupSnapshot,
        entry: HistoryEntry?
    ) -> (severity: MonitoringAlertSeverity, message: String)? {
        let changedLabels = Set(
            (previousSnapshot.map { DomainDiffService.diff(from: $0, to: snapshot) } ?? [])
                .flatMap(\.items)
                .filter(\.hasChanges)
                .map(\.label)
        )

        if changedLabels.contains("Availability") {
            return (.critical, "Availability changed")
        }
        if changedLabels.contains("Primary IP") {
            return (.critical, "Primary IP changed")
        }
        if changedLabels.contains("Redirect Target") {
            return (.critical, "Redirect target changed")
        }

        let ownershipLabels: Set<String> = [
            "Registrar",
            "Registration Date",
            "Expiration Date",
            "Ownership Status",
            "Abuse Contact"
        ]
        if !changedLabels.isDisjoint(with: ownershipLabels) {
            return (.warning, "Ownership changed")
        }
        if changedLabels.contains("Nameservers") || changedLabels.contains(where: { $0.hasSuffix("Records") }) {
            return (.warning, "DNS changed")
        }

        let oldCertificateLevel = previousSnapshot.map { DomainDiffService.certificateWarningLevel(for: $0) } ?? .none
        let newCertificateLevel = DomainDiffService.certificateWarningLevel(for: snapshot)
        if newCertificateLevel != .none, newCertificateLevel != oldCertificateLevel {
            let daysRemaining = snapshot.sslInfo?.daysUntilExpiry ?? 0
            return (.warning, "Certificate expires in \(daysRemaining) days")
        }

        if entry?.changeSummary?.hasChanges == true, let message = entry?.changeSummary?.message {
            return (.info, message)
        }

        return nil
    }

    private static func resolvedSnapshotAfterFallback(
        _ snapshot: LookupSnapshot,
        previousSnapshot: LookupSnapshot?
    ) -> LookupSnapshot {
        guard shouldFallbackToSnapshot(snapshot), let previousSnapshot else {
            return snapshot
        }

        return LookupSnapshot(
            historyEntryID: previousSnapshot.historyEntryID,
            domain: previousSnapshot.domain,
            timestamp: previousSnapshot.timestamp,
            trackedDomainID: previousSnapshot.trackedDomainID,
            note: previousSnapshot.note,
            appVersion: previousSnapshot.appVersion,
            resolverDisplayName: previousSnapshot.resolverDisplayName,
            resolverURLString: previousSnapshot.resolverURLString,
            dataSources: previousSnapshot.dataSources,
            provenanceBySection: previousSnapshot.provenanceBySection,
            availabilityConfidence: previousSnapshot.availabilityConfidence,
            ownershipConfidence: previousSnapshot.ownershipConfidence,
            subdomainConfidence: previousSnapshot.subdomainConfidence,
            emailSecurityConfidence: previousSnapshot.emailSecurityConfidence,
            geolocationConfidence: previousSnapshot.geolocationConfidence,
            errorDetails: previousSnapshot.errorDetails,
            isPartialSnapshot: previousSnapshot.isPartialSnapshot,
            validationIssues: previousSnapshot.validationIssues,
            totalLookupDurationMs: previousSnapshot.totalLookupDurationMs,
            snapshotIndex: previousSnapshot.snapshotIndex,
            previousSnapshotID: previousSnapshot.previousSnapshotID,
            changeCount: previousSnapshot.changeCount,
            severitySummary: previousSnapshot.severitySummary,
            dnsSections: previousSnapshot.dnsSections,
            dnsError: previousSnapshot.dnsError,
            availabilityResult: previousSnapshot.availabilityResult,
            suggestions: previousSnapshot.suggestions,
            sslInfo: previousSnapshot.sslInfo,
            sslError: previousSnapshot.sslError,
            hstsPreloaded: previousSnapshot.hstsPreloaded,
            httpHeaders: previousSnapshot.httpHeaders,
            httpSecurityGrade: previousSnapshot.httpSecurityGrade,
            httpStatusCode: previousSnapshot.httpStatusCode,
            httpResponseTimeMs: previousSnapshot.httpResponseTimeMs,
            httpProtocol: previousSnapshot.httpProtocol,
            http3Advertised: previousSnapshot.http3Advertised,
            httpHeadersError: previousSnapshot.httpHeadersError,
            reachabilityResults: previousSnapshot.reachabilityResults,
            reachabilityError: previousSnapshot.reachabilityError,
            ipGeolocation: previousSnapshot.ipGeolocation,
            ipGeolocationError: previousSnapshot.ipGeolocationError,
            emailSecurity: previousSnapshot.emailSecurity,
            emailSecurityError: previousSnapshot.emailSecurityError,
            ownership: previousSnapshot.ownership,
            ownershipError: previousSnapshot.ownershipError,
            ownershipHistory: previousSnapshot.ownershipHistory,
            ownershipHistoryError: previousSnapshot.ownershipHistoryError,
            ptrRecord: previousSnapshot.ptrRecord,
            ptrError: previousSnapshot.ptrError,
            redirectChain: previousSnapshot.redirectChain,
            redirectChainError: previousSnapshot.redirectChainError,
            subdomains: previousSnapshot.subdomains,
            subdomainsError: previousSnapshot.subdomainsError,
            extendedSubdomains: previousSnapshot.extendedSubdomains,
            extendedSubdomainsError: previousSnapshot.extendedSubdomainsError,
            dnsHistory: previousSnapshot.dnsHistory,
            dnsHistoryError: previousSnapshot.dnsHistoryError,
            domainPricing: previousSnapshot.domainPricing,
            domainPricingError: previousSnapshot.domainPricingError,
            portScanResults: previousSnapshot.portScanResults,
            portScanError: previousSnapshot.portScanError,
            changeSummary: previousSnapshot.changeSummary,
            resultSource: .snapshot,
            cachedSections: [],
            statusMessage: "Last known result • \(previousSnapshot.timestamp.formatted(date: .abbreviated, time: .shortened))"
        )
    }

    private static func shouldFallbackToSnapshot(_ snapshot: LookupSnapshot) -> Bool {
        let candidateMessages = [
            snapshot.dnsError,
            snapshot.httpHeadersError,
            snapshot.sslError,
            snapshot.ownershipError,
            snapshot.subdomainsError,
            snapshot.redirectChainError,
            snapshot.ipGeolocationError
        ]
        .compactMap { $0?.lowercased() }

        guard !candidateMessages.isEmpty else { return false }
        let connectivityFailure = candidateMessages.allSatisfy { message in
            message.hasPrefix("network error:")
                || message.hasPrefix("timeout:")
                || message.hasPrefix("rate limit:")
        }

        let hasMaterialData = !snapshot.dnsSections.isEmpty
            || !snapshot.httpHeaders.isEmpty
            || snapshot.sslInfo != nil
            || snapshot.ownership != nil
            || !snapshot.subdomains.isEmpty

        return connectivityFailure && !hasMaterialData
    }

    private static func primaryIPAddress(from snapshot: LookupSnapshot) -> String? {
        snapshot.dnsSections.first(where: { $0.recordType == .A })?.records.first?.value
    }

    private static func tlsSummary(from snapshot: LookupSnapshot) -> String? {
        guard let sslInfo = snapshot.sslInfo else { return snapshot.sslError }
        switch DomainDiffService.certificateWarningLevel(for: snapshot) {
        case .critical:
            return "Critical (\(sslInfo.daysUntilExpiry)d)"
        case .warning:
            return "Warning (\(sslInfo.daysUntilExpiry)d)"
        case .none:
            return "Healthy (\(sslInfo.daysUntilExpiry)d)"
        }
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
}
