import Foundation
import UserNotifications

@MainActor
final class LocalNotificationService {
    static let shared = LocalNotificationService()

    private init() {}

    func configureForegroundPresentation() {
        UNUserNotificationCenter.current().delegate = NotificationCenterDelegate.shared
    }

    func requestAuthorizationIfNeeded() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()

        switch settings.authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            return true
        case .notDetermined:
            return (try? await center.requestAuthorization(options: [.alert, .badge, .sound])) ?? false
        case .denied:
            return false
        @unknown default:
            return false
        }
    }

    func notifyDomainEvent(domain: String, message: String, severity: ChangeSeverity) async {
        await schedule(
            identifier: "domain-change-\(domain)",
            title: domain,
            body: message,
            interruptionLevel: severity == .high ? .timeSensitive : .active
        )
    }

    func notifyCertificateWarning(domain: String, daysRemaining: Int) async {
        await schedule(
            identifier: "cert-warning-\(domain)",
            title: domain,
            body: "Certificate expires in \(daysRemaining) days",
            interruptionLevel: .timeSensitive
        )
    }

    func notifySweepComplete(summary: BatchSweepSummary) async {
        let body = "\(summary.changedDomains) changed, \(summary.warningDomains) warnings, \(summary.unchangedDomains) unchanged"
        await schedule(
            identifier: "sweep-complete",
            title: summary.source == .watchlistRefresh ? "Check All Complete" : "Batch Complete",
            body: body,
            interruptionLevel: .active
        )
    }

    private func schedule(
        identifier: String,
        title: String,
        body: String,
        interruptionLevel: UNNotificationInterruptionLevel
    ) async {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.interruptionLevel = interruptionLevel

        let request = UNNotificationRequest(
            identifier: identifier,
            content: content,
            trigger: UNTimeIntervalNotificationTrigger(timeInterval: 0.1, repeats: false)
        )

        try? await UNUserNotificationCenter.current().add(request)
    }
}

private final class NotificationCenterDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationCenterDelegate()

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }
}
