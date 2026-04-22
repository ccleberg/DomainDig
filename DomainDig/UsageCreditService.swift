import Foundation

actor UsageCreditService {
    static let shared = UsageCreditService()

    private struct CreditLedger: Codable {
        let appVersion: String
        var remainingByFeature: [UsageCreditFeature: Int]
    }

    private let storageKey = "usageCredits.ledger"
    private var ledger: CreditLedger

    init(defaults: UserDefaults = .standard) {
        if let data = defaults.data(forKey: storageKey),
           let decoded = try? JSONDecoder().decode(CreditLedger.self, from: data),
           decoded.appVersion == AppVersion.current {
            ledger = decoded
        } else {
            ledger = Self.makeLedger()
            if let data = try? JSONEncoder().encode(ledger) {
                defaults.set(data, forKey: storageKey)
            }
        }
    }

    func status(for feature: UsageCreditFeature) -> UsageCreditStatus {
        let total = feature.defaultAllowance
        let remaining = ledger.remainingByFeature[feature] ?? total
        return UsageCreditStatus(
            feature: feature,
            remaining: remaining,
            total: total,
            resetContext: "Resets with app version \(ledger.appVersion)"
        )
    }

    func allStatuses() -> [UsageCreditStatus] {
        UsageCreditFeature.allCases.map { status(for: $0) }
    }

    func canUse(_ feature: UsageCreditFeature) -> Bool {
        status(for: feature).remaining > 0
    }

    @discardableResult
    func consume(_ feature: UsageCreditFeature) -> UsageCreditStatus {
        let current = ledger.remainingByFeature[feature] ?? feature.defaultAllowance
        ledger.remainingByFeature[feature] = max(0, current - 1)
        persist()
        return status(for: feature)
    }

    func resetForCurrentVersion() {
        ledger = Self.makeLedger()
        persist()
    }

    private static func makeLedger() -> CreditLedger {
        CreditLedger(
            appVersion: AppVersion.current,
            remainingByFeature: Dictionary(
                uniqueKeysWithValues: UsageCreditFeature.allCases.map { ($0, $0.defaultAllowance) }
            )
        )
    }

    private func persist(defaults: UserDefaults = .standard) {
        if let data = try? JSONEncoder().encode(ledger) {
            defaults.set(data, forKey: storageKey)
        }
    }
}
