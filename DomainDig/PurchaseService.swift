import Foundation
import StoreKit

#if canImport(UIKit)
import UIKit
#endif

@MainActor
@Observable
final class PurchaseService {
    struct CachedEntitlement: Codable {
        let tier: FeatureTier
        let activeProductID: String?
        let updatedAt: Date
    }

    static let shared = PurchaseService()
    static let monthlyProductID = "domaindig.pro.monthly"
    static let yearlyProductID = "domaindig.pro.yearly"
    static let productIDs = [monthlyProductID, yearlyProductID]

    private static let entitlementCacheKey = "purchase.cachedEntitlement"

    static var cachedEntitlement: CachedEntitlement? {
        guard let data = UserDefaults.standard.data(forKey: entitlementCacheKey) else { return nil }
        return try? JSONDecoder().decode(CachedEntitlement.self, from: data)
    }

    static var cachedTier: FeatureTier {
        cachedEntitlement?.tier ?? .free
    }

    var products: [Product] = []
    var currentTier: FeatureTier
    var activeProductID: String?
    var isLoadingProducts = false
    var isPurchasing = false
    var isRestoring = false
    var statusMessage: String?
    var errorMessage: String?

    private var updatesTask: Task<Void, Never>?

    private init() {
        currentTier = Self.cachedTier
        activeProductID = Self.cachedEntitlement?.activeProductID
        updatesTask = observeTransactionUpdates()
        Task {
            await refreshProducts()
            await refreshEntitlements()
        }
    }

    var hasProAccess: Bool {
        currentTier == .pro
    }

    func refreshProducts() async {
        isLoadingProducts = true
        errorMessage = nil

        do {
            let fetchedProducts = try await Product.products(for: Self.productIDs)
            products = fetchedProducts.sorted { lhs, rhs in
                productSortIndex(for: lhs.id) < productSortIndex(for: rhs.id)
            }
        } catch {
            products = []
            errorMessage = storeMessage(for: error, fallback: "Pricing is unavailable right now.")
        }

        isLoadingProducts = false
    }

    func refreshEntitlements() async {
        var activeTransactions: [Transaction] = []

        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result else {
                continue
            }
            guard Self.productIDs.contains(transaction.productID), transaction.revocationDate == nil else {
                continue
            }
            activeTransactions.append(transaction)
        }

        let activeProductID = activeTransactions
            .sorted { $0.purchaseDate > $1.purchaseDate }
            .first?
            .productID

        self.activeProductID = activeProductID
        currentTier = activeProductID == nil ? .free : .pro
        persistCurrentEntitlement()
    }

    func purchase(_ product: Product) async {
        isPurchasing = true
        statusMessage = nil
        errorMessage = nil

        do {
            let result = try await product.purchase()

            switch result {
            case .success(let verification):
                let transaction = try verifiedTransaction(from: verification)
                apply(transaction: transaction)
                await transaction.finish()
                await refreshEntitlements()
                statusMessage = "Pro is active."
            case .userCancelled:
                break
            case .pending:
                statusMessage = "Purchase is pending approval."
            @unknown default:
                errorMessage = "The purchase could not be completed."
            }
        } catch {
            errorMessage = storeMessage(for: error, fallback: "The purchase could not be completed.")
        }

        isPurchasing = false
    }

    func restorePurchases() async {
        isRestoring = true
        statusMessage = nil
        errorMessage = nil

        do {
            try await AppStore.sync()
            await refreshEntitlements()
            statusMessage = hasProAccess ? "Purchases restored." : "No previous Pro purchase was found."
        } catch {
            errorMessage = storeMessage(for: error, fallback: "Restore failed. Try again when the App Store is available.")
        }

        isRestoring = false
    }

    func manageSubscription() async {
        errorMessage = nil

        #if canImport(UIKit)
        if ProcessInfo.processInfo.isiOSAppOnMac {
            errorMessage = "Manage Subscription is not available on this device."
            return
        }

        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first(where: { $0.activationState == .foregroundActive }) else {
            errorMessage = "Manage Subscription is not available right now."
            return
        }

        do {
            try await AppStore.showManageSubscriptions(in: scene)
        } catch {
            errorMessage = storeMessage(for: error, fallback: "Manage Subscription is not available right now.")
        }
        #else
        errorMessage = "Manage Subscription is not available on this platform."
        #endif
    }

    func clearMessages() {
        statusMessage = nil
        errorMessage = nil
    }

    private func apply(transaction: Transaction) {
        guard Self.productIDs.contains(transaction.productID), transaction.revocationDate == nil else {
            return
        }

        activeProductID = transaction.productID
        currentTier = .pro
        persistCurrentEntitlement()
    }

    private func observeTransactionUpdates() -> Task<Void, Never> {
        Task.detached(priority: .background) { [weak self] in
            for await result in Transaction.updates {
                guard let self else { return }
                await self.handleTransactionUpdate(result)
            }
        }
    }

    private func handleTransactionUpdate(_ result: VerificationResult<Transaction>) async {
        guard case .verified(let transaction) = result else { return }
        apply(transaction: transaction)
        await transaction.finish()
        await refreshEntitlements()
    }

    private func persistCurrentEntitlement() {
        let cachedEntitlement = CachedEntitlement(
            tier: currentTier,
            activeProductID: activeProductID,
            updatedAt: Date()
        )

        if let data = try? JSONEncoder().encode(cachedEntitlement) {
            UserDefaults.standard.set(data, forKey: Self.entitlementCacheKey)
        }
    }

    private func verifiedTransaction(from result: VerificationResult<Transaction>) throws -> Transaction {
        switch result {
        case .verified(let transaction):
            return transaction
        case .unverified:
            throw StoreKitError.notEntitled
        }
    }

    private func productSortIndex(for productID: String) -> Int {
        switch productID {
        case Self.monthlyProductID:
            return 0
        case Self.yearlyProductID:
            return 1
        default:
            return Int.max
        }
    }

    private func storeMessage(for error: Error, fallback: String) -> String {
        if let storeKitError = error as? StoreKitError {
            switch storeKitError {
            case .networkError:
                return "The App Store is offline right now."
            default:
                return fallback
            }
        }

        let message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        return message.isEmpty ? fallback : message
    }
}
