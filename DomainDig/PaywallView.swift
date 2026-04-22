import StoreKit
import SwiftUI

struct PaywallView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.appDensity) private var appDensity
    @State private var purchaseService = PurchaseService.shared

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Pro unlocks workflows, scale, and exports. Data+ adds deeper external intelligence with local-first usage credits and no account requirement.")
                        .font(appDensity.font(.body, design: .default))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Section("What Pro Unlocks") {
                    featureRow("Unlimited tracked domains")
                    featureRow("Workflows")
                    featureRow("Larger batch sizes")
                    featureRow("Advanced exports")
                }

                Section("What Data+ Unlocks") {
                    featureRow("Ownership history")
                    featureRow("DNS history")
                    featureRow("Extended subdomains")
                    featureRow("External pricing signals")
                }

                Section("Subscription") {
                    if purchaseService.isLoadingProducts {
                        ProgressView("Loading pricing…")
                    } else if purchaseService.products.isEmpty {
                        Text("Pricing is unavailable right now.")
                            .font(appDensity.font(.caption, design: .default))
                            .foregroundStyle(.secondary)

                        Button("Retry") {
                            Task {
                                await purchaseService.refreshProducts()
                            }
                        }
                    } else {
                        ForEach(purchaseService.products, id: \.id) { product in
                            Button {
                                Task {
                                    await purchaseService.purchase(product)
                                }
                            } label: {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(subscriptionTitle(for: product))
                                        .font(appDensity.font(.headline, design: .default, weight: .semibold))
                                        .foregroundStyle(.primary)
                                    Text(product.displayPrice)
                                        .font(appDensity.font(.callout, design: .default))
                                        .foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .disabled(purchaseService.isPurchasing || purchaseService.isRestoring)
                        }
                    }

                    if let statusMessage = purchaseService.statusMessage {
                        Text(statusMessage)
                            .font(appDensity.font(.caption, design: .default))
                            .foregroundStyle(.secondary)
                    }

                    if let errorMessage = purchaseService.errorMessage {
                        Text(errorMessage)
                            .font(appDensity.font(.caption, design: .default))
                            .foregroundStyle(.red)
                    }
                }

                Section("Account") {
                    Button(purchaseService.isRestoring ? "Restoring…" : "Restore Purchases") {
                        Task {
                            await purchaseService.restorePurchases()
                        }
                    }
                    .disabled(purchaseService.isPurchasing || purchaseService.isRestoring)

                    if purchaseService.hasProAccess {
                        Button("Manage Subscription") {
                            Task {
                                await purchaseService.manageSubscription()
                            }
                        }
                    }
                }
            }
            .navigationTitle("DomainDig Pro")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .task {
            await purchaseService.refreshProducts()
            await purchaseService.refreshEntitlements()
        }
        .onDisappear {
            purchaseService.clearMessages()
        }
    }

    private func featureRow(_ title: String) -> some View {
        Text(title)
            .font(appDensity.font(.body, design: .default))
    }

    private func subscriptionTitle(for product: Product) -> String {
        switch product.id {
        case PurchaseService.monthlyProductID:
            return "Pro Monthly"
        case PurchaseService.yearlyProductID:
            return "Pro Yearly"
        case PurchaseService.dataPlusMonthlyProductID:
            return "Data+ Monthly"
        case PurchaseService.dataPlusYearlyProductID:
            return "Data+ Yearly"
        default:
            return product.displayName
        }
    }
}
