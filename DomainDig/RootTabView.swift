import SwiftUI

struct RootTabView: View {
    @Bindable var viewModel: DomainViewModel
    @State private var purchaseService = PurchaseService.shared

    var body: some View {
        let _ = purchaseService.currentTier

        TabView {
            ContentView(viewModel: viewModel)
                .tabItem {
                    Label("Inspect", systemImage: "magnifyingglass")
                }

            NavigationStack {
                WatchlistView(viewModel: viewModel)
            }
            .tabItem {
                Label("Watchlist", systemImage: "eye")
            }

            NavigationStack {
                HistoryView(viewModel: viewModel)
            }
            .tabItem {
                Label("History", systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90")
            }

            NavigationStack {
                WorkflowsView(viewModel: viewModel)
            }
            .tabItem {
                Label("Workflows", systemImage: "square.stack.3d.down.right")
            }

            NavigationStack {
                SettingsView(viewModel: viewModel)
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
        }
        .sheet(isPresented: Binding(
            get: { viewModel.isPaywallPresented },
            set: { viewModel.isPaywallPresented = $0 }
        )) {
            PaywallView()
        }
        .alert(item: Binding(
            get: { viewModel.upgradePrompt },
            set: { viewModel.upgradePrompt = $0 }
        )) { prompt in
            Alert(
                title: Text(prompt.title),
                message: Text(prompt.message),
                primaryButton: .default(Text("Open Paywall")) {
                    viewModel.upgradePrompt = nil
                    viewModel.isPaywallPresented = true
                },
                secondaryButton: .cancel(Text("Continue")) {
                    viewModel.upgradePrompt = nil
                }
            )
        }
    }
}
