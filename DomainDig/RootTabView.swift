import SwiftUI

private enum RootTab: Hashable {
    case dashboard
    case history
    case inspect
    case audit
    case settings
}

struct RootTabView: View {
    @Bindable var viewModel: DomainViewModel
    @State private var purchaseService = PurchaseService.shared
    @State private var selectedTab: RootTab = FeatureAccessService.currentTier == .free ? .inspect : .dashboard

    var body: some View {
        let _ = purchaseService.currentTier

        TabView(selection: $selectedTab) {
            NavigationStack {
                DashboardView(viewModel: viewModel)
            }
            .tabItem {
                Label("Dashboard", systemImage: "square.grid.2x2")
            }
            .tag(RootTab.dashboard)

            NavigationStack {
                HistoryView(viewModel: viewModel)
            }
            .tabItem {
                Label("History", systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90")
            }
            .tag(RootTab.history)

            ContentView(viewModel: viewModel)
                .tabItem {
                    Label("Inspect", systemImage: "magnifyingglass")
                }
                .tag(RootTab.inspect)

            NavigationStack {
                AuditModeView(viewModel: viewModel)
            }
            .tabItem {
                Label("Audit", systemImage: "checklist")
            }
            .tag(RootTab.audit)

            NavigationStack {
                SettingsView(viewModel: viewModel)
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
            .tag(RootTab.settings)
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
        .onChange(of: purchaseService.currentTier) { _, newValue in
            if newValue != .free, selectedTab == .inspect, viewModel.trackedDomains.isEmpty == false {
                selectedTab = .dashboard
            }
        }
    }
}
