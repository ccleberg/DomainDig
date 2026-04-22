import SwiftUI

struct RootTabView: View {
    @Bindable var viewModel: DomainViewModel

    var body: some View {
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
    }
}
