import SwiftUI

struct WatchlistView: View {
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            if viewModel.watchedDomains.isEmpty {
                Text("No watched domains")
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
            } else {
                ForEach(viewModel.watchedDomains) { watchedDomain in
                    Button {
                        viewModel.domain = watchedDomain.domain
                        dismiss()
                        viewModel.run()
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(watchedDomain.domain)
                                .font(.system(.callout, design: .monospaced))
                                .foregroundStyle(.primary)
                            Text(statusLabel(watchedDomain.lastKnownAvailability))
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(statusColor(watchedDomain.lastKnownAvailability))
                        }
                    }
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
                }
                .onDelete { offsets in
                    viewModel.removeWatchedDomains(at: offsets)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle("Watchlist")
        .toolbar {
            if !viewModel.watchedDomains.isEmpty {
                EditButton()
            }
        }
        .preferredColorScheme(.dark)
    }

    private func statusLabel(_ status: DomainAvailabilityStatus?) -> String {
        switch status {
        case .available:
            return "Available"
        case .registered:
            return "Registered"
        case .unknown, .none:
            return "Unknown"
        }
    }

    private func statusColor(_ status: DomainAvailabilityStatus?) -> Color {
        switch status {
        case .available:
            return .green
        case .registered:
            return .yellow
        case .unknown, .none:
            return .secondary
        }
    }
}
