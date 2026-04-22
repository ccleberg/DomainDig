import SwiftUI

struct BatchSweepSummaryView: View {
    @Bindable var viewModel: DomainViewModel
    let summary: BatchSweepSummary

    @State private var showUnchangedDomains = false

    private var visibleResults: [BatchLookupResult] {
        if showUnchangedDomains {
            return summary.results
        }

        return summary.results.filter {
            ($0.changeSeverity ?? .low) >= .medium || $0.certificateWarningLevel != .none || $0.status == .failed
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section("Overview") {
                    statRow(label: "Checked", value: "\(summary.totalDomains)")
                    statRow(label: "Changed", value: "\(summary.changedDomains)")
                    statRow(label: "Warnings", value: "\(summary.warningDomains)")
                    statRow(label: "Unchanged", value: "\(summary.unchangedDomains)")
                }

                Section {
                    Toggle("Show unchanged domains", isOn: $showUnchangedDomains)
                }

                Section(visibleResults.isEmpty ? "Changed Domains" : "Results") {
                    if visibleResults.isEmpty {
                        Text("No domains with changes or warnings")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(visibleResults) { result in
                            if let entry = viewModel.historyEntry(for: result) {
                                NavigationLink {
                                    HistoryDetailView(viewModel: viewModel, entry: entry)
                                } label: {
                                    BatchResultRowView(result: result)
                                }
                            } else {
                                BatchResultRowView(result: result)
                            }
                        }
                    }
                }
            }
            .navigationTitle(summary.source == .watchlistRefresh ? "Sweep Summary" : "Batch Summary")
        }
    }

    private func statRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(.primary)
        }
    }
}
