import SwiftUI

struct BatchResultsView: View {
    @Bindable var viewModel: DomainViewModel
    let title: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                SectionTitleView(title: title)
                Spacer()
                if viewModel.batchLookupRunning {
                    VStack(alignment: .trailing, spacing: 4) {
                        ProgressView(value: Double(viewModel.batchCompletedCount), total: Double(max(viewModel.batchTotalCount, 1)))
                            .tint(.cyan)
                            .frame(width: 120)
                        Text(viewModel.batchProgressLabel)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                } else if !viewModel.batchResults.isEmpty {
                    Text("\(viewModel.batchResults.count) domains")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }

            if viewModel.batchResults.isEmpty {
                MessageCardView(text: "No batch results yet", isError: false)
            } else {
                CardView(allowsHorizontalScroll: false) {
                    ForEach(viewModel.batchResults) { result in
                        if let entry = viewModel.historyEntry(for: result) {
                            NavigationLink {
                                HistoryDetailView(viewModel: viewModel, entry: entry)
                            } label: {
                                BatchResultRowView(result: result)
                            }
                            .buttonStyle(.plain)
                        } else {
                            BatchResultRowView(result: result)
                        }
                    }
                }
            }
        }
    }
}

struct BatchResultRowView: View {
    let result: BatchLookupResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(result.domain)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                Text(result.quickStatus)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(quickStatusColor)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(quickStatusColor.opacity(0.16))
                    .clipShape(Capsule())
            }

            HStack(spacing: 10) {
                Text(availabilityText)
                Text(result.primaryIP ?? "No IP")
                Text(result.timestamp.formatted(date: .abbreviated, time: .shortened))
            }
            .font(.system(.caption2, design: .monospaced))
            .foregroundStyle(.secondary)

            if let summaryMessage = result.summaryMessage {
                Text(summaryMessage)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            if let errorMessage = result.errorMessage {
                Text(errorMessage)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }

    private var availabilityText: String {
        switch result.availability {
        case .available:
            return "Available"
        case .registered:
            return "Registered"
        case .unknown, .none:
            return "Unknown"
        }
    }

    private var quickStatusColor: Color {
        switch result.status {
        case .pending:
            return .secondary
        case .running:
            return .cyan
        case .completed:
            if result.changeSeverity == .high || result.certificateWarningLevel == .critical {
                return .red
            }
            if result.changeSeverity == .medium || result.certificateWarningLevel == .warning {
                return .yellow
            }
            if result.quickStatus == "Changed" {
                return .blue
            }
            return .green
        case .failed:
            return .red
        }
    }
}
