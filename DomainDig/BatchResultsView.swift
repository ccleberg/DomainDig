import SwiftUI

struct BatchResultsView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    let title: String

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            HStack(alignment: .top) {
                SectionTitleView(title: title)
                Spacer()
                if viewModel.batchLookupRunning {
                    VStack(alignment: .trailing, spacing: 4) {
                        ProgressView(value: Double(viewModel.batchCompletedCount), total: Double(max(viewModel.batchTotalCount, 1)))
                            .tint(.cyan)
                            .frame(width: 120)
                        Text(viewModel.batchProgressLabel)
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                    }
                } else if !viewModel.batchResults.isEmpty {
                    Text("\(viewModel.batchResults.count) domains")
                        .font(appDensity.font(.caption2))
                        .foregroundStyle(.secondary)
                }
            }

            if viewModel.batchResults.isEmpty {
                EmptyStateCardView(
                    title: "No Batch Results Yet",
                    message: "Batch runs collect availability, IP, and change status for multiple domains in one pass.",
                    suggestion: "Switch to Bulk mode, paste a list of domains, then run a batch lookup.",
                    systemImage: "square.stack.3d.up"
                )
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
    @Environment(\.appDensity) private var appDensity
    let result: BatchLookupResult

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing + 1) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(result.domain)
                    .font(appDensity.font(.callout))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 8)
                Text(result.resultSource.label.lowercased())
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
                AppStatusBadgeView(model: quickStatusBadge)
            }

            HStack(spacing: 10) {
                AppStatusBadgeView(model: availabilityBadgeModel)
                if let riskScore = result.riskScore, let riskLevel = result.riskLevel {
                    Text("Risk \(riskScore) \(riskLevel.title)")
                        .lineLimit(1)
                        .minimumScaleFactor(0.85)
                }
            }
            .font(appDensity.font(.caption2))
            .foregroundStyle(.secondary)

            HStack(spacing: 10) {
                Text(result.primaryIP ?? "No IP")
                    .lineLimit(1)
                    .truncationMode(.middle)

                Spacer(minLength: 8)

                Text(result.timestamp.formatted(date: .abbreviated, time: .shortened))
                    .lineLimit(1)
            }
            .font(appDensity.font(.caption2))
            .foregroundStyle(.secondary)

            if let summaryMessage = result.summaryMessage {
                Text(summaryMessage)
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
            }

            if let changeClassification = result.changeClassification {
                Text("Impact: \(changeClassification.title)")
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(changeClassification == .critical ? .red : (changeClassification == .warning ? .yellow : .secondary))
            }

            if let errorMessage = result.errorMessage {
                Text(errorMessage)
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(result.status == .failed ? .red : .secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
        .frame(minHeight: appDensity.metrics.rowMinHeight + 12, alignment: .topLeading)
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

    private var availabilityBadgeModel: AppStatusBadgeModel {
        guard result.status == .failed else {
            return AppStatusFactory.availability(result.availability)
        }

        return .init(
            title: availabilityText,
            systemImage: "exclamationmark.circle",
            foregroundColor: .secondary,
            backgroundColor: Color(.systemGray5).opacity(0.55)
        )
    }

    private var quickStatusBadge: AppStatusBadgeModel {
        switch result.status {
        case .pending:
            return .init(title: "Pending", systemImage: "clock", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        case .running:
            return .init(title: "Running", systemImage: "arrow.clockwise", foregroundColor: .cyan, backgroundColor: .cyan.opacity(0.16))
        case .completed:
            if result.changeClassification == .critical || result.certificateWarningLevel == .critical || result.riskLevel == .high {
                return .init(title: "Critical", systemImage: "exclamationmark.octagon.fill", foregroundColor: .red, backgroundColor: .red.opacity(0.16))
            }
            if result.changeClassification == .warning || result.changeSeverity == .medium || result.certificateWarningLevel == .warning {
                return .init(title: "Warning", systemImage: "exclamationmark.triangle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
            }
            if result.quickStatus == "Changed" {
                return .init(title: "Changed", systemImage: "arrow.triangle.2.circlepath", foregroundColor: .cyan, backgroundColor: .cyan.opacity(0.16))
            }
            return .init(title: "Stable", systemImage: "checkmark.circle.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        case .failed:
            return .init(title: "Failed", systemImage: "xmark.circle.fill", foregroundColor: .red, backgroundColor: .red.opacity(0.16))
        }
    }
}
