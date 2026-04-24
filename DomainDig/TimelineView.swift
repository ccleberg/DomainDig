import SwiftUI

struct TimelineView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    let domain: String

    @State private var presentedDiff: DomainDiff?
    @State private var focusedSectionID: String?

    private var timelineSections: [TimelineSection] {
        viewModel.timelineSections(for: domain)
    }

    var body: some View {
        List {
            ForEach(timelineSections) { section in
                Section(section.title) {
                    ForEach(section.entries) { summary in
                        if let entry = viewModel.historyEntry(withID: summary.historyEntryID) {
                            NavigationLink {
                                HistoryDetailView(viewModel: viewModel, entry: entry)
                            } label: {
                                TimelineRow(summary: summary)
                            }
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button {
                                    viewModel.toggleSnapshotSelection(entry)
                                } label: {
                                    Label(
                                        viewModel.selectedSnapshotIDs.contains(entry.id) ? "Selected" : "Compare",
                                        systemImage: viewModel.selectedSnapshotIDs.contains(entry.id) ? "checkmark.circle.fill" : "arrow.left.arrow.right"
                                    )
                                }

                                Button(role: .destructive) {
                                    viewModel.removeHistoryEntries(withIDs: [entry.id])
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle(domain)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Menu {
                    Picker("Grouping", selection: $viewModel.timelineGrouping) {
                        ForEach(TimelineGroupingOption.allCases) { option in
                            Text(option.title).tag(option)
                        }
                    }
                } label: {
                    Image(systemName: "line.3.horizontal.decrease.circle")
                }

                Button("Compare") {
                    presentedDiff = viewModel.generateDiffForSelectedSnapshots()
                    focusedSectionID = viewModel.currentDiffTargetSectionID
                }
                .disabled(viewModel.selectedSnapshots.count != 2)

                Menu("Export") {
                    Button("Export TXT") {
                        ExportPresenter.share(
                            filename: "\(domain)-timeline.txt",
                            contents: viewModel.exportTimelineText(domain: domain, includeDiffSummary: true)
                        )
                    }

                    Button("Export JSON") {
                        guard let data = viewModel.exportTimelineJSONData(domain: domain, includeDiffSummary: true) else { return }
                        ExportPresenter.share(filename: "\(domain)-timeline.json", data: data)
                    }
                }
            }
        }
        .sheet(item: $presentedDiff) { diff in
            NavigationStack {
                TimelineDiffView(viewModel: viewModel, diff: diff, focusedSectionID: $focusedSectionID)
            }
        }
    }
}

private struct TimelineRow: View {
    @Environment(\.appDensity) private var appDensity
    let summary: SnapshotSummary

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing + 1) {
            HStack(alignment: .center, spacing: 8) {
                Text(summary.timestamp.formatted(date: .abbreviated, time: .shortened))
                    .font(appDensity.font(.callout))
                    .foregroundStyle(.primary)
                Spacer()
                if let severity = summary.severitySummary {
                    AppStatusBadgeView(
                        model: .init(
                            title: severity.title,
                            systemImage: "arrow.triangle.2.circlepath",
                            foregroundColor: severity == .high ? .red : .yellow,
                            backgroundColor: (severity == .high ? Color.red : .yellow).opacity(0.16)
                        )
                    )
                }
            }

            Text(summary.changeSummaryMessage ?? "No change summary")
                .font(appDensity.font(.caption))
                .foregroundStyle(.secondary)
                .lineLimit(2)

            HStack(spacing: 8) {
                AppStatusBadgeView(model: AppStatusFactory.availability(summary.availability))
                if let primaryIP = summary.primaryIP {
                    AppStatusBadgeView(
                        model: .init(
                            title: primaryIP,
                            systemImage: "network",
                            foregroundColor: .blue,
                            backgroundColor: .blue.opacity(0.16)
                        )
                    )
                }
                if let tlsStatus = summary.tlsStatus {
                    AppStatusBadgeView(
                        model: .init(
                            title: tlsStatus.capitalized,
                            systemImage: "lock.shield",
                            foregroundColor: .green,
                            backgroundColor: .green.opacity(0.16)
                        )
                    )
                }
                if let riskScore = summary.riskScore {
                    AppStatusBadgeView(
                        model: .init(
                            title: "Risk \(riskScore)",
                            systemImage: "exclamationmark.shield",
                            foregroundColor: riskScore >= 70 ? .red : .orange,
                            backgroundColor: (riskScore >= 70 ? Color.red : .orange).opacity(0.16)
                        )
                    )
                }
            }

            HStack(spacing: 8) {
                if let snapshotIndex = summary.snapshotIndex {
                    Text("#\(snapshotIndex)")
                }
                Text(summary.timestamp.formatted(.relative(presentation: .named)))
                if summary.changeCount > 0 {
                    Text("\(summary.changeCount) changes")
                }
            }
            .font(appDensity.font(.caption2))
            .foregroundStyle(.secondary)
        }
    }
}

struct TimelineDiffView: View {
    @Bindable var viewModel: DomainViewModel
    let diff: DomainDiff
    @Binding var focusedSectionID: String?

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Button("Previous Change") {
                            viewModel.moveToPreviousDiffChange()
                            focusedSectionID = viewModel.currentDiffTargetSectionID
                            scroll(proxy: proxy)
                        }
                        .disabled(viewModel.activeDiffChangeIndex == 0)

                        Button("Next Change") {
                            viewModel.moveToNextDiffChange()
                            focusedSectionID = viewModel.currentDiffTargetSectionID
                            scroll(proxy: proxy)
                        }
                        .disabled(viewModel.activeDomainDiff?.changedSectionIDs.isEmpty != false || viewModel.currentDiffTargetSectionID == viewModel.activeDomainDiff?.changedSectionIDs.last)

                        Spacer()
                    }

                    DomainDiffView(
                        title: "Snapshot Diff",
                        sections: diff.sections,
                        contextNote: diff.contextNote,
                        showsUnchanged: false,
                        highlightedSectionID: focusedSectionID
                    )
                }
                .padding()
            }
            .background(Color.black)
            .navigationTitle("Compare Snapshots")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                scroll(proxy: proxy)
            }
            .onChange(of: focusedSectionID) { _, _ in
                scroll(proxy: proxy)
            }
        }
    }

    private func scroll(proxy: ScrollViewProxy) {
        guard let focusedSectionID else { return }
        withAnimation {
            proxy.scrollTo(focusedSectionID, anchor: .top)
        }
    }
}
