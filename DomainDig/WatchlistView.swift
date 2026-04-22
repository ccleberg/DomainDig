import SwiftUI

struct WatchlistView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var purchaseService = PurchaseService.shared
    @State private var showWorkflowAddSheet = false

    private var pinnedDomains: [TrackedDomain] {
        viewModel.filteredTrackedDomains.filter(\.isPinned)
    }

    private var otherDomains: [TrackedDomain] {
        viewModel.filteredTrackedDomains.filter { !$0.isPinned }
    }

    var body: some View {
        let _ = purchaseService.currentTier

        List {
            if viewModel.batchLookupSource == .watchlistRefresh, (!viewModel.batchResults.isEmpty || viewModel.batchLookupRunning) {
                Section("Refresh Progress") {
                    VStack(alignment: .leading, spacing: 8) {
                        ProgressView(value: Double(viewModel.batchCompletedCount), total: Double(max(viewModel.batchTotalCount, 1)))
                            .tint(.cyan)
                        HStack {
                            Text(viewModel.batchProgressLabel)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.secondary)
                            Spacer()
                            if viewModel.batchLookupRunning {
                                Button("Cancel") {
                                    viewModel.cancelBatchLookup()
                                }
                                .buttonStyle(.bordered)
                                .font(appDensity.font(.caption2))
                            }
                        }

                        ForEach(viewModel.batchResults.prefix(5)) { result in
                            BatchResultRowView(result: result)
                        }
                    }
                    .padding(.vertical, 4)
                }
                .listRowBackground(Color(.systemGray6).opacity(0.5))
            }

            if viewModel.filteredTrackedDomains.isEmpty {
                Section {
                    EmptyStateCardView(
                        title: "No Tracked Domains",
                        message: "Track important domains locally so you can refresh them quickly and see status changes at a glance.",
                        suggestion: "Run an inspection and use the Track action on a domain you care about.",
                        systemImage: "eye"
                    )
                }
                .listRowBackground(Color(.systemGray6).opacity(0.5))
            } else {
                if let limitMessage = FeatureAccessService.trackedDomainLimitMessage(currentCount: viewModel.trackedDomains.count) {
                    Section {
                        Text(limitMessage)
                            .font(appDensity.font(.caption))
                            .foregroundStyle(.secondary)
                    }
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
                }

                if !pinnedDomains.isEmpty {
                    trackedSection(title: "Pinned", domains: pinnedDomains)
                }

                if !otherDomains.isEmpty {
                    trackedSection(title: pinnedDomains.isEmpty ? "Tracked Domains" : "Others", domains: otherDomains)
                }
            }
        }
        .animation(.easeInOut(duration: 0.2), value: viewModel.filteredTrackedDomains.map(\.id))
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle("Watchlist")
        .searchable(text: $viewModel.watchlistSearchText, prompt: "Search tracked domains")
        .toolbar {
            if !viewModel.filteredTrackedDomains.isEmpty {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Menu {
                        Picker("Filter", selection: $viewModel.watchlistFilter) {
                            ForEach(WatchlistFilterOption.allCases) { option in
                                Text(option.title).tag(option)
                            }
                        }

                        Picker("Sort", selection: $viewModel.watchlistSortOption) {
                            ForEach(WatchlistSortOption.allCases) { option in
                                Text(option.title).tag(option)
                            }
                        }

                        Button(viewModel.batchLookupRunning ? "Check All Running" : "Check All") {
                            AppHaptics.refresh()
                            viewModel.refreshAllTrackedDomains()
                        }
                        .disabled(viewModel.batchLookupRunning)

                        Button("Add to Workflow") {
                            showWorkflowAddSheet = true
                        }

                        Button("Export TXT") {
                            shareTrackedDomains(format: .text)
                        }

                        if FeatureAccessService.hasAccess(to: .advancedExports) {
                            Button("Export CSV") {
                                shareTrackedDomains(format: .csv)
                            }

                            Button("Export JSON") {
                                shareTrackedDomains(format: .json)
                            }
                        } else {
                            Button("CSV Export • Available in Pro") {}
                                .disabled(true)
                            Button("JSON Export • Available in Pro") {}
                                .disabled(true)
                        }
                    } label: {
                        Image(systemName: "line.3.horizontal.decrease.circle")
                    }

                    EditButton()
                }
            }
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .sheet(item: batchSummaryBinding) { summary in
            BatchSweepSummaryView(viewModel: viewModel, summary: summary)
        }
        .sheet(isPresented: $showWorkflowAddSheet) {
            WorkflowBulkAddSheet(
                viewModel: viewModel,
                title: "Add Watchlist Domains",
                availableDomains: viewModel.filteredTrackedDomains.map(\.domain)
            )
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private func trackedSection(title: String, domains: [TrackedDomain]) -> some View {
        Section(title) {
            ForEach(domains) { trackedDomain in
                trackedDomainRow(trackedDomain)
            }
        }
    }

    private func trackedDomainRow(_ trackedDomain: TrackedDomain) -> some View {
        NavigationLink {
            TrackedDomainDetailView(viewModel: viewModel, trackedDomain: trackedDomain)
        } label: {
            WatchlistRowView(
                trackedDomain: trackedDomain,
                isRefreshing: viewModel.refreshingTrackedDomainID == trackedDomain.id
            )
        }
        .buttonStyle(.plain)
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            Button {
                AppHaptics.refresh()
                viewModel.refreshTrackedDomain(trackedDomain)
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .tint(.cyan)

            Button {
                viewModel.togglePinned(for: trackedDomain)
            } label: {
                Label(trackedDomain.isPinned ? "Unpin" : "Pin", systemImage: trackedDomain.isPinned ? "pin.slash" : "pin")
            }
            .tint(.yellow)
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button {
                AppHaptics.refresh()
                viewModel.refreshTrackedDomain(trackedDomain)
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .tint(.cyan)

            Button(role: .destructive) {
                viewModel.deleteTrackedDomain(trackedDomain)
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .contextMenu {
            Button {
                AppHaptics.refresh()
                viewModel.refreshTrackedDomain(trackedDomain)
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }

            Button {
                dismiss()
                viewModel.rerunInspection(for: trackedDomain)
            } label: {
                Label("Open Inspection", systemImage: "magnifyingglass")
            }

            Button {
                viewModel.togglePinned(for: trackedDomain)
            } label: {
                Label(trackedDomain.isPinned ? "Unpin" : "Pin", systemImage: trackedDomain.isPinned ? "pin.slash" : "pin")
            }

            Button(role: .destructive) {
                viewModel.deleteTrackedDomain(trackedDomain)
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .listRowBackground(Color(.systemGray6).opacity(0.5))
    }

    private var batchSummaryBinding: Binding<BatchSweepSummary?> {
        Binding(
            get: { viewModel.latestBatchSweepSummary },
            set: { viewModel.latestBatchSweepSummary = $0 }
        )
    }

    private func deleteFilteredTrackedDomains(at offsets: IndexSet) {
        let domains = offsets.map { viewModel.filteredTrackedDomains[$0] }
        domains.forEach(viewModel.deleteTrackedDomain)
    }

    private func shareTrackedDomains(format: DomainExportFormat) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = formatter.string(from: Date())
        let filename = "\(timestamp)_domaindig_watchlist.\(format.fileExtension)"
        let data: Data

        switch format {
        case .text:
            data = Data(viewModel.exportTrackedDomainsText(domains: viewModel.filteredTrackedDomains).utf8)
        case .csv:
            data = Data(viewModel.exportTrackedDomainsCSV(domains: viewModel.filteredTrackedDomains).utf8)
        case .json:
            data = viewModel.exportTrackedDomainsJSONData(domains: viewModel.filteredTrackedDomains) ?? Data("[]".utf8)
        }

        ExportPresenter.share(filename: filename, data: data)
    }
}

struct WatchlistRowView: View {
    @Environment(\.appDensity) private var appDensity
    let trackedDomain: TrackedDomain
    let isRefreshing: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing + 1) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                if trackedDomain.isPinned {
                    Image(systemName: "pin.fill")
                        .font(.caption2)
                        .foregroundStyle(.yellow)
                }
                Text(trackedDomain.domain)
                    .font(appDensity.font(.callout))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 8)
                statusBadge
            }

            Text("Updated \(trackedDomain.updatedAt.formatted(date: .abbreviated, time: .shortened))")
                .font(appDensity.font(.caption2))
                .foregroundStyle(.secondary)

            indicatorRow

            if let note = trackedDomain.note?.trimmingCharacters(in: .whitespacesAndNewlines), !note.isEmpty {
                Text(note)
                    .font(appDensity.font(.caption))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            } else if let summary = trackedDomain.lastChangeSummary {
                Text(summary.message)
                    .font(appDensity.font(.caption))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
    }

    private func availabilityLabel(_ status: DomainAvailabilityStatus?) -> String {
        switch status {
        case .available:
            return "Available"
        case .registered:
            return "Registered"
        case .unknown, .none:
            return "Unknown"
        }
    }

    @ViewBuilder
    private var statusBadge: some View {
        if isRefreshing {
            AppStatusBadgeView(model: .init(title: "Refreshing", systemImage: "arrow.clockwise", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.6)))
        } else {
            AppStatusBadgeView(model: AppStatusFactory.availability(trackedDomain.lastKnownAvailability))
        }
    }

    @ViewBuilder
    private var indicatorRow: some View {
        HStack(spacing: 8) {
            AppStatusBadgeView(model: AppStatusFactory.change(trackedDomain.lastChangeSummary))

            if trackedDomain.certificateWarningLevel != .none {
                AppStatusBadgeView(model: certificateBadge)
            }
        }
    }

    private var certificateBadge: AppStatusBadgeModel {
        let days = trackedDomain.certificateDaysRemaining.map { "\($0)d" } ?? "Soon"
        switch trackedDomain.certificateWarningLevel {
        case .critical:
            return .init(title: "Invalid \(days)", systemImage: "xmark.octagon.fill", foregroundColor: .red, backgroundColor: .red.opacity(0.16))
        case .warning:
            return .init(title: "Expiring \(days)", systemImage: "exclamationmark.triangle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        case .none:
            return .init(title: "Valid", systemImage: "lock.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        }
    }
}

struct TrackedDomainDetailView: View {
    @Bindable var viewModel: DomainViewModel
    let trackedDomain: TrackedDomain
    @Environment(\.dismiss) private var dismiss

    @State private var noteDraft = ""
    @State private var isEditingNote = false
    @State private var showRerunOptions = false

    private var liveTrackedDomain: TrackedDomain {
        viewModel.trackedDomains.first(where: { $0.id == trackedDomain.id }) ?? trackedDomain
    }

    private var latestSnapshots: [HistoryEntry] {
        viewModel.recentSnapshots(for: liveTrackedDomain)
    }

    private var latestDiffSections: [DomainDiffSection] {
        viewModel.diffSectionsForLatestSnapshots(of: liveTrackedDomain)
    }

    var body: some View {
        List {
            Section {
                WatchlistRowView(
                    trackedDomain: liveTrackedDomain,
                    isRefreshing: viewModel.refreshingTrackedDomainID == liveTrackedDomain.id
                )
            }
            .listRowBackground(Color(.systemGray6).opacity(0.5))

            Section {
                Button {
                    viewModel.refreshTrackedDomain(liveTrackedDomain)
                } label: {
                    Label("Manual Refresh", systemImage: "arrow.clockwise")
                }

                Button {
                    showRerunOptions = true
                } label: {
                    Label("Re-run Inspection", systemImage: "magnifyingglass")
                }

                Button {
                    viewModel.togglePinned(for: liveTrackedDomain)
                } label: {
                    Label(liveTrackedDomain.isPinned ? "Unpin Domain" : "Pin Domain", systemImage: liveTrackedDomain.isPinned ? "pin.slash" : "pin")
                }

                Button {
                    noteDraft = liveTrackedDomain.note ?? ""
                    isEditingNote = true
                } label: {
                    Label(liveTrackedDomain.note == nil ? "Add Note" : "Edit Note", systemImage: "note.text")
                }
            }
            .listRowBackground(Color(.systemGray6).opacity(0.5))

            if let summary = viewModel.latestChangeSummary(for: liveTrackedDomain) {
                Section("Latest Change Summary") {
                    DomainChangeSummaryView(summary: summary)
                }
                .listRowBackground(Color.clear)
            }

            if !latestDiffSections.isEmpty {
                Section("Latest Diff") {
                    DomainDiffView(
                        title: "Latest Snapshot vs Previous",
                        sections: latestDiffSections,
                        contextNote: latestSnapshots.count >= 2
                            ? DomainDiffService.comparisonContextNote(from: latestSnapshots[1].snapshot, to: latestSnapshots[0].snapshot)
                            : nil,
                        showsUnchanged: false
                    )
                }
                .listRowBackground(Color.clear)
            }

            Section("Recent Snapshots") {
                if latestSnapshots.isEmpty {
                    Text("No snapshots yet")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(latestSnapshots) { entry in
                        NavigationLink {
                            HistoryDetailView(viewModel: viewModel, entry: entry)
                        } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(entry.timestamp.formatted(date: .abbreviated, time: .shortened))
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.primary)
                                Text(entry.changeSummary?.hasChanges == true ? "Changed" : "Snapshot")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .listRowBackground(Color(.systemGray6).opacity(0.5))
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle(liveTrackedDomain.domain)
        .preferredColorScheme(.dark)
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .confirmationDialog("Re-run inspection", isPresented: $showRerunOptions) {
            Button("Run with Current Settings") {
                viewModel.rerunInspection(for: liveTrackedDomain, useSnapshotResolver: false)
            }
            if latestSnapshots.first != nil {
                Button("Run with Snapshot Resolver") {
                    viewModel.rerunInspection(for: liveTrackedDomain, useSnapshotResolver: true)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(viewModel.resolverMismatchNote(for: liveTrackedDomain) ?? "Choose how to reproduce the most recent snapshot.")
        }
        .sheet(isPresented: $isEditingNote) {
            NavigationStack {
                Form {
                    Section("Tracking Note") {
                        TextField("Optional note", text: $noteDraft, axis: .vertical)
                            .lineLimit(3...6)
                    }
                }
                .navigationTitle("Edit Note")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            isEditingNote = false
                        }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            viewModel.updateNote(noteDraft, for: liveTrackedDomain)
                            isEditingNote = false
                        }
                    }
                }
            }
        }
    }
}
