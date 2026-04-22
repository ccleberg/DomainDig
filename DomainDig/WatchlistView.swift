import SwiftUI

struct WatchlistView: View {
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            if viewModel.batchLookupSource == .watchlistRefresh, (!viewModel.batchResults.isEmpty || viewModel.batchLookupRunning) {
                Section("Refresh Progress") {
                    VStack(alignment: .leading, spacing: 8) {
                        ProgressView(value: Double(viewModel.batchCompletedCount), total: Double(max(viewModel.batchTotalCount, 1)))
                            .tint(.cyan)
                        HStack {
                            Text(viewModel.batchProgressLabel)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                            Spacer()
                            if viewModel.batchLookupRunning {
                                Button("Cancel") {
                                    viewModel.cancelBatchLookup()
                                }
                                .buttonStyle(.bordered)
                                .font(.system(.caption2, design: .monospaced))
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
                    VStack(alignment: .leading, spacing: 8) {
                        Text("No tracked domains yet")
                            .font(.system(.callout, design: .monospaced))
                            .foregroundStyle(.primary)
                        Text("Tracked domains appear here. Tracking is local and manual for now.")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 8)
                }
                .listRowBackground(Color(.systemGray6).opacity(0.5))
            } else {
                if let limitMessage = PremiumAccessService.trackedDomainLimitMessage(currentCount: viewModel.trackedDomains.count) {
                    Section {
                        Text(limitMessage)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
                }

                Section {
                    ForEach(viewModel.filteredTrackedDomains) { trackedDomain in
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
                                viewModel.togglePinned(for: trackedDomain)
                            } label: {
                                Label(trackedDomain.isPinned ? "Unpin" : "Pin", systemImage: trackedDomain.isPinned ? "pin.slash" : "pin")
                            }
                            .tint(.yellow)
                        }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                viewModel.deleteTrackedDomain(trackedDomain)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                        .contextMenu {
                            Button {
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
                    .onDelete(perform: deleteFilteredTrackedDomains)
                } header: {
                    Text("Tracked Domains")
                }
            }
        }
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
                            viewModel.refreshAllTrackedDomains()
                        }
                        .disabled(viewModel.batchLookupRunning)

                        Button("Export TXT") {
                            shareTrackedDomains(asCSV: false)
                        }

                        Button("Export CSV") {
                            shareTrackedDomains(asCSV: true)
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
        .preferredColorScheme(.dark)
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

    private func shareTrackedDomains(asCSV: Bool) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = formatter.string(from: Date())
        let fileExtension = asCSV ? "csv" : "txt"
        let filename = "\(timestamp)_domaindig_watchlist.\(fileExtension)"
        let contents = asCSV
            ? viewModel.exportTrackedDomainsCSV(domains: viewModel.filteredTrackedDomains)
            : viewModel.exportTrackedDomainsText(domains: viewModel.filteredTrackedDomains)
        ExportPresenter.share(filename: filename, contents: contents)
    }
}

struct WatchlistRowView: View {
    let trackedDomain: TrackedDomain
    let isRefreshing: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                if trackedDomain.isPinned {
                    Image(systemName: "pin.fill")
                        .font(.caption2)
                        .foregroundStyle(.yellow)
                }
                Text(trackedDomain.domain)
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 8)
                statusBadge
            }

            Text("Updated \(trackedDomain.updatedAt.formatted(date: .abbreviated, time: .shortened))")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)

            indicatorRow

            if let note = trackedDomain.note?.trimmingCharacters(in: .whitespacesAndNewlines), !note.isEmpty {
                Text(note)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            } else if let summary = trackedDomain.lastChangeSummary {
                Text(summary.message)
                    .font(.system(.caption, design: .monospaced))
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
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.small)
                Text("Refreshing")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(Color(.systemGray5).opacity(0.6))
            .clipShape(Capsule())
        } else {
            Text(availabilityLabel(trackedDomain.lastKnownAvailability))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(badgeColor)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(badgeBackground)
                .clipShape(Capsule())
        }
    }

    private var badgeColor: Color {
        switch trackedDomain.lastKnownAvailability {
        case .available:
            return .green
        case .registered:
            return .yellow
        case .unknown, .none:
            return .secondary
        }
    }

    private var badgeBackground: Color {
        switch trackedDomain.lastKnownAvailability {
        case .available:
            return .green.opacity(0.16)
        case .registered:
            return .yellow.opacity(0.16)
        case .unknown, .none:
            return Color(.systemGray5).opacity(0.6)
        }
    }

    @ViewBuilder
    private var indicatorRow: some View {
        HStack(spacing: 8) {
            if let severity = trackedDomain.lastChangeSeverity, severity >= .medium {
                Label(severity.title, systemImage: severity == .high ? "exclamationmark.circle.fill" : "circle.fill")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(severity == .high ? .red : .yellow)
            } else {
                Label("Stable", systemImage: "circle.fill")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            if trackedDomain.certificateWarningLevel != .none {
                Text(certificateLabel)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(trackedDomain.certificateWarningLevel == .critical ? .red : .yellow)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background((trackedDomain.certificateWarningLevel == .critical ? Color.red : Color.yellow).opacity(0.16))
                    .clipShape(Capsule())
            }
        }
    }

    private var certificateLabel: String {
        let days = trackedDomain.certificateDaysRemaining.map { "\($0)d" } ?? "Soon"
        switch trackedDomain.certificateWarningLevel {
        case .critical:
            return "Cert \(days)"
        case .warning:
            return "Warn \(days)"
        case .none:
            return ""
        }
    }
}

struct TrackedDomainDetailView: View {
    @Bindable var viewModel: DomainViewModel
    let trackedDomain: TrackedDomain
    @Environment(\.dismiss) private var dismiss

    @State private var noteDraft = ""
    @State private var isEditingNote = false

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
                    viewModel.rerunInspection(for: liveTrackedDomain)
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
                    DomainDiffView(title: "Latest Snapshot vs Previous", sections: latestDiffSections, showsUnchanged: false)
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
