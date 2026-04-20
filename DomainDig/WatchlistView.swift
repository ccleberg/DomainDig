import SwiftUI

struct WatchlistView: View {
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            if viewModel.sortedTrackedDomains.isEmpty {
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
                    ForEach(viewModel.sortedTrackedDomains) { trackedDomain in
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
                    .onDelete(perform: viewModel.deleteTrackedDomains)
                } header: {
                    Text("Tracked Domains")
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle("Watchlist")
        .toolbar {
            if !viewModel.sortedTrackedDomains.isEmpty {
                EditButton()
            }
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .preferredColorScheme(.dark)
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

            if let note = trackedDomain.note?.trimmingCharacters(in: .whitespacesAndNewlines), !note.isEmpty {
                Text(note)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            } else if let summary = trackedDomain.lastChangeSummary {
                Text(summary.changedSections.isEmpty ? "No meaningful changes detected." : summary.changedSections.joined(separator: " • "))
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
