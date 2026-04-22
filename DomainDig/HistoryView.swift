import SwiftUI

struct HistoryView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showClearAllConfirmation = false
    @State private var showWorkflowAddSheet = false

    private var groupedHistory: [HistoryGroup] {
        HistoryGroup.groups(for: viewModel.filteredHistory)
    }

    var body: some View {
        List {
            if viewModel.filteredHistory.isEmpty {
                EmptyStateCardView(
                    title: "No History Yet",
                    message: "History stores local snapshots of previous inspections so you can revisit and compare them later.",
                    suggestion: "Run a lookup to create your first saved snapshot.",
                    systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90"
                )
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
            } else {
                ForEach(groupedHistory) { group in
                    Section(group.title) {
                        ForEach(group.entries) { entry in
                            NavigationLink {
                                HistoryDetailView(viewModel: viewModel, entry: entry)
                            } label: {
                                VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing + 1) {
                                    HStack(alignment: .center, spacing: 8) {
                                        Text(entry.domain)
                                            .font(appDensity.font(.callout))
                                            .foregroundStyle(.primary)
                                        Spacer()
                                        AppStatusBadgeView(model: AppStatusFactory.change(entry.changeSummary))
                                    }

                                    HStack(spacing: 8) {
                                        AppStatusBadgeView(model: AppStatusFactory.availability(entry.availabilityResult?.status))
                                        AppStatusBadgeView(model: AppStatusFactory.tls(sslInfo: entry.sslInfo, error: entry.sslError))
                                        if entry.isPartialSnapshot {
                                            AppStatusBadgeView(model: .init(title: "Partial", systemImage: "exclamationmark.triangle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16)))
                                        }
                                    }

                                    HStack(spacing: 8) {
                                        Text(entry.timestamp.formatted(date: .abbreviated, time: .shortened))
                                        Text(entry.timestamp.formatted(.relative(presentation: .named)))
                                        Text(entry.resolverDisplayName)
                                        if let totalLookupDurationMs = entry.totalLookupDurationMs {
                                            Text("\(totalLookupDurationMs) ms")
                                        }
                                    }
                                    .font(appDensity.font(.caption2))
                                    .foregroundStyle(.secondary)

                                    if let note = entry.note, !note.isEmpty {
                                        Text(note)
                                            .font(appDensity.font(.caption2))
                                            .foregroundStyle(.secondary)
                                            .lineLimit(1)
                                    }
                                }
                            }
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    viewModel.removeHistoryEntries(withIDs: [entry.id])
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                        .listRowBackground(Color(.systemGray6).opacity(0.5))
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle("History")
        .searchable(text: $viewModel.historySearchText, prompt: "Search domains")
        .toolbar {
            if !viewModel.history.isEmpty {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Menu {
                        Picker("Date Range", selection: $viewModel.historyDateFilter) {
                            ForEach(HistoryDateFilter.allCases) { option in
                                Text(option.title).tag(option)
                            }
                        }

                        Picker("Change Filter", selection: $viewModel.historyChangeFilter) {
                            ForEach(ChangeFilterOption.allCases) { option in
                                Text(option.title).tag(option)
                            }
                        }

                        Picker("Sort", selection: $viewModel.historySortOption) {
                            ForEach(HistorySortOption.allCases) { option in
                                Text(option.title).tag(option)
                            }
                        }

                        Button("Clear All", role: .destructive) {
                            showClearAllConfirmation = true
                        }

                        if !viewModel.filteredHistory.isEmpty {
                            Button("Add to Workflow") {
                                showWorkflowAddSheet = true
                            }
                        }
                    } label: {
                        Image(systemName: "line.3.horizontal.decrease.circle")
                    }

                    EditButton()
                }
            }
        }
        .alert("Clear history?", isPresented: $showClearAllConfirmation) {
            Button("Clear All", role: .destructive) {
                viewModel.clearHistory()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will delete all saved history entries. This cannot be undone.")
        }
        .sheet(isPresented: $showWorkflowAddSheet) {
            WorkflowBulkAddSheet(
                viewModel: viewModel,
                title: "Add History Domains",
                availableDomains: Array(Set(viewModel.filteredHistory.map(\.domain))).sorted()
            )
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .preferredColorScheme(.dark)
    }

    private func deleteFilteredHistoryEntries(at offsets: IndexSet) {
        let ids = offsets.map { viewModel.filteredHistory[$0].id }
        viewModel.removeHistoryEntries(withIDs: ids)
    }
}

struct HistoryDetailView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    let entry: HistoryEntry
    @Environment(\.dismiss) private var dismiss
    @State private var noteDraft = ""
    @State private var isEditingNote = false
    @State private var showRerunOptions = false

    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private var snapshot: LookupSnapshot {
        entry.snapshot
    }

    private var report: DomainReport {
        DomainReportBuilder().build(from: entry, previousSnapshot: viewModel.comparisonSnapshot(for: entry))
    }

    private var trackedDomain: TrackedDomain? {
        viewModel.trackedDomains.first { $0.domain.caseInsensitiveCompare(entry.domain) == .orderedSame }
    }

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 0) {
                snapshotBanner
                SummaryView(fields: DomainViewModel.summaryFields(from: snapshot))
                    .padding(.top, 8)
                RiskSummaryCardView(report: report)
                    .padding(.top, 8)
                InsightsSummaryCardView(insights: report.insights)
                    .padding(.top, 8)
                DomainSectionView(
                    isCollapsed: .constant(false),
                    rows: DomainViewModel.domainRows(from: snapshot),
                    suggestions: DomainViewModel.suggestionRows(from: snapshot),
                    showSuggestions: entry.availabilityResult?.status == .registered && !entry.suggestions.isEmpty,
                    availabilityLoading: false,
                    suggestionsLoading: false,
                    provenance: snapshot.provenanceBySection[.availability],
                    confidence: snapshot.availabilityConfidence,
                    snapshotNote: entry.note,
                    trackedDomain: trackedDomain,
                    workflows: viewModel.workflowsContaining(domain: entry.domain),
                    trackingLimitMessage: nil,
                    onTrack: {
                        _ = viewModel.trackDomain(domain: entry.domain, availabilityStatus: entry.availabilityResult?.status)
                    },
                    onTogglePinned: {
                        guard let trackedDomain else { return }
                        viewModel.togglePinned(for: trackedDomain)
                    },
                    onEditNote: nil,
                    onAddToWorkflow: nil,
                    onOpenWorkflow: nil,
                    onRunWorkflow: nil
                )
                    .padding(.top, appDensity.metrics.sectionSpacing)
                OwnershipSectionView(
                    isCollapsed: .constant(false),
                    rows: DomainViewModel.ownershipRows(from: snapshot),
                    loading: false,
                    error: snapshot.ownershipError,
                    provenance: snapshot.provenanceBySection[.ownership],
                    confidence: snapshot.ownershipConfidence,
                    showsHistoryPlaceholder: !DataAccessService.hasAccess(to: .ownershipHistory)
                )
                .padding(.top, appDensity.metrics.sectionSpacing)
                SubdomainsSectionView(
                    isCollapsed: .constant(false),
                    rows: DomainViewModel.subdomainRows(from: snapshot),
                    groups: report.subdomainGroups,
                    loading: false,
                    error: snapshot.subdomainsError,
                    provenance: snapshot.provenanceBySection[.subdomains],
                    confidence: snapshot.subdomainConfidence,
                    showsExtendedPlaceholder: !DataAccessService.hasAccess(to: .extendedSubdomains)
                )
                .padding(.top, appDensity.metrics.sectionSpacing)
                if let comparisonSnapshot = viewModel.comparisonSnapshot(for: entry) {
                    if let changeSummary = entry.changeSummary {
                        DomainChangeSummaryView(summary: changeSummary)
                            .padding(.top, appDensity.metrics.sectionSpacing)
                    }
                    DomainDiffView(
                        title: "Compared With Previous Snapshot",
                        sections: DomainDiffService.diff(from: comparisonSnapshot, to: snapshot),
                        contextNote: DomainDiffService.comparisonContextNote(from: comparisonSnapshot, to: snapshot),
                        showsUnchanged: false
                    )
                    .padding(.top, appDensity.metrics.sectionSpacing)
                }
                DNSSectionView(
                    isCollapsed: .constant(false),
                    dnssecLabel: DomainViewModel.dnssecLabel(from: snapshot),
                    patternSummary: report.dns.patternSummary,
                    sections: DomainViewModel.dnsRows(from: snapshot),
                    ptrMessage: DomainViewModel.ptrMessage(from: snapshot),
                    loading: false,
                    dnsProvenance: snapshot.provenanceBySection[.dns],
                    ptrProvenance: snapshot.provenanceBySection[.ptr],
                    sectionError: snapshot.dnsError
                )
                .padding(.top, appDensity.metrics.sectionSpacing)
                WebSectionView(
                    isCollapsed: .constant(false),
                    certificateRows: DomainViewModel.webCertificateRows(from: snapshot),
                    sslInfo: snapshot.sslInfo,
                    tlsSummary: report.web,
                    sslLoading: false,
                    sslError: snapshot.sslError,
                    tlsProvenance: snapshot.provenanceBySection[.ssl],
                    responseRows: DomainViewModel.webResponseRows(from: snapshot),
                    headers: snapshot.httpHeaders,
                    headersLoading: false,
                    headersError: snapshot.httpHeadersError,
                    httpProvenance: snapshot.provenanceBySection[.httpHeaders],
                    redirects: DomainViewModel.redirectRows(from: snapshot),
                    redirectLoading: false,
                    redirectError: snapshot.redirectChainError,
                    redirectProvenance: snapshot.provenanceBySection[.redirectChain],
                    finalURL: snapshot.redirectChain.last?.url
                )
                .padding(.top, appDensity.metrics.sectionSpacing)
                EmailSectionView(
                    isCollapsed: .constant(false),
                    rows: DomainViewModel.emailRows(from: snapshot),
                    assessment: report.email,
                    loading: false,
                    provenance: snapshot.provenanceBySection[.emailSecurity],
                    confidence: snapshot.emailSecurityConfidence,
                    error: snapshot.emailSecurityError
                )
                .padding(.top, appDensity.metrics.sectionSpacing)
                NetworkSectionView(
                    isCollapsed: .constant(false),
                    reachabilityRows: DomainViewModel.reachabilityRows(from: snapshot),
                    reachabilityLoading: false,
                    reachabilityError: snapshot.reachabilityError,
                    reachabilityProvenance: snapshot.provenanceBySection[.reachability],
                    locationRows: DomainViewModel.locationRows(from: snapshot),
                    geolocation: snapshot.ipGeolocation,
                    geolocationLoading: false,
                    geolocationError: snapshot.ipGeolocationError,
                    geolocationProvenance: snapshot.provenanceBySection[.ipGeolocation],
                    geolocationConfidence: snapshot.geolocationConfidence,
                    standardPortRows: DomainViewModel.portRows(from: snapshot, kind: .standard),
                    customPortRows: DomainViewModel.portRows(from: snapshot, kind: .custom),
                    portScanLoading: false,
                    portScanError: snapshot.portScanError,
                    portScanProvenance: snapshot.provenanceBySection[.portScan],
                    customPortScanLoading: false,
                    customPortScanError: nil,
                    isCloudflareProxied: snapshot.httpHeaders.contains(where: { $0.name.lowercased() == "cf-ray" }),
                    customPortsExpanded: .constant(false),
                    customPortInput: .constant(""),
                    onScanCustomPorts: {}
                )
                .padding(.top, appDensity.metrics.sectionSpacing)
            }
            .padding(.horizontal)
            .padding(.bottom, 32)
        }
        .background(Color.black)
        .navigationTitle(entry.domain)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                Button("Note") {
                    noteDraft = entry.note ?? ""
                    isEditingNote = true
                }
                Button("Re-run") {
                    showRerunOptions = true
                }
            }
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .confirmationDialog("Re-run lookup", isPresented: $showRerunOptions) {
            Button("Run with Current Settings") {
                viewModel.rerunLookup(from: entry, useSnapshotResolver: false)
            }
            Button("Run with Snapshot Resolver") {
                viewModel.rerunLookup(from: entry, useSnapshotResolver: true)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(viewModel.resolverMismatchNote(for: entry) ?? "Choose how to reproduce this snapshot.")
        }
        .sheet(isPresented: $isEditingNote) {
            NavigationStack {
                Form {
                    Section("Audit Note") {
                        TextField("Optional note", text: $noteDraft, axis: .vertical)
                            .lineLimit(3...6)
                    }
                }
                .navigationTitle(entry.domain)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            isEditingNote = false
                        }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            viewModel.updateHistoryNote(noteDraft, for: entry)
                            isEditingNote = false
                        }
                    }
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var snapshotBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "archivebox")
                    .font(.caption)
                Text("Snapshot from \(dateFormatter.string(from: entry.timestamp))")
                    .font(appDensity.font(.caption))
                Spacer()
                Text("Live re-run available")
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
            }
            if let mismatchNote = viewModel.resolverMismatchNote(for: entry) {
                Text(mismatchNote)
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.orange)
            }
            if entry.isPartialSnapshot {
                Text("Partial snapshot: \(entry.validationIssues.joined(separator: " | "))")
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.yellow)
            }
            if let note = entry.note, !note.isEmpty {
                Text(note)
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
            }
        }
        .foregroundStyle(.secondary)
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.systemGray6).opacity(0.3))
        .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
        .padding(.vertical, 12)
    }
}

private struct HistoryGroup: Identifiable {
    let title: String
    let entries: [HistoryEntry]

    var id: String { title }

    static func groups(for entries: [HistoryEntry]) -> [HistoryGroup] {
        let calendar = Calendar.current
        let today = Date()
        let yesterday = calendar.date(byAdding: .day, value: -1, to: today) ?? today

        let grouped = Dictionary(grouping: entries) { entry -> String in
            if calendar.isDate(entry.timestamp, inSameDayAs: today) {
                return "Today"
            }
            if calendar.isDate(entry.timestamp, inSameDayAs: yesterday) {
                return "Yesterday"
            }
            return "Older"
        }

        return ["Today", "Yesterday", "Older"].compactMap { title in
            guard let entries = grouped[title], !entries.isEmpty else { return nil }
            return HistoryGroup(title: title, entries: entries)
        }
    }
}
