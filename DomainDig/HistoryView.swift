import SwiftUI

struct HistoryView: View {
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showClearAllConfirmation = false

    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    var body: some View {
        List {
            if viewModel.history.isEmpty {
                Text("No lookup history")
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
            } else {
                ForEach(viewModel.history) { entry in
                    NavigationLink {
                        HistoryDetailView(viewModel: viewModel, entry: entry)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.domain)
                                .font(.system(.callout, design: .monospaced))
                                .foregroundStyle(.primary)
                            HStack(spacing: 8) {
                                Text(dateFormatter.string(from: entry.timestamp))
                                Text("Snapshot")
                                Text(entry.resolverDisplayName)
                                if let totalLookupDurationMs = entry.totalLookupDurationMs {
                                    Text("\(totalLookupDurationMs) ms")
                                }
                            }
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                        }
                    }
                    .listRowBackground(Color(.systemGray6).opacity(0.5))
                }
                .onDelete { offsets in
                    viewModel.removeHistoryEntries(at: offsets)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .navigationTitle("History")
        .toolbar {
            if !viewModel.history.isEmpty {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Menu {
                        Button("Clear All", role: .destructive) {
                            showClearAllConfirmation = true
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
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
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .preferredColorScheme(.dark)
    }
}

struct HistoryDetailView: View {
    @Bindable var viewModel: DomainViewModel
    let entry: HistoryEntry
    @Environment(\.dismiss) private var dismiss

    private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private var snapshot: LookupSnapshot {
        entry.snapshot
    }

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 0) {
                snapshotBanner
                SummaryView(fields: DomainViewModel.summaryFields(from: snapshot))
                    .padding(.top, 8)
                DomainSectionView(
                    rows: DomainViewModel.domainRows(from: snapshot),
                    suggestions: DomainViewModel.suggestionRows(from: snapshot),
                    showSuggestions: entry.availabilityResult?.status == .registered && !entry.suggestions.isEmpty,
                    availabilityLoading: false,
                    suggestionsLoading: false,
                    trackedDomain: viewModel.trackedDomains.first(where: { $0.domain.lowercased() == entry.domain.lowercased() }),
                    trackingLimitMessage: nil,
                    onTrack: {
                        _ = viewModel.trackDomain(domain: entry.domain, availabilityStatus: entry.availabilityResult?.status)
                    },
                    onTogglePinned: {
                        guard let trackedDomain = viewModel.trackedDomains.first(where: { $0.domain.lowercased() == entry.domain.lowercased() }) else { return }
                        viewModel.togglePinned(for: trackedDomain)
                    },
                    onEditNote: nil
                )
                    .padding(.top, 16)
                if let comparisonSnapshot = viewModel.comparisonSnapshot(for: entry) {
                    if let changeSummary = entry.changeSummary {
                        DomainChangeSummaryView(summary: changeSummary)
                            .padding(.top, 16)
                    }
                    DomainDiffView(
                        title: "Compared With Previous Snapshot",
                        sections: DomainDiffService.diff(from: comparisonSnapshot, to: snapshot),
                        showsUnchanged: false
                    )
                    .padding(.top, 16)
                }
                DNSSectionView(
                    dnssecLabel: DomainViewModel.dnssecLabel(from: snapshot),
                    sections: DomainViewModel.dnsRows(from: snapshot),
                    ptrMessage: DomainViewModel.ptrMessage(from: snapshot),
                    loading: false,
                    sectionError: snapshot.dnsError
                )
                .padding(.top, 16)
                WebSectionView(
                    certificateRows: DomainViewModel.webCertificateRows(from: snapshot),
                    sslInfo: snapshot.sslInfo,
                    sslLoading: false,
                    sslError: snapshot.sslError,
                    responseRows: DomainViewModel.webResponseRows(from: snapshot),
                    headers: snapshot.httpHeaders,
                    headersLoading: false,
                    headersError: snapshot.httpHeadersError,
                    redirects: DomainViewModel.redirectRows(from: snapshot),
                    redirectLoading: false,
                    redirectError: snapshot.redirectChainError,
                    finalURL: snapshot.redirectChain.last?.url
                )
                .padding(.top, 16)
                EmailSectionView(
                    rows: DomainViewModel.emailRows(from: snapshot),
                    loading: false,
                    error: snapshot.emailSecurityError
                )
                .padding(.top, 16)
                NetworkSectionView(
                    reachabilityRows: DomainViewModel.reachabilityRows(from: snapshot),
                    reachabilityLoading: false,
                    reachabilityError: snapshot.reachabilityError,
                    locationRows: DomainViewModel.locationRows(from: snapshot),
                    geolocation: snapshot.ipGeolocation,
                    geolocationLoading: false,
                    geolocationError: snapshot.ipGeolocationError,
                    standardPortRows: DomainViewModel.portRows(from: snapshot, kind: .standard),
                    customPortRows: DomainViewModel.portRows(from: snapshot, kind: .custom),
                    portScanLoading: false,
                    portScanError: snapshot.portScanError,
                    customPortScanLoading: false,
                    customPortScanError: nil,
                    isCloudflareProxied: snapshot.httpHeaders.contains(where: { $0.name.lowercased() == "cf-ray" }),
                    customPortsExpanded: .constant(false),
                    customPortInput: .constant(""),
                    onScanCustomPorts: {}
                )
                .padding(.top, 16)
            }
            .padding(.horizontal)
            .padding(.bottom, 32)
        }
        .background(Color.black)
        .navigationTitle(entry.domain)
        .toolbar {
            Button("Re-run") {
                viewModel.rerunLookup(from: entry)
            }
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            dismiss()
        }
        .preferredColorScheme(.dark)
    }

    private var snapshotBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "archivebox")
                .font(.caption)
            Text("Snapshot from \(dateFormatter.string(from: entry.timestamp))")
                .font(.system(.caption, design: .monospaced))
            Spacer()
            Text("Live re-run available")
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .foregroundStyle(.secondary)
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.systemGray6).opacity(0.3))
        .cornerRadius(6)
        .padding(.vertical, 12)
    }
}
