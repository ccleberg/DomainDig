import SwiftUI

struct HistoryView: View {
    @Bindable var viewModel: DomainViewModel

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
                EditButton()
            }
        }
        .preferredColorScheme(.dark)
    }
}

struct HistoryDetailView: View {
    @Bindable var viewModel: DomainViewModel
    let entry: HistoryEntry

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
                    isWatched: viewModel.watchedDomains.contains(where: { $0.domain.lowercased() == entry.domain.lowercased() }),
                    onToggleWatch: {
                        viewModel.toggleWatchedDomain(domain: entry.domain, availabilityStatus: entry.availabilityResult?.status)
                    }
                )
                    .padding(.top, 16)
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
