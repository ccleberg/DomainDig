import MapKit
import SwiftUI

enum LookupInputMode: String, CaseIterable, Identifiable {
    case single
    case bulk

    var id: String { rawValue }
}

enum ResultSection: String, Hashable {
    case domain
    case ownership
    case dns
    case web
    case email
    case network
    case subdomains
}

struct ContentView: View {
    @Environment(\.appDensity) private var appDensity
    @State private var viewModel = DomainViewModel()
    @State private var navigationPath = NavigationPath()
    @FocusState private var domainFieldFocused: Bool
    @State private var customPortInput = ""
    @State private var customPortsExpanded = false
    @State private var trackingNoteDraft = ""
    @State private var editingTrackedDomain: TrackedDomain?
    @State private var showTrackLimitAlert = false
    @State private var inputMode: LookupInputMode = .single
    @State private var collapsedSections: Set<ResultSection> = [.network]

    var body: some View {
        NavigationStack(path: $navigationPath) {
            ScrollView(.vertical) {
                VStack(spacing: 0) {
                    inputSection
                    if !viewModel.batchResults.isEmpty || viewModel.batchLookupRunning {
                        batchSection
                            .padding(.top, appDensity.metrics.cardSpacing)
                    }
                    if viewModel.hasRun {
                        actionButtons
                        if !viewModel.resultsLoaded {
                            LookupProgressOverviewView(steps: viewModel.activeLoadingLabels)
                                .padding(.top, appDensity.metrics.cardSpacing)
                        } else if let statusMessage = resultStatusMessage {
                            LookupStatusBannerView(message: statusMessage, resultSource: viewModel.currentResultSource)
                                .padding(.top, appDensity.metrics.cardSpacing)
                        }
                        if viewModel.resultsLoaded {
                            SummaryView(fields: viewModel.summaryFields)
                                .padding(.top, appDensity.metrics.cardSpacing)
                            if let changeSummary = viewModel.currentChangeSummary {
                                DomainChangeSummaryView(summary: changeSummary)
                                    .padding(.top, appDensity.metrics.cardSpacing)
                            }
                        }
                        DomainSectionView(
                            isCollapsed: sectionCollapsedBinding(.domain),
                            rows: viewModel.domainRows,
                            suggestions: viewModel.suggestionRows,
                            showSuggestions: viewModel.availabilityResult?.status == .registered || viewModel.suggestionsLoading,
                            availabilityLoading: viewModel.availabilityLoading,
                            suggestionsLoading: viewModel.suggestionsLoading,
                            provenance: viewModel.currentSnapshot.provenanceBySection[.availability],
                            confidence: viewModel.currentSnapshot.availabilityConfidence,
                            snapshotNote: viewModel.currentSnapshot.note,
                            trackedDomain: viewModel.currentTrackedDomain,
                            trackingLimitMessage: viewModel.trackingLimitMessage,
                            onTrack: {
                                if !viewModel.trackCurrentDomain() {
                                    showTrackLimitAlert = true
                                }
                            },
                            onTogglePinned: {
                                guard let trackedDomain = viewModel.currentTrackedDomain else { return }
                                viewModel.togglePinned(for: trackedDomain)
                            },
                            onEditNote: {
                                guard let trackedDomain = viewModel.currentTrackedDomain else { return }
                                trackingNoteDraft = trackedDomain.note ?? ""
                                editingTrackedDomain = trackedDomain
                            }
                        )
                            .padding(.top, appDensity.metrics.sectionSpacing)
                        OwnershipSectionView(
                            isCollapsed: sectionCollapsedBinding(.ownership),
                            rows: viewModel.ownershipRows,
                            loading: viewModel.ownershipLoading,
                            error: viewModel.ownershipError,
                            provenance: viewModel.currentSnapshot.provenanceBySection[.ownership],
                            confidence: viewModel.currentSnapshot.ownershipConfidence,
                            showsHistoryPlaceholder: !DataAccessService.hasAccess(to: .ownershipHistory)
                        )
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        SubdomainsSectionView(
                            isCollapsed: sectionCollapsedBinding(.subdomains),
                            rows: viewModel.subdomainRows,
                            loading: viewModel.subdomainsLoading,
                            error: viewModel.subdomainsError,
                            provenance: viewModel.currentSnapshot.provenanceBySection[.subdomains],
                            confidence: viewModel.currentSnapshot.subdomainConfidence,
                            showsExtendedPlaceholder: !DataAccessService.hasAccess(to: .extendedSubdomains)
                        )
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        if !viewModel.currentDiffSections.isEmpty {
                            DomainDiffView(
                                title: "Latest Changes",
                                sections: viewModel.currentDiffSections,
                                contextNote: viewModel.currentChangeSummary?.contextNote,
                                showsUnchanged: false
                            )
                            .padding(.top, appDensity.metrics.sectionSpacing)
                        }
                        DNSSectionView(
                            isCollapsed: sectionCollapsedBinding(.dns),
                            dnssecLabel: viewModel.dnssecLabel,
                            sections: viewModel.dnsRows,
                            ptrMessage: viewModel.ptrMessage,
                            loading: viewModel.dnsLoading || viewModel.ptrLoading,
                            dnsProvenance: viewModel.currentSnapshot.provenanceBySection[.dns],
                            ptrProvenance: viewModel.currentSnapshot.provenanceBySection[.ptr],
                            sectionError: viewModel.dnsError
                        )
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        WebSectionView(
                            isCollapsed: sectionCollapsedBinding(.web),
                            certificateRows: viewModel.webCertificateRows,
                            sslInfo: viewModel.sslInfo,
                            sslLoading: viewModel.sslLoading || viewModel.hstsLoading,
                            sslError: viewModel.sslError,
                            tlsProvenance: viewModel.currentSnapshot.provenanceBySection[.ssl],
                            responseRows: viewModel.webResponseRows,
                            headers: viewModel.httpHeaders,
                            headersLoading: viewModel.httpHeadersLoading,
                            headersError: viewModel.httpHeadersError,
                            httpProvenance: viewModel.currentSnapshot.provenanceBySection[.httpHeaders],
                            redirects: viewModel.redirectRows,
                            redirectLoading: viewModel.redirectChainLoading,
                            redirectError: viewModel.redirectChainError,
                            redirectProvenance: viewModel.currentSnapshot.provenanceBySection[.redirectChain],
                            finalURL: viewModel.currentSnapshot.redirectChain.last?.url
                        )
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        EmailSectionView(
                            isCollapsed: sectionCollapsedBinding(.email),
                            rows: viewModel.emailRows,
                            loading: viewModel.emailSecurityLoading,
                            provenance: viewModel.currentSnapshot.provenanceBySection[.emailSecurity],
                            confidence: viewModel.currentSnapshot.emailSecurityConfidence,
                            error: viewModel.emailSecurityError
                        )
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        NetworkSectionView(
                            isCollapsed: sectionCollapsedBinding(.network),
                            reachabilityRows: viewModel.reachabilityRows,
                            reachabilityLoading: viewModel.reachabilityLoading,
                            reachabilityError: viewModel.reachabilityError,
                            reachabilityProvenance: viewModel.currentSnapshot.provenanceBySection[.reachability],
                            locationRows: viewModel.locationRows,
                            geolocation: viewModel.ipGeolocation,
                            geolocationLoading: viewModel.ipGeolocationLoading,
                            geolocationError: viewModel.ipGeolocationError,
                            geolocationProvenance: viewModel.currentSnapshot.provenanceBySection[.ipGeolocation],
                            geolocationConfidence: viewModel.currentSnapshot.geolocationConfidence,
                            standardPortRows: viewModel.standardPortRows,
                            customPortRows: viewModel.customPortRows,
                            portScanLoading: viewModel.portScanLoading,
                            portScanError: viewModel.portScanError,
                            portScanProvenance: viewModel.currentSnapshot.provenanceBySection[.portScan],
                            customPortScanLoading: viewModel.customPortScanLoading,
                            customPortScanError: viewModel.customPortScanError,
                            isCloudflareProxied: viewModel.isCloudflareProxied,
                            customPortsExpanded: $customPortsExpanded,
                            customPortInput: $customPortInput,
                            onScanCustomPorts: runCustomPortScan
                        )
                        .padding(.top, appDensity.metrics.sectionSpacing)
                    } else if !viewModel.recentSearches.isEmpty {
                        recentSearchesSection
                    }
                }
                .padding(.horizontal)
                .padding(.bottom, 32)
            }
            .background(
                LinearGradient(
                    colors: [Color.black, Color(.systemGray6).opacity(0.12)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            )
            .navigationTitle("DomainDig")
            .toolbarColorScheme(.dark, for: .navigationBar)
            .preferredColorScheme(.dark)
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    if viewModel.hasRun {
                        Button {
                            viewModel.reset()
                        } label: {
                            Image(systemName: "xmark.circle")
                                .foregroundStyle(.secondary)
                        }
                    }
                    NavigationLink {
                        WatchlistView(viewModel: viewModel)
                    } label: {
                        Image(systemName: "eye")
                            .foregroundStyle(.secondary)
                    }
                    Menu {
                        NavigationLink {
                            HistoryView(viewModel: viewModel)
                        } label: {
                            Label("History", systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90")
                        }

                        NavigationLink {
                            SavedDomainsView(viewModel: viewModel)
                        } label: {
                            Label("Saved Domains", systemImage: "bookmark")
                        }

                        NavigationLink {
                            SettingsView(viewModel: viewModel)
                        } label: {
                            Label("Settings", systemImage: "gearshape")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .onAppear {
            domainFieldFocused = true
        }
        .onChange(of: viewModel.searchedDomain) { _, _ in
            collapsedSections = defaultCollapsedSections
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            navigationPath = NavigationPath()
            domainFieldFocused = false
        }
        .alert("Tracking limit reached", isPresented: $showTrackLimitAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Free version supports up to 3 tracked domains. More tracked domains will be available in a future Pro upgrade.")
        }
        .sheet(item: $editingTrackedDomain) { trackedDomain in
            NavigationStack {
                Form {
                    Section("Tracking Note") {
                        TextField("Optional note", text: $trackingNoteDraft, axis: .vertical)
                            .lineLimit(3...6)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }
                .navigationTitle(trackedDomain.domain)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") {
                            editingTrackedDomain = nil
                        }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            viewModel.updateNote(trackingNoteDraft, for: trackedDomain)
                            editingTrackedDomain = nil
                        }
                    }
                }
            }
        }
    }

    private var inputSection: some View {
        VStack(spacing: appDensity.metrics.cardSpacing + 2) {
            Picker("Mode", selection: $inputMode) {
                Text("Single").tag(LookupInputMode.single)
                Text("Bulk").tag(LookupInputMode.bulk)
            }
            .pickerStyle(.segmented)

            if inputMode == .single {
                TextField("e.g. cleberg.net", text: $viewModel.domain)
                    .font(appDensity.font(.title3, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .padding(.horizontal, 12)
                    .padding(.vertical, appDensity.metrics.controlVerticalPadding)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
                    .focused($domainFieldFocused)
                    .onSubmit { viewModel.run() }

                Button {
                    domainFieldFocused = false
                    viewModel.run()
                } label: {
                    Text("Run")
                        .font(appDensity.font(.headline, design: .default, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .frame(minHeight: appDensity.metrics.controlMinHeight)
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.trimmedDomain.isEmpty)
            } else {
                VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
                    Text("Paste domains separated by new lines or commas.")
                        .font(appDensity.font(.caption))
                        .foregroundStyle(.secondary)

                    TextField(
                        "example.com\napple.com, openai.com",
                        text: $viewModel.bulkInput,
                        axis: .vertical
                    )
                    .font(appDensity.font(.body))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .lineLimit(4...10)
                    .padding(.horizontal, 12)
                    .padding(.vertical, appDensity.metrics.controlVerticalPadding)
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))

                    Button {
                        domainFieldFocused = false
                        viewModel.runBulkLookup()
                    } label: {
                        Text(viewModel.batchLookupRunning ? "Running Batch…" : "Run Batch")
                            .font(appDensity.font(.headline, design: .default, weight: .semibold))
                            .frame(maxWidth: .infinity)
                            .frame(minHeight: appDensity.metrics.controlMinHeight)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.bulkInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || viewModel.batchLookupRunning)
                }
            }
        }
        .padding(.vertical, appDensity.metrics.sectionSpacing)
    }

    private var actionButtons: some View {
        HStack {
            Spacer()
            if viewModel.resultsLoaded {
                Button {
                    viewModel.toggleSavedDomain()
                } label: {
                    Image(systemName: viewModel.isCurrentDomainSaved ? "bookmark.fill" : "bookmark")
                        .font(appDensity.font(.body, design: .default))
                        .foregroundStyle(viewModel.isCurrentDomainSaved ? .yellow : .secondary)
                }
                Menu {
                    Button("Export TXT") {
                        shareSingleResults(format: .text)
                    }
                    Button("Export CSV") {
                        shareSingleResults(format: .csv)
                    }
                    Button("Export JSON") {
                        shareSingleResults(format: .json)
                    }
                } label: {
                    Image(systemName: "square.and.arrow.up")
                        .font(appDensity.font(.body, design: .default))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var batchSection: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            HStack {
                Spacer()
                if viewModel.batchLookupRunning {
                    Button("Cancel") {
                        viewModel.cancelBatchLookup()
                    }
                    .buttonStyle(.bordered)
                    .font(appDensity.font(.caption))
                }
                if !viewModel.currentBatchResultEntries.isEmpty {
                    Menu {
                        Button("Export Batch TXT") {
                            shareBatchResults(format: .text)
                        }
                        Button("Export Batch CSV") {
                            shareBatchResults(format: .csv)
                        }
                        Button("Export Batch JSON") {
                            shareBatchResults(format: .json)
                        }
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                            .font(appDensity.font(.caption))
                    }
                    .buttonStyle(.bordered)
                }
            }

            BatchResultsView(
                viewModel: viewModel,
                title: viewModel.batchLookupSource == .watchlistRefresh ? "Tracked Domain Refresh" : "Batch Results"
            )
        }
    }

    private var recentSearchesSection: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            HStack {
                Text("RECENT")
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear") {
                    viewModel.clearRecentSearches()
                }
                .font(appDensity.font(.caption2))
                .foregroundStyle(.secondary)
            }

            ForEach(viewModel.recentSearches, id: \.self) { domain in
                Button {
                    viewModel.domain = domain
                    domainFieldFocused = false
                    viewModel.run()
                } label: {
                    Text(domain)
                        .font(appDensity.font(.callout))
                        .foregroundStyle(.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 8)
                        .padding(.horizontal, 10)
                        .background(Color(.systemGray6).opacity(0.5))
                        .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
                }
            }
        }
        .padding(.top, appDensity.metrics.cardSpacing)
    }

    private func runCustomPortScan() {
        let ports = parsedCustomPorts(from: customPortInput)
        Task {
            await viewModel.runCustomPortScan(ports: ports)
        }
    }

    private func parsedCustomPorts(from input: String) -> [UInt16] {
        let parts = input.split(separator: ",", omittingEmptySubsequences: true)
        var seen = Set<UInt16>()
        var ports: [UInt16] = []

        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let value = UInt16(trimmed), seen.insert(value).inserted else {
                continue
            }
            ports.append(value)
            if ports.count == 20 {
                break
            }
        }

        return ports
    }

    private func shareSingleResults(format: DomainExportFormat) {
        let (filename, data) = exportPayload(
            prefix: "domaindig_single",
            format: format,
            text: viewModel.exportText(),
            csv: viewModel.exportCSV(),
            json: viewModel.exportJSONData()
        )
        ExportPresenter.share(filename: filename, data: data)
    }

    private func shareBatchResults(format: DomainExportFormat) {
        let (filename, data) = exportPayload(
            prefix: "domaindig_batch",
            format: format,
            text: viewModel.exportBatchText(),
            csv: viewModel.exportBatchCSV(),
            json: viewModel.exportBatchJSONData()
        )
        ExportPresenter.share(filename: filename, data: data)
    }

    private func exportPayload(
        prefix: String,
        format: DomainExportFormat,
        text: String,
        csv: String,
        json: Data?
    ) -> (String, Data) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = formatter.string(from: Date())
        let filename = "\(timestamp)_\(prefix).\(format.fileExtension)"
        let data: Data

        switch format {
        case .text:
            data = Data(text.utf8)
        case .csv:
            data = Data(csv.utf8)
        case .json:
            data = json ?? Data("[]".utf8)
        }

        return (filename, data)
    }

    private var defaultCollapsedSections: Set<ResultSection> {
        []
    }

    private var currentPrimaryIP: String? {
        viewModel.currentSnapshot.dnsSections.first(where: { $0.recordType == .A })?.records.first?.value
    }

    private var resultStatusMessage: String? {
        if let currentStatusMessage = viewModel.currentStatusMessage {
            return currentStatusMessage
        }

        if viewModel.currentResultSource != .live {
            return viewModel.currentResultSource.label
        }

        return nil
    }

    private func sectionCollapsedBinding(_ section: ResultSection) -> Binding<Bool> {
        Binding(
            get: { collapsedSections.contains(section) },
            set: { isCollapsed in
                if isCollapsed {
                    collapsedSections.insert(section)
                } else {
                    collapsedSections.remove(section)
                }
            }
        )
    }
}

struct SummaryView: View {
    @Environment(\.appDensity) private var appDensity
    let fields: [SummaryFieldViewData]

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            SectionTitleView(title: "Summary")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: appDensity.metrics.cardSpacing) {
                ForEach(fields) { field in
                    VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing) {
                        Text(field.label)
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                        Text(field.value)
                            .font(appDensity.font(.caption))
                            .foregroundStyle(ResultColors.color(for: field.tone))
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                    .frame(minHeight: appDensity.metrics.rowMinHeight + 12, alignment: .topLeading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(appDensity.metrics.cardPadding)
                    .background(Color(.systemGray6).opacity(0.5))
                    .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
                }
            }
        }
    }
}

struct StickyLookupSummaryView: View {
    @Environment(\.appDensity) private var appDensity

    let domain: String
    let availability: DomainAvailabilityStatus?
    let primaryIP: String?
    let sslInfo: SSLCertificateInfo?
    let sslError: String?
    let emailSecurity: EmailSecurityResult?
    let emailError: String?
    let changeSummary: DomainChangeSummary?

    var body: some View {
        CardView(allowsHorizontalScroll: false) {
            VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
                HStack(alignment: .center, spacing: 10) {
                    Text(domain)
                        .font(appDensity.font(.headline, weight: .semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Spacer(minLength: 6)
                    AppCopyButton(value: domain, label: "Copy domain")
                }

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        AppStatusBadgeView(model: AppStatusFactory.availability(availability))
                        AppStatusBadgeView(model: AppStatusFactory.tls(sslInfo: sslInfo, error: sslError))
                        AppStatusBadgeView(model: AppStatusFactory.email(emailSecurity, error: emailError))
                        AppStatusBadgeView(model: AppStatusFactory.change(changeSummary))
                    }
                }

                if let primaryIP {
                    HStack(spacing: 8) {
                        Label(primaryIP, systemImage: "network")
                            .font(appDensity.font(.caption))
                            .foregroundStyle(.secondary)
                        Spacer(minLength: 6)
                        AppCopyButton(value: primaryIP, label: "Copy IP")
                    }
                }
            }
        }
        .shadow(color: .black.opacity(0.12), radius: 14, y: 6)
    }
}

struct LookupProgressOverviewView: View {
    @Environment(\.appDensity) private var appDensity
    let steps: [String]

    var body: some View {
        CardView(allowsHorizontalScroll: false) {
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Running lookup…")
                        .font(appDensity.font(.caption))
                        .foregroundStyle(.primary)
                    Text(steps.isEmpty ? "Preparing requests" : steps.joined(separator: " • "))
                        .font(appDensity.font(.caption2))
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
        }
    }
}

struct LookupStatusBannerView: View {
    @Environment(\.appDensity) private var appDensity
    let message: String
    let resultSource: LookupResultSource

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: iconName)
                .font(.caption)
            Text(message)
                .font(appDensity.font(.caption))
            Spacer()
        }
        .foregroundStyle(color)
        .padding(appDensity.metrics.cardPadding - 2)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(color.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
    }

    private var color: Color {
        switch resultSource {
        case .live:
            return .green
        case .cached:
            return .secondary
        case .mixed:
            return .yellow
        case .snapshot:
            return .orange
        }
    }

    private var iconName: String {
        switch resultSource {
        case .live:
            return "bolt.horizontal"
        case .cached:
            return "clock.arrow.trianglehead.counterclockwise.rotate.90"
        case .mixed:
            return "arrow.triangle.branch"
        case .snapshot:
            return "archivebox"
        }
    }
}

struct DomainChangeSummaryView: View {
    @Environment(\.appDensity) private var appDensity
    let summary: DomainChangeSummary
    @State private var showsDetails = false

    var body: some View {
        CardView(allowsHorizontalScroll: false) {
            HStack {
                Label(summary.hasChanges ? "Changed" : "Stable", systemImage: summary.hasChanges ? "arrow.triangle.2.circlepath" : "checkmark.circle")
                    .font(appDensity.font(.caption))
                    .foregroundStyle(summary.hasChanges ? severityColor(summary.severity) : .green)
                Spacer()
                Text(summary.severity.title.uppercased())
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(summary.hasChanges ? severityColor(summary.severity) : .secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background((summary.hasChanges ? severityColor(summary.severity) : .secondary).opacity(0.16))
                    .clipShape(Capsule())
                Text(summary.generatedAt, style: .time)
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Inference")
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(.secondary)
                Text(summary.message)
                    .font(appDensity.font(.caption))
                    .foregroundStyle(.primary)
                    .lineLimit(2)
            }

            if !summary.observedFacts.isEmpty || summary.contextNote != nil {
                DisclosureGroup(showsDetails ? "Hide Details" : "Show Details", isExpanded: $showsDetails) {
                    VStack(alignment: .leading, spacing: 8) {
                        if !summary.observedFacts.isEmpty {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Observed")
                                    .font(appDensity.font(.caption2))
                                    .foregroundStyle(.secondary)
                                ForEach(Array(summary.observedFacts.enumerated()), id: \.offset) { _, fact in
                                    Text(fact)
                                        .font(appDensity.font(.caption))
                                        .foregroundStyle(.primary)
                                }
                            }
                        }

                        if let contextNote = summary.contextNote {
                            Text(contextNote)
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(.orange)
                        }
                    }
                    .padding(.top, 4)
                }
                .font(appDensity.font(.caption))
                .tint(.secondary)
            }
        }
    }

    private func severityColor(_ severity: ChangeSeverity) -> Color {
        switch severity {
        case .low:
            return .secondary
        case .medium:
            return .yellow
        case .high:
            return .red
        }
    }
}

struct DomainDiffView: View {
    let title: String
    let sections: [DomainDiffSection]
    let contextNote: String?
    let showsUnchanged: Bool

    @State private var collapsedSections = Set<UUID>()
    @State private var showsLowSeverity = false

    private var filteredSections: [DomainDiffSection] {
        sections
            .map { section in
                let items = section.items.filter { item in
                    if !showsUnchanged, !item.hasChanges {
                        return false
                    }
                    if showsLowSeverity {
                        return true
                    }
                    return item.severity >= .medium || (showsUnchanged && item.changeType == .unchanged)
                }
                return DomainDiffSection(title: section.title, items: items)
            }
            .filter { !$0.items.isEmpty }
    }

    private var hasLowSeverityChanges: Bool {
        sections.flatMap(\.items).contains { $0.hasChanges && $0.severity == .low }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                SectionTitleView(title: title)
                Spacer()
                if hasLowSeverityChanges {
                    Button(showsLowSeverity ? "Hide Low" : "Show Low") {
                        showsLowSeverity.toggle()
                    }
                    .buttonStyle(.bordered)
                    .font(.system(.caption, design: .monospaced))
                }
            }
            if let contextNote {
                MessageCardView(text: contextNote, isError: false)
            }
            if filteredSections.isEmpty {
                MessageCardView(text: "No comparison data available", isError: false)
            } else {
                ForEach(filteredSections) { section in
                    CardView(allowsHorizontalScroll: false) {
                        DisclosureGroup(isExpanded: binding(for: section)) {
                            let visibleItems = showsUnchanged ? section.items : section.items.filter(\.hasChanges)

                            ForEach(visibleItems) { item in
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack {
                                        Text(item.label)
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                        Spacer()
                                        Text("\(item.severity.title) • \(changeLabel(for: item.changeType))")
                                            .font(.system(.caption2, design: .monospaced))
                                            .foregroundStyle(changeColor(for: item))
                                            .padding(.horizontal, 8)
                                            .padding(.vertical, 4)
                                            .background(changeColor(for: item).opacity(0.16))
                                            .clipShape(Capsule())
                                    }

                                    if let oldValue = item.oldValue {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("Old")
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(.secondary)
                                            Text(oldValue)
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(.secondary)
                                                .textSelection(.enabled)
                                        }
                                    }

                                    if let newValue = item.newValue {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text("New")
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundStyle(.secondary)
                                            Text(newValue)
                                                .font(.system(.caption, design: .monospaced))
                                                .foregroundStyle(item.hasChanges ? .primary : .secondary)
                                                .textSelection(.enabled)
                                        }
                                    }
                                }
                                .padding(10)
                                .background(item.hasChanges ? changeColor(for: item).opacity(0.08) : Color(.systemGray6).opacity(0.25))
                                .cornerRadius(8)
                            }
                        } label: {
                            HStack {
                                Text(section.title)
                                    .font(.system(.subheadline, design: .monospaced))
                                    .fontWeight(.semibold)
                                    .foregroundStyle(sectionColor(section))
                                Spacer()
                                Text(section.severity.title)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(sectionColor(section))
                            }
                        }
                    }
                }
            }
        }
    }

    private func changeLabel(for changeType: DiffChangeType) -> String {
        switch changeType {
        case .added:
            return "Added"
        case .removed:
            return "Removed"
        case .changed:
            return "Changed"
        case .unchanged:
            return "Unchanged"
        }
    }

    private func changeColor(for item: DomainDiffItem) -> Color {
        if item.changeType == .unchanged {
            return .secondary
        }

        switch item.severity {
        case .low:
            return .blue
        case .medium:
            return .yellow
        case .high:
            return .red
        }
    }

    private func sectionColor(_ section: DomainDiffSection) -> Color {
        switch section.severity {
        case .low:
            return .blue
        case .medium:
            return .yellow
        case .high:
            return .red
        }
    }

    private func binding(for section: DomainDiffSection) -> Binding<Bool> {
        Binding(
            get: { !collapsedSections.contains(section.id) },
            set: { isExpanded in
                if isExpanded {
                    collapsedSections.remove(section.id)
                } else {
                    collapsedSections.insert(section.id)
                }
            }
        )
    }
}

struct TrackedDomainDetailHeaderView: View {
    let trackedDomain: TrackedDomain

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let note = trackedDomain.note?.nilIfEmpty {
                LabeledValueRow(row: InfoRowViewData(label: "Tracking Note", value: note, tone: .secondary))
            }
            HStack(spacing: 8) {
                if trackedDomain.isPinned {
                    Label("Pinned", systemImage: "pin.fill")
                }
                Text("Last refresh \(trackedDomain.updatedAt.formatted(date: .abbreviated, time: .shortened))")
            }
            .font(.system(.caption2, design: .monospaced))
            .foregroundStyle(.secondary)
        }
    }
}

struct DomainSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let rows: [InfoRowViewData]
    let suggestions: [DomainSuggestionViewData]
    let showSuggestions: Bool
    let availabilityLoading: Bool
    let suggestionsLoading: Bool
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let snapshotNote: String?
    let trackedDomain: TrackedDomain?
    let trackingLimitMessage: String?
    let onTrack: () -> Void
    let onTogglePinned: () -> Void
    let onEditNote: (() -> Void)?

    var body: some View {
        CollapsibleSectionView(title: "Domain", isCollapsed: $isCollapsed) {
            if let trackedDomain {
                HStack(spacing: 8) {
                    AppStatusBadgeView(model: .init(title: "Tracked", systemImage: "eye.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16)))
                    Button {
                        onTogglePinned()
                    } label: {
                        Image(systemName: trackedDomain.isPinned ? "pin.fill" : "pin")
                    }
                    .buttonStyle(.bordered)
                    .font(appDensity.font(.caption))
                    if let onEditNote {
                        Button("Note") {
                            onEditNote()
                        }
                        .buttonStyle(.bordered)
                        .font(appDensity.font(.caption))
                    }
                }
            } else {
                Button("Track") {
                    AppHaptics.track()
                    onTrack()
                }
                .buttonStyle(.bordered)
                .font(appDensity.font(.caption))
            }
        } content: {
            CardView(allowsHorizontalScroll: false) {
                SectionTrustMetadataView(
                    provenance: provenance,
                    confidence: confidence,
                    note: snapshotNote == nil ? nil : "Audit note present"
                )
                ForEach(rows) { row in
                    LabeledValueRow(row: row)
                }
                if let trackedDomain {
                    TrackedDomainDetailHeaderView(trackedDomain: trackedDomain)
                        .padding(.top, 4)
                } else if let trackingLimitMessage {
                    MessageRowView(text: trackingLimitMessage, isError: false)
                        .padding(.top, 4)
                }
                if availabilityLoading {
                    ProgressView("Checking availability…")
                        .appLoadingStyle()
                        .padding(.top, 4)
                }
                if showSuggestions {
                    Text("Suggestions")
                        .font(appDensity.font(.caption))
                        .foregroundStyle(.secondary)
                        .padding(.top, 4)
                    if suggestionsLoading {
                        ProgressView("Checking alternatives…")
                            .appLoadingStyle()
                    } else if suggestions.isEmpty {
                        MessageRowView(text: "No suggestions", isError: false)
                    } else {
                        ForEach(suggestions) { suggestion in
                            HStack {
                                Text(suggestion.domain)
                                    .font(appDensity.font(.caption))
                                    .foregroundStyle(.primary)
                                    .textSelection(.enabled)
                                Spacer()
                                AppStatusBadgeView(model: AppStatusFactory.availability(suggestion.availabilityStatus))
                            }
                        }
                    }
                }
            }
        }
    }
}

struct OwnershipSectionView: View {
    @Binding var isCollapsed: Bool
    let rows: [InfoRowViewData]
    let loading: Bool
    let error: String?
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let showsHistoryPlaceholder: Bool

    var body: some View {
        CollapsibleSectionView(title: "Ownership", isCollapsed: $isCollapsed) {
            CardView(allowsHorizontalScroll: false) {
                SectionTrustMetadataView(provenance: provenance, confidence: confidence)
                if loading {
                    ProgressView("Fetching RDAP ownership…")
                        .appLoadingStyle()
                } else {
                    ForEach(rows) { row in
                        LabeledValueRow(row: row)
                    }
                    if let error, rows.allSatisfy({ $0.value == "Unavailable" }) {
                        MessageRowView(text: error, isError: error != "Unavailable")
                            .padding(.top, 4)
                    }
                    if showsHistoryPlaceholder {
                        MessageRowView(text: "Ownership history (coming soon)", isError: false)
                            .padding(.top, 4)
                    }
                }
            }
        }
    }
}

struct SubdomainsSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let rows: [SubdomainRowViewData]
    let loading: Bool
    let error: String?
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let showsExtendedPlaceholder: Bool

    var body: some View {
        CollapsibleSectionView(title: "Subdomains", isCollapsed: $isCollapsed, subtitle: "\(rows.count) found") {
            CardView(allowsHorizontalScroll: false) {
                SectionTrustMetadataView(provenance: provenance, confidence: confidence)
                if loading {
                    ProgressView("Checking certificate transparency…")
                        .appLoadingStyle()
                } else if rows.isEmpty {
                    MessageRowView(text: error ?? "No passive subdomains found", isError: false)
                    if showsExtendedPlaceholder {
                        MessageRowView(text: "Extended subdomain discovery (Data+)", isError: false)
                            .padding(.top, 4)
                    }
                } else {
                    ForEach(rows) { row in
                        HStack(spacing: 8) {
                            Text(row.hostname)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                            Spacer()
                            if row.isInteresting {
                                Text("Interesting")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.yellow)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 4)
                                    .background(Color.yellow.opacity(0.14))
                                    .clipShape(Capsule())
                            }
                        }
                    }
                    if showsExtendedPlaceholder {
                        MessageRowView(text: "Extended subdomain discovery (Data+)", isError: false)
                            .padding(.top, 4)
                    }
                }
            }
        }
    }
}

struct DNSSectionView: View {
    @Binding var isCollapsed: Bool
    let dnssecLabel: String?
    let sections: [DNSRecordSectionViewData]
    let ptrMessage: SectionMessageViewData?
    let loading: Bool
    let dnsProvenance: SectionProvenance?
    let ptrProvenance: SectionProvenance?
    let sectionError: String?

    var body: some View {
        CollapsibleSectionView(title: "DNS", isCollapsed: $isCollapsed, subtitle: dnssecLabel) {
            if loading {
                LoadingCardView(text: "Querying DNS…")
            } else if let sectionError, sections.isEmpty {
                MessageCardView(text: sectionError, isError: true)
            } else {
                if dnsProvenance != nil {
                    CardView(allowsHorizontalScroll: false) {
                        SectionTrustMetadataView(provenance: dnsProvenance, confidence: nil)
                    }
                }
                ForEach(sections) { section in
                    CardView {
                        Text(section.title)
                            .font(.system(.subheadline, design: .monospaced))
                            .fontWeight(.semibold)
                            .foregroundStyle(.cyan)

                        if let message = section.message {
                            MessageRowView(text: message.text, isError: message.isError)
                        }

                        ForEach(section.rows) { row in
                            LabeledValueRow(row: row)
                        }

                        if let wildcardTitle = section.wildcardTitle {
                            Text(wildcardTitle)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .padding(.top, 4)
                            ForEach(section.wildcardRows) { row in
                                LabeledValueRow(row: row)
                            }
                        }
                    }
                }

                if let ptrMessage {
                    CardView {
                        Text("PTR")
                            .font(.system(.subheadline, design: .monospaced))
                            .fontWeight(.semibold)
                            .foregroundStyle(.cyan)
                        SectionTrustMetadataView(provenance: ptrProvenance, confidence: nil)
                        MessageRowView(text: ptrMessage.text, isError: ptrMessage.isError)
                    }
                }
            }
        }
    }
}

struct WebSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let certificateRows: [InfoRowViewData]
    let sslInfo: SSLCertificateInfo?
    let sslLoading: Bool
    let sslError: String?
    let tlsProvenance: SectionProvenance?
    let responseRows: [InfoRowViewData]
    let headers: [HTTPHeader]
    let headersLoading: Bool
    let headersError: String?
    let httpProvenance: SectionProvenance?
    let redirects: [RedirectHopViewData]
    let redirectLoading: Bool
    let redirectError: String?
    let redirectProvenance: SectionProvenance?
    let finalURL: String?

    var body: some View {
        CollapsibleSectionView(title: "Web", isCollapsed: $isCollapsed) {
            CardView {
                HStack {
                    Text("TLS")
                        .font(appDensity.font(.subheadline, weight: .semibold))
                        .foregroundStyle(.cyan)
                    Spacer()
                    AppStatusBadgeView(model: AppStatusFactory.tls(sslInfo: sslInfo, error: sslError))
                }
                SectionTrustMetadataView(provenance: tlsProvenance, confidence: nil)
                if sslLoading {
                    ProgressView("Checking certificate…")
                        .appLoadingStyle()
                } else if let sslError {
                    MessageRowView(text: sslError, isError: true)
                } else {
                    ForEach(certificateRows) { row in
                        LabeledValueRow(row: row)
                    }
                    if let sslInfo, !sslInfo.subjectAltNames.isEmpty {
                        Text("SANs")
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                        ForEach(sslInfo.subjectAltNames, id: \.self) { san in
                            HStack(spacing: 8) {
                                Text(san)
                                    .font(appDensity.font(.caption))
                                    .textSelection(.enabled)
                                Spacer()
                                AppCopyButton(value: san, label: "Copy certificate SAN")
                            }
                        }
                    }
                }
            }

            CardView {
                Text("Headers")
                    .font(appDensity.font(.subheadline, weight: .semibold))
                    .foregroundStyle(.cyan)
                SectionTrustMetadataView(provenance: httpProvenance, confidence: nil)
                if headersLoading {
                    ProgressView("Fetching headers…")
                        .appLoadingStyle()
                } else if let headersError {
                    MessageRowView(text: headersError, isError: true)
                } else {
                    ForEach(responseRows) { row in
                        LabeledValueRow(row: row)
                    }
                    if headers.isEmpty {
                        MessageRowView(text: "No HTTP headers returned", isError: false)
                    } else {
                        ForEach(headers) { header in
                            HStack(alignment: .top, spacing: 4) {
                                Text(header.name + ":")
                                    .font(appDensity.font(.caption))
                                    .foregroundStyle(header.isSecurityHeader ? .yellow : .cyan)
                                Text(header.value)
                                    .font(appDensity.font(.caption))
                                    .foregroundStyle(.primary)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
            }

            CardView {
                HStack {
                    Text("Redirects")
                        .font(appDensity.font(.subheadline, weight: .semibold))
                        .foregroundStyle(.cyan)
                    Spacer()
                    if let finalURL {
                        AppCopyButton(value: finalURL, label: "Copy redirect URL")
                    }
                }
                SectionTrustMetadataView(provenance: redirectProvenance, confidence: nil)
                if redirectLoading {
                    ProgressView("Tracing redirects…")
                        .appLoadingStyle()
                } else if let redirectError {
                    MessageRowView(text: redirectError, isError: true)
                } else if redirects.isEmpty {
                    MessageRowView(text: "No redirect data available", isError: false)
                } else {
                    if let finalURL {
                        LabeledValueRow(row: InfoRowViewData(label: "Final URL", value: finalURL, tone: .secondary))
                    }
                    ForEach(redirects) { redirect in
                        HStack(alignment: .top, spacing: 6) {
                            Text(redirect.stepLabel)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.secondary)
                                .frame(width: 16, alignment: .trailing)
                            Text(redirect.statusCode)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.cyan)
                                .frame(width: 36, alignment: .leading)
                            Text(redirect.url)
                                .font(appDensity.font(.caption))
                                .textSelection(.enabled)
                            AppCopyButton(value: redirect.url, label: "Copy redirect URL")
                            if redirect.isFinal {
                                Text("(final)")
                                    .font(appDensity.font(.caption2))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }
}

struct EmailSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let rows: [EmailRowViewData]
    let loading: Bool
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let error: String?

    var body: some View {
        CollapsibleSectionView(title: "Email", isCollapsed: $isCollapsed) {
            CardView {
                SectionTrustMetadataView(provenance: provenance, confidence: confidence)
                HStack {
                    Spacer()
                    AppStatusBadgeView(model: AppStatusFactory.email(nil, error: error))
                        .opacity(loading ? 0 : 1)
                }
                if loading {
                    ProgressView("Checking email records…")
                        .appLoadingStyle()
                } else if let error {
                    MessageRowView(text: error, isError: true)
                } else if rows.isEmpty {
                    MessageRowView(text: "No email security records found", isError: false)
                } else {
                    ForEach(rows) { row in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 8) {
                                Text(row.label)
                                    .font(appDensity.font(.caption))
                                    .foregroundStyle(.cyan)
                                    .frame(width: 76, alignment: .leading)
                                AppStatusBadgeView(model: emailRowBadge(row))
                            }
                            Text(row.detail)
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                            if let auxiliaryDetail = row.auxiliaryDetail {
                                Text(auxiliaryDetail)
                                    .font(appDensity.font(.caption2))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }

    private func emailRowBadge(_ row: EmailRowViewData) -> AppStatusBadgeModel {
        switch row.statusTone {
        case .success:
            return .init(title: row.status, systemImage: "checkmark.shield.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        case .warning:
            return .init(title: row.status, systemImage: "shield.lefthalf.filled", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        case .failure:
            return .init(title: row.status, systemImage: "minus.circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        case .primary, .secondary:
            return .init(title: row.status, systemImage: "circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }
    }
}

struct NetworkSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let reachabilityRows: [ReachabilityRowViewData]
    let reachabilityLoading: Bool
    let reachabilityError: String?
    let reachabilityProvenance: SectionProvenance?
    let locationRows: [InfoRowViewData]
    let geolocation: IPGeolocation?
    let geolocationLoading: Bool
    let geolocationError: String?
    let geolocationProvenance: SectionProvenance?
    let geolocationConfidence: ConfidenceLevel?
    let standardPortRows: [PortScanRowViewData]
    let customPortRows: [PortScanRowViewData]
    let portScanLoading: Bool
    let portScanError: String?
    let portScanProvenance: SectionProvenance?
    let customPortScanLoading: Bool
    let customPortScanError: String?
    let isCloudflareProxied: Bool
    @Binding var customPortsExpanded: Bool
    @Binding var customPortInput: String
    let onScanCustomPorts: () -> Void

    var body: some View {
        CollapsibleSectionView(title: "Network", isCollapsed: $isCollapsed) {
            CardView {
                Text("Reachability")
                    .font(appDensity.font(.subheadline, weight: .semibold))
                    .foregroundStyle(.cyan)
                SectionTrustMetadataView(provenance: reachabilityProvenance, confidence: nil)
                if reachabilityLoading {
                    ProgressView("Checking ports…")
                        .appLoadingStyle()
                } else if let reachabilityError {
                    MessageRowView(text: reachabilityError, isError: true)
                } else {
                    ForEach(reachabilityRows) { row in
                        HStack {
                            Text(row.portLabel)
                                .font(appDensity.font(.caption))
                            Spacer()
                            Text(row.latencyLabel)
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(.secondary)
                            AppStatusBadgeView(model: reachabilityBadge(row))
                        }
                    }
                }
            }

            CardView(allowsHorizontalScroll: false) {
                Text("Location")
                    .font(appDensity.font(.subheadline, weight: .semibold))
                    .foregroundStyle(.cyan)
                SectionTrustMetadataView(provenance: geolocationProvenance, confidence: geolocationConfidence)
                if geolocationLoading {
                    ProgressView("Looking up location…")
                        .appLoadingStyle()
                } else if let geolocationError, geolocation == nil {
                    MessageRowView(text: geolocationError, isError: geolocationError != "No A record available")
                } else if let geolocation {
                    ForEach(locationRows) { row in
                        LabeledValueRow(row: row)
                    }
                    if let latitude = geolocation.latitude, let longitude = geolocation.longitude {
                        let coordinate = CLLocationCoordinate2D(latitude: latitude, longitude: longitude)
                        Map(initialPosition: .region(MKCoordinateRegion(
                            center: coordinate,
                            span: MKCoordinateSpan(latitudeDelta: 1, longitudeDelta: 1)
                        ))) {
                            Marker(geolocation.ip, coordinate: coordinate)
                        }
                        .mapStyle(.standard)
                        .frame(maxWidth: .infinity)
                        .frame(height: 180)
                        .cornerRadius(8)
                    }
                } else {
                    MessageRowView(text: "No location data available", isError: false)
                }
            }

            CardView(allowsHorizontalScroll: false) {
                Text("Port Scan")
                    .font(appDensity.font(.subheadline, weight: .semibold))
                    .foregroundStyle(.cyan)
                SectionTrustMetadataView(provenance: portScanProvenance, confidence: nil)

                if isCloudflareProxied {
                    Text("Domain is behind Cloudflare's proxy. Results reflect the edge, not the origin.")
                        .font(appDensity.font(.caption2))
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if portScanLoading {
                    ProgressView("Scanning ports…")
                        .appLoadingStyle()
                } else if let portScanError, standardPortRows.isEmpty {
                    MessageRowView(text: portScanError, isError: true)
                } else {
                    Text("Standard Ports")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    PortRowsView(rows: standardPortRows)
                }

                DisclosureGroup("Custom Ports", isExpanded: $customPortsExpanded) {
                    VStack(alignment: .leading, spacing: 10) {
                        TextField("8888, 9000, 27017", text: $customPortInput)
                            .font(appDensity.font(.caption))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.numberPad)
                            .padding(10)
                            .background(Color(.systemGray6).opacity(0.5))
                            .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))

                        Button("Scan") {
                            AppHaptics.refresh()
                            onScanCustomPorts()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(customPortScanLoading)

                        if customPortScanLoading {
                            ProgressView("Scanning custom ports…")
                                .appLoadingStyle()
                        } else if let customPortScanError {
                            MessageRowView(text: customPortScanError, isError: true)
                        } else {
                            PortRowsView(rows: customPortRows)
                        }
                    }
                    .padding(.top, 8)
                }
                .font(.system(.caption, design: .monospaced))
                .tint(.secondary)
            }
        }
    }

    private func reachabilityBadge(_ row: ReachabilityRowViewData) -> AppStatusBadgeModel {
        switch row.statusTone {
        case .success:
            return .init(title: row.statusLabel, systemImage: "checkmark.circle.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        case .warning:
            return .init(title: row.statusLabel, systemImage: "exclamationmark.triangle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        case .failure:
            return .init(title: row.statusLabel, systemImage: "xmark.circle.fill", foregroundColor: .red, backgroundColor: .red.opacity(0.16))
        case .primary, .secondary:
            return .init(title: row.statusLabel, systemImage: "circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }
    }
}

struct PortRowsView: View {
    @Environment(\.appDensity) private var appDensity
    let rows: [PortScanRowViewData]

    var body: some View {
        if rows.isEmpty {
            MessageRowView(text: "No results", isError: false)
        } else {
            ForEach(rows) { row in
                VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing - 1) {
                    HStack {
                        Text(row.portLabel)
                            .font(appDensity.font(.caption))
                            .frame(width: 52, alignment: .leading)
                        Text(row.service)
                            .font(appDensity.font(.caption))
                            .foregroundStyle(.primary)
                        Spacer()
                        if let durationLabel = row.durationLabel {
                            Text(durationLabel)
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(.secondary)
                        }
                        AppStatusBadgeView(model: portBadge(row))
                    }
                    if let banner = row.banner {
                        Text(banner)
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                            .padding(.leading, 8)
                    }
                }
                .frame(minHeight: appDensity.metrics.rowMinHeight, alignment: .topLeading)
            }
        }
    }

    private func portBadge(_ row: PortScanRowViewData) -> AppStatusBadgeModel {
        switch row.statusTone {
        case .success:
            return .init(title: row.statusLabel, systemImage: "checkmark.circle.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        case .warning:
            return .init(title: row.statusLabel, systemImage: "exclamationmark.triangle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        case .failure:
            return .init(title: row.statusLabel, systemImage: "xmark.circle.fill", foregroundColor: .red, backgroundColor: .red.opacity(0.16))
        case .primary, .secondary:
            return .init(title: row.statusLabel, systemImage: "circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }
    }
}

struct SectionTitleView: View {
    @Environment(\.appDensity) private var appDensity
    let title: String

    var body: some View {
        Text(title)
            .font(appDensity.font(.headline, design: .default, weight: .semibold))
            .foregroundStyle(.white)
    }
}

struct CardView<Content: View>: View {
    @Environment(\.appDensity) private var appDensity
    let allowsHorizontalScroll: Bool
    let content: Content

    init(allowsHorizontalScroll: Bool = true, @ViewBuilder content: () -> Content) {
        self.allowsHorizontalScroll = allowsHorizontalScroll
        self.content = content()
    }

    var body: some View {
        Group {
            if allowsHorizontalScroll {
                ScrollView(.horizontal) {
                    cardContent
                        .scrollTargetLayout()
                }
                .scrollBounceBehavior(.basedOnSize, axes: .horizontal)
            } else {
                cardContent
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(appDensity.metrics.cardPadding)
        .background(Color(.systemGray6).opacity(0.5))
        .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
    }

    private var cardContent: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            content
        }
    }
}

struct LoadingCardView: View {
    let text: String

    var body: some View {
        CardView {
            ProgressView(text)
                .appLoadingStyle()
                .frame(maxWidth: .infinity, alignment: .center)
        }
    }
}

struct MessageCardView: View {
    let text: String
    let isError: Bool

    var body: some View {
        CardView {
            MessageRowView(text: text, isError: isError)
        }
    }
}

struct MessageRowView: View {
    @Environment(\.appDensity) private var appDensity
    let text: String
    let isError: Bool

    var body: some View {
        Label(text, systemImage: isError ? "exclamationmark.triangle.fill" : "info.circle")
            .font(appDensity.font(.caption))
            .foregroundStyle(isError ? .red : .secondary)
    }
}

struct SectionTrustMetadataView: View {
    @Environment(\.appDensity) private var appDensity
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let note: String?

    init(provenance: SectionProvenance?, confidence: ConfidenceLevel?, note: String? = nil) {
        self.provenance = provenance
        self.confidence = confidence
        self.note = note
    }

    var body: some View {
        if provenance != nil || confidence != nil || note != nil {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    if let confidence {
                        Text("Confidence \(confidence.title)")
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                    }
                    if let provenance {
                        Text(provenance.provider ?? provenance.source)
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                        Text(provenance.resultSource.label)
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                    }
                }
                DisclosureGroup("Details") {
                    VStack(alignment: .leading, spacing: 4) {
                        if let provenance {
                            LabeledValueRow(row: .init(label: "Method", value: provenance.source, tone: .secondary))
                            if let provider = provenance.provider {
                                LabeledValueRow(row: .init(label: "Provider", value: provider, tone: .secondary))
                            }
                            if let resolver = provenance.resolver {
                                LabeledValueRow(row: .init(label: "Resolver", value: resolver, tone: .secondary))
                            }
                            LabeledValueRow(row: .init(label: "Collected", value: provenance.collectedAt.formatted(date: .abbreviated, time: .shortened), tone: .secondary))
                            LabeledValueRow(row: .init(label: "Mode", value: provenance.resultSource.label, tone: .secondary))
                        }
                        if let note {
                            LabeledValueRow(row: .init(label: "Note", value: note, tone: .secondary))
                        }
                    }
                    .padding(.top, 4)
                }
                .font(appDensity.font(.caption))
                .tint(.secondary)
            }
        }
    }
}

struct LabeledValueRow: View {
    @Environment(\.appDensity) private var appDensity
    let row: InfoRowViewData

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing - 1) {
            HStack(alignment: .top, spacing: 8) {
                VStack(alignment: .leading, spacing: appDensity.metrics.rowSpacing - 1) {
                    Text(row.label)
                        .font(appDensity.font(.caption2))
                        .foregroundStyle(.secondary)
                    Text(row.value)
                        .font(appDensity.font(.caption))
                        .foregroundStyle(ResultColors.color(for: row.tone))
                        .textSelection(.enabled)
                }
                Spacer(minLength: 6)
                if !row.value.isEmpty, row.value != "Unavailable" {
                    AppCopyButton(value: row.value, label: "Copy \(row.label)")
                }
            }
        }
        .frame(minHeight: appDensity.metrics.rowMinHeight, alignment: .topLeading)
    }
}

enum ResultColors {
    static func color(for tone: ResultTone) -> Color {
        switch tone {
        case .primary:
            return .primary
        case .secondary:
            return .secondary
        case .success:
            return .green
        case .warning:
            return .yellow
        case .failure:
            return .red
        }
    }
}

extension DateFormatter {
    static let certDate: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()
}

private extension View {
    func appLoadingStyle() -> some View {
        font(.system(.caption, design: .monospaced))
    }
}

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

private struct SettingsView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    @AppStorage(DNSResolverOption.userDefaultsKey)
    private var storedResolverURL = DNSResolverOption.defaultURLString
    @AppStorage(AppDensity.userDefaultsKey)
    private var storedDensity = AppDensity.compact.rawValue

    @State private var resolverOption: DNSResolverOption = .cloudflare
    @State private var customResolverURL = DNSResolverOption.defaultURLString
    @State private var showClearHistoryConfirmation = false
    @State private var showClearCacheConfirmation = false

    private var customResolverError: String? {
        guard resolverOption == .custom else {
            return nil
        }
        return DNSResolverOption.isValidCustomURL(customResolverURL) ? nil : "Resolver URL must start with https://"
    }

    var body: some View {
        Form {
            Section("Display") {
                Picker("Density", selection: $storedDensity) {
                    ForEach(AppDensity.allCases) { density in
                        Text(density.title).tag(density.rawValue)
                    }
                }
            }

            Section("Network") {
                Picker("Resolver", selection: $resolverOption) {
                    ForEach(DNSResolverOption.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }

                if resolverOption == .custom {
                    TextField("https://resolver.example/dns-query", text: $customResolverURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)

                    if let customResolverError {
                        Text(customResolverError)
                            .font(appDensity.font(.caption, design: .default))
                            .foregroundStyle(.red)
                    }
                }
            }

            Section("Data") {
                Button("Clear History", role: .destructive) {
                    showClearHistoryConfirmation = true
                }

                Button("Clear Cache", role: .destructive) {
                    showClearCacheConfirmation = true
                }
            }

            Section("About") {
                LabeledContent("Version", value: appVersion)
                LabeledContent("Storage", value: "Local-only")
            }
        }
        .navigationTitle("Settings")
        .alert("Clear history?", isPresented: $showClearHistoryConfirmation) {
            Button("Clear", role: .destructive) {
                viewModel.clearHistory()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes saved lookup snapshots from this device.")
        }
        .alert("Clear cache?", isPresented: $showClearCacheConfirmation) {
            Button("Clear", role: .destructive) {
                viewModel.clearLookupCache()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This clears the in-memory lookup cache and cancels any cached in-flight work.")
        }
        .onAppear {
            let currentResolverURL = storedResolverURL.trimmingCharacters(in: .whitespacesAndNewlines)
            resolverOption = DNSResolverOption.option(for: currentResolverURL)
            customResolverURL = resolverOption == .custom ? currentResolverURL : DNSResolverOption.defaultURLString
        }
        .onChange(of: resolverOption) { _, newValue in
            guard let presetURL = newValue.urlString else {
                storedResolverURL = customResolverURL.trimmingCharacters(in: .whitespacesAndNewlines)
                return
            }
            storedResolverURL = presetURL
        }
        .onChange(of: customResolverURL) { _, newValue in
            guard resolverOption == .custom else { return }
            storedResolverURL = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private var appVersion: String {
        AppVersion.current
    }
}

#Preview {
    ContentView()
}
