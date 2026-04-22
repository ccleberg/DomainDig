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

private struct WorkflowNavigationTarget: Hashable {
    let workflowID: UUID
}

struct ContentView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    @State private var purchaseService = PurchaseService.shared
    @State private var navigationPath = NavigationPath()
    @FocusState private var domainFieldFocused: Bool
    @State private var customPortInput = ""
    @State private var customPortsExpanded = false
    @State private var trackingNoteDraft = ""
    @State private var editingTrackedDomain: TrackedDomain?
    @State private var inputMode: LookupInputMode = .single
    @State private var collapsedSections: Set<ResultSection> = [.network]
    @State private var showingCurrentDomainWorkflowSheet = false
    @State private var showingBatchWorkflowSheet = false

    var body: some View {
        let _ = purchaseService.currentTier

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
                            if let report = viewModel.currentReport {
                                RiskSummaryCardView(report: report)
                                    .padding(.top, appDensity.metrics.cardSpacing)
                                InsightsSummaryCardView(insights: report.insights)
                                    .padding(.top, appDensity.metrics.cardSpacing)
                            }
                            if let changeSummary = viewModel.currentChangeSummary {
                                DomainChangeSummaryView(summary: changeSummary)
                                    .padding(.top, appDensity.metrics.cardSpacing)
                            }
                        }
                        domainOverviewSection
                            .padding(.top, appDensity.metrics.sectionSpacing)
                        ownershipSection
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        subdomainsSection
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
                        dnsSection
                        .padding(.top, appDensity.metrics.sectionSpacing)
                        WebSectionView(
                            isCollapsed: sectionCollapsedBinding(.web),
                            certificateRows: viewModel.webCertificateRows,
                            sslInfo: viewModel.sslInfo,
                            tlsSummary: viewModel.currentTLSSummary,
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
                            assessment: viewModel.currentEmailAssessment,
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
                ToolbarItem(placement: .topBarTrailing) {
                    if viewModel.hasRun {
                        Button {
                            viewModel.reset()
                        } label: {
                            Image(systemName: "xmark.circle")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .navigationDestination(for: WorkflowNavigationTarget.self) { target in
                WorkflowDetailView(viewModel: viewModel, workflowID: target.workflowID)
            }
        }
        .onAppear {
            domainFieldFocused = true
        }
        .task {
            await viewModel.refreshUsageCredits()
        }
        .onChange(of: viewModel.searchedDomain) { _, _ in
            collapsedSections = defaultCollapsedSections
        }
        .onChange(of: viewModel.rerunNavigationToken) { _, _ in
            navigationPath = NavigationPath()
            domainFieldFocused = false
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
        .sheet(isPresented: $showingCurrentDomainWorkflowSheet) {
            WorkflowBulkAddSheet(
                viewModel: viewModel,
                title: "Add Domain to Workflow",
                availableDomains: [viewModel.searchedDomain]
            )
        }
        .sheet(isPresented: $showingBatchWorkflowSheet) {
            WorkflowBulkAddSheet(
                viewModel: viewModel,
                title: "Add Batch Domains",
                availableDomains: viewModel.batchResults.map(\.domain)
            )
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
                if FeatureAccessService.hasAccess(to: .batchOperations) {
                    VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
                        Text("Paste domains separated by new lines or commas.")
                            .font(appDensity.font(.caption))
                            .foregroundStyle(.secondary)

                        if let batchAllowanceSummary = FeatureAccessService.batchAllowanceSummary() {
                            Text(batchAllowanceSummary)
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(.secondary)
                        }

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
                } else {
                    lockedFeatureCard(
                        title: "Batch Operations",
                        message: FeatureAccessService.upgradeMessage(for: .batchOperations)
                    )
                }
            }
        }
        .padding(.vertical, appDensity.metrics.sectionSpacing)
    }

    private var domainOverviewSection: some View {
        let trackedDomain = viewModel.currentTrackedDomain
        let workflows = viewModel.currentDomainWorkflows

        return DomainSectionView(
            isCollapsed: sectionCollapsedBinding(.domain),
            rows: viewModel.domainRows,
            suggestions: viewModel.suggestionRows,
            showSuggestions: viewModel.availabilityResult?.status == .registered || viewModel.suggestionsLoading,
            availabilityLoading: viewModel.availabilityLoading,
            suggestionsLoading: viewModel.suggestionsLoading,
            provenance: viewModel.currentSnapshot.provenanceBySection[.availability],
            confidence: viewModel.currentSnapshot.availabilityConfidence,
            snapshotNote: viewModel.currentSnapshot.note,
            trackedDomain: trackedDomain,
            workflows: workflows,
            trackingLimitMessage: viewModel.trackingLimitMessage,
            pricingLoading: viewModel.domainPricingLoading,
            pricingError: viewModel.domainPricingError,
            showsPricingPlaceholder: !DataAccessService.hasAccess(to: .domainPricing),
            onTrack: {
                _ = viewModel.trackCurrentDomain()
            },
            onTogglePinned: {
                guard let trackedDomain else { return }
                viewModel.togglePinned(for: trackedDomain)
            },
            onEditNote: {
                guard let trackedDomain else { return }
                trackingNoteDraft = trackedDomain.note ?? ""
                editingTrackedDomain = trackedDomain
            },
            onAddToWorkflow: {
                showingCurrentDomainWorkflowSheet = true
            },
            onOpenWorkflow: { workflow in
                navigationPath.append(WorkflowNavigationTarget(workflowID: workflow.id))
            },
            onRunWorkflow: { workflow in
                viewModel.rerunCurrentDomain(in: workflow)
            }
        )
    }

    private var ownershipSection: some View {
        OwnershipSectionView(
            isCollapsed: sectionCollapsedBinding(.ownership),
            rows: viewModel.ownershipRows,
            loading: viewModel.ownershipLoading,
            error: viewModel.ownershipError,
            provenance: viewModel.currentSnapshot.provenanceBySection[.ownership],
            confidence: viewModel.currentSnapshot.ownershipConfidence,
            showsHistoryPlaceholder: !DataAccessService.hasAccess(to: .ownershipHistory),
            history: viewModel.ownershipHistory,
            historyLoading: viewModel.ownershipHistoryLoading,
            historyError: viewModel.ownershipHistoryError,
            historyCreditStatus: viewModel.ownershipHistoryCreditStatus,
            onLoadHistory: {
                Task {
                    await viewModel.loadOwnershipHistory()
                }
            }
        )
    }

    private var subdomainsSection: some View {
        SubdomainsSectionView(
            isCollapsed: sectionCollapsedBinding(.subdomains),
            rows: viewModel.subdomainRows,
            groups: viewModel.currentSubdomainGroups,
            loading: viewModel.subdomainsLoading,
            error: viewModel.subdomainsError,
            provenance: viewModel.currentSnapshot.provenanceBySection[.subdomains],
            confidence: viewModel.currentSnapshot.subdomainConfidence,
            showsExtendedPlaceholder: !DataAccessService.hasAccess(to: .extendedSubdomains),
            extendedCount: viewModel.extendedSubdomains.count,
            extendedLoading: viewModel.extendedSubdomainsLoading,
            extendedError: viewModel.extendedSubdomainsError,
            extendedCreditStatus: viewModel.extendedSubdomainsCreditStatus,
            onLoadExtended: {
                Task {
                    await viewModel.loadExtendedSubdomains()
                }
            }
        )
    }

    private var dnsSection: some View {
        DNSSectionView(
            isCollapsed: sectionCollapsedBinding(.dns),
            dnssecLabel: viewModel.dnssecLabel,
            patternSummary: viewModel.currentDNSPatterns,
            sections: viewModel.dnsRows,
            ptrMessage: viewModel.ptrMessage,
            loading: viewModel.dnsLoading || viewModel.ptrLoading,
            dnsProvenance: viewModel.currentSnapshot.provenanceBySection[.dns],
            ptrProvenance: viewModel.currentSnapshot.provenanceBySection[.ptr],
            sectionError: viewModel.dnsError,
            history: viewModel.dnsHistory,
            historyLoading: viewModel.dnsHistoryLoading,
            historyError: viewModel.dnsHistoryError,
            showsHistoryPlaceholder: !DataAccessService.hasAccess(to: .dnsHistory),
            historyCreditStatus: viewModel.dnsHistoryCreditStatus,
            onLoadHistory: {
                Task {
                    await viewModel.loadDNSHistory()
                }
            }
        )
    }

    private var actionButtons: some View {
        HStack {
            Spacer()
            if viewModel.resultsLoaded {
                Menu {
                    if !viewModel.isCurrentDomainTracked {
                        Button("Track this domain") {
                            _ = viewModel.trackCurrentDomain()
                        }
                    }
                    Button("Add to workflow") {
                        showingCurrentDomainWorkflowSheet = true
                    }
                    if FeatureAccessService.hasAccess(to: .advancedExports) {
                        Button("Copy report JSON") {
                            guard let json = viewModel.exportJSONString() else { return }
                            AppClipboard.copy(json)
                            AppHaptics.copy()
                        }
                    } else {
                        Button("Copy report JSON") {
                            viewModel.upgradePrompt = FeatureAccessService.upgradePrompt(for: .advancedExports)
                        }
                    }
                    Button("Export report") {
                        shareSingleResults(format: .text)
                    }
                } label: {
                    Image(systemName: "bolt.circle")
                        .font(appDensity.font(.body, design: .default))
                        .foregroundStyle(.secondary)
                }
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
                    if FeatureAccessService.hasAccess(to: .advancedExports) {
                        Button("Export CSV") {
                            shareSingleResults(format: .csv)
                        }
                        Button("Export JSON") {
                            shareSingleResults(format: .json)
                        }
                    } else {
                        Button("CSV Export • Available in Pro") {}
                            .disabled(true)
                        Button("JSON Export • Available in Pro") {}
                            .disabled(true)
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
                        Button("Add to Workflow") {
                            showingBatchWorkflowSheet = true
                        }
                        Divider()
                        Button("Export Batch TXT") {
                            shareBatchResults(format: .text)
                        }
                        if FeatureAccessService.hasAccess(to: .advancedExports) {
                            Button("Export Batch CSV") {
                                shareBatchResults(format: .csv)
                            }
                            Button("Export Batch JSON") {
                                shareBatchResults(format: .json)
                            }
                        } else {
                            Button("Batch CSV • Available in Pro") {}
                                .disabled(true)
                            Button("Batch JSON • Available in Pro") {}
                                .disabled(true)
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

    private func lockedFeatureCard(title: String, message: String) -> some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            Text(title)
                .font(appDensity.font(.headline, design: .default, weight: .semibold))
            Text(message)
                .font(appDensity.font(.callout, design: .default))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(appDensity.metrics.cardPadding)
        .background(Color(.systemGray6))
        .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
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

struct RiskSummaryCardView: View {
    @Environment(\.appDensity) private var appDensity
    let report: DomainReport

    private var topFactors: [RiskFactor] {
        Array(report.riskAssessment.factors.prefix(3))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            SectionTitleView(title: "Risk")
            CardView(allowsHorizontalScroll: false) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(report.riskAssessment.score)")
                            .font(appDensity.font(.largeTitle, weight: .bold))
                            .foregroundStyle(levelColor)
                        Text(report.riskAssessment.level.title)
                            .font(appDensity.font(.caption))
                            .foregroundStyle(levelColor)
                    }
                    Spacer()
                    Text("Deterministic")
                        .font(appDensity.font(.caption2))
                        .foregroundStyle(.secondary)
                }

                if topFactors.isEmpty {
                    Text("No major risk factors identified")
                        .font(appDensity.font(.caption))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(topFactors.enumerated()), id: \.offset) { _, factor in
                        HStack(alignment: .top, spacing: 8) {
                            Circle()
                                .fill(factorColor(factor.impact))
                                .frame(width: 8, height: 8)
                                .padding(.top, 5)
                            Text(factor.description)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.primary)
                        }
                    }
                }
            }
        }
    }

    private var levelColor: Color {
        switch report.riskAssessment.level {
        case .low:
            return .green
        case .medium:
            return .yellow
        case .high:
            return .red
        }
    }

    private func factorColor(_ impact: RiskImpact) -> Color {
        switch impact {
        case .positive:
            return .green
        case .neutral:
            return .secondary
        case .negative:
            return .red
        }
    }
}

struct InsightsSummaryCardView: View {
    @Environment(\.appDensity) private var appDensity
    let insights: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            SectionTitleView(title: "Insights")
            CardView(allowsHorizontalScroll: false) {
                if insights.isEmpty {
                    Text("No deterministic insights triggered")
                        .font(appDensity.font(.caption))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(insights.enumerated()), id: \.offset) { _, insight in
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "sparkline")
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(.cyan)
                                .padding(.top, 2)
                            Text(insight)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.primary)
                        }
                    }
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
                Text(summary.impactClassification.title.uppercased())
                    .font(appDensity.font(.caption2))
                    .foregroundStyle(impactColor(summary.impactClassification))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(impactColor(summary.impactClassification).opacity(0.16))
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

                        if let riskScoreDelta = summary.riskScoreDelta {
                            Text("Risk delta: \(riskScoreDelta >= 0 ? "+" : "")\(riskScoreDelta)")
                                .font(appDensity.font(.caption2))
                                .foregroundStyle(riskScoreDelta > 0 ? .orange : .secondary)
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

    private func impactColor(_ impact: ChangeImpactClassification) -> Color {
        switch impact {
        case .informational:
            return .secondary
        case .warning:
            return .yellow
        case .critical:
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
    let workflows: [DomainWorkflow]
    let trackingLimitMessage: String?
    let pricingLoading: Bool
    let pricingError: String?
    let showsPricingPlaceholder: Bool
    let onTrack: () -> Void
    let onTogglePinned: () -> Void
    let onEditNote: (() -> Void)?
    let onAddToWorkflow: (() -> Void)?
    let onOpenWorkflow: ((DomainWorkflow) -> Void)?
    let onRunWorkflow: ((DomainWorkflow) -> Void)?

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
                if let onAddToWorkflow {
                    Button {
                        onAddToWorkflow()
                    } label: {
                        Label("Add to workflow", systemImage: "plus.rectangle.on.folder")
                            .font(appDensity.font(.caption))
                    }
                    .buttonStyle(.bordered)
                    .padding(.top, 4)
                }
                if !workflows.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Part of workflow")
                            .font(appDensity.font(.caption))
                            .foregroundStyle(.secondary)

                        ForEach(workflows) { workflow in
                            HStack {
                                Text(workflow.name)
                                    .font(appDensity.font(.caption))
                                    .foregroundStyle(.primary)
                                Spacer()
                                if let onOpenWorkflow {
                                    Button("Open") {
                                        onOpenWorkflow(workflow)
                                    }
                                    .buttonStyle(.bordered)
                                    .font(appDensity.font(.caption2))
                                }
                                if let onRunWorkflow {
                                    Button("Run") {
                                        onRunWorkflow(workflow)
                                    }
                                    .buttonStyle(.bordered)
                                    .font(appDensity.font(.caption2))
                                }
                            }
                        }
                    }
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
                if pricingLoading {
                    ProgressView("Loading external pricing…")
                        .appLoadingStyle()
                        .padding(.top, 4)
                } else if let pricingError {
                    MessageRowView(text: pricingError, isError: false)
                        .padding(.top, 4)
                } else if showsPricingPlaceholder {
                    MessageRowView(text: "Pricing signals available in Data+", isError: false)
                        .padding(.top, 4)
                }
            }
        }
    }
}

struct OwnershipSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let rows: [InfoRowViewData]
    let loading: Bool
    let error: String?
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let showsHistoryPlaceholder: Bool
    let history: [DomainOwnershipHistoryEvent]
    let historyLoading: Bool
    let historyError: String?
    let historyCreditStatus: UsageCreditStatus?
    let onLoadHistory: (() -> Void)?

    init(
        isCollapsed: Binding<Bool>,
        rows: [InfoRowViewData],
        loading: Bool,
        error: String?,
        provenance: SectionProvenance?,
        confidence: ConfidenceLevel?,
        showsHistoryPlaceholder: Bool,
        history: [DomainOwnershipHistoryEvent] = [],
        historyLoading: Bool = false,
        historyError: String? = nil,
        historyCreditStatus: UsageCreditStatus? = nil,
        onLoadHistory: (() -> Void)? = nil
    ) {
        _isCollapsed = isCollapsed
        self.rows = rows
        self.loading = loading
        self.error = error
        self.provenance = provenance
        self.confidence = confidence
        self.showsHistoryPlaceholder = showsHistoryPlaceholder
        self.history = history
        self.historyLoading = historyLoading
        self.historyError = historyError
        self.historyCreditStatus = historyCreditStatus
        self.onLoadHistory = onLoadHistory
    }

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
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("History")
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.secondary)
                            Spacer()
                            if let historyCreditStatus, let onLoadHistory, history.isEmpty, !historyLoading, !showsHistoryPlaceholder {
                                Button("Load (\(historyCreditStatus.remaining) left)") {
                                    onLoadHistory()
                                }
                                .buttonStyle(.bordered)
                                .font(appDensity.font(.caption2))
                            }
                        }
                        if historyLoading {
                            ProgressView("Loading history…")
                                .appLoadingStyle()
                        } else if !history.isEmpty {
                            ForEach(history) { event in
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(event.date.formatted(date: .abbreviated, time: .omitted))
                                        .font(appDensity.font(.caption2))
                                        .foregroundStyle(.secondary)
                                    Text(event.summary)
                                        .font(appDensity.font(.caption))
                                    Text(event.source)
                                        .font(appDensity.font(.caption2))
                                        .foregroundStyle(.secondary)
                                }
                            }
                        } else if let historyError {
                            MessageRowView(text: historyError, isError: false)
                        } else if showsHistoryPlaceholder {
                            MessageRowView(text: "Ownership history available in Data+", isError: false)
                        }
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
    let groups: [SubdomainGroup]
    let loading: Bool
    let error: String?
    let provenance: SectionProvenance?
    let confidence: ConfidenceLevel?
    let showsExtendedPlaceholder: Bool
    let extendedCount: Int
    let extendedLoading: Bool
    let extendedError: String?
    let extendedCreditStatus: UsageCreditStatus?
    let onLoadExtended: (() -> Void)?

    init(
        isCollapsed: Binding<Bool>,
        rows: [SubdomainRowViewData],
        groups: [SubdomainGroup],
        loading: Bool,
        error: String?,
        provenance: SectionProvenance?,
        confidence: ConfidenceLevel?,
        showsExtendedPlaceholder: Bool,
        extendedCount: Int = 0,
        extendedLoading: Bool = false,
        extendedError: String? = nil,
        extendedCreditStatus: UsageCreditStatus? = nil,
        onLoadExtended: (() -> Void)? = nil
    ) {
        _isCollapsed = isCollapsed
        self.rows = rows
        self.groups = groups
        self.loading = loading
        self.error = error
        self.provenance = provenance
        self.confidence = confidence
        self.showsExtendedPlaceholder = showsExtendedPlaceholder
        self.extendedCount = extendedCount
        self.extendedLoading = extendedLoading
        self.extendedError = extendedError
        self.extendedCreditStatus = extendedCreditStatus
        self.onLoadExtended = onLoadExtended
    }

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
                        MessageRowView(text: "Extended subdomain discovery available in Data+", isError: false)
                            .padding(.top, 4)
                    }
                } else {
                    if let extendedCreditStatus, let onLoadExtended, extendedCount == 0, !extendedLoading, !showsExtendedPlaceholder {
                        Button("Load extended results (\(extendedCreditStatus.remaining) left)") {
                            onLoadExtended()
                        }
                        .buttonStyle(.bordered)
                        .font(appDensity.font(.caption2))
                    }
                    if !groups.isEmpty {
                        Text("Groups")
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                        ForEach(groups) { group in
                            HStack {
                                Text("\(group.label).*")
                                    .font(appDensity.font(.caption))
                                    .foregroundStyle(.cyan)
                                Spacer()
                                Text("\(group.subdomains.count)")
                                    .font(appDensity.font(.caption2))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
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
                    if extendedLoading {
                        ProgressView("Loading extended subdomains…")
                            .appLoadingStyle()
                            .padding(.top, 4)
                    } else if extendedCount > 0 {
                        MessageRowView(text: "\(extendedCount) extended results included", isError: false)
                            .padding(.top, 4)
                    } else if let extendedError {
                        MessageRowView(text: extendedError, isError: false)
                            .padding(.top, 4)
                    } else if showsExtendedPlaceholder {
                        MessageRowView(text: "Extended subdomain discovery available in Data+", isError: false)
                            .padding(.top, 4)
                    }
                }
            }
        }
    }
}

struct DNSSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let dnssecLabel: String?
    let patternSummary: DNSPatternSummary?
    let sections: [DNSRecordSectionViewData]
    let ptrMessage: SectionMessageViewData?
    let loading: Bool
    let dnsProvenance: SectionProvenance?
    let ptrProvenance: SectionProvenance?
    let sectionError: String?
    let history: [DNSHistoryEvent]
    let historyLoading: Bool
    let historyError: String?
    let showsHistoryPlaceholder: Bool
    let historyCreditStatus: UsageCreditStatus?
    let onLoadHistory: (() -> Void)?

    init(
        isCollapsed: Binding<Bool>,
        dnssecLabel: String?,
        patternSummary: DNSPatternSummary?,
        sections: [DNSRecordSectionViewData],
        ptrMessage: SectionMessageViewData?,
        loading: Bool,
        dnsProvenance: SectionProvenance?,
        ptrProvenance: SectionProvenance?,
        sectionError: String?,
        history: [DNSHistoryEvent] = [],
        historyLoading: Bool = false,
        historyError: String? = nil,
        showsHistoryPlaceholder: Bool = false,
        historyCreditStatus: UsageCreditStatus? = nil,
        onLoadHistory: (() -> Void)? = nil
    ) {
        _isCollapsed = isCollapsed
        self.dnssecLabel = dnssecLabel
        self.patternSummary = patternSummary
        self.sections = sections
        self.ptrMessage = ptrMessage
        self.loading = loading
        self.dnsProvenance = dnsProvenance
        self.ptrProvenance = ptrProvenance
        self.sectionError = sectionError
        self.history = history
        self.historyLoading = historyLoading
        self.historyError = historyError
        self.showsHistoryPlaceholder = showsHistoryPlaceholder
        self.historyCreditStatus = historyCreditStatus
        self.onLoadHistory = onLoadHistory
    }

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
                        if let patternSummary {
                            if !patternSummary.providers.isEmpty {
                                MessageRowView(text: "Providers: \(patternSummary.providers.joined(separator: ", "))", isError: false)
                            }
                            if !patternSummary.patterns.isEmpty {
                                ForEach(Array(patternSummary.patterns.enumerated()), id: \.offset) { _, pattern in
                                    MessageRowView(text: pattern, isError: false)
                                }
                            }
                        }
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

                CardView(allowsHorizontalScroll: false) {
                    HStack {
                        Text("History")
                            .font(appDensity.font(.subheadline, weight: .semibold))
                            .foregroundStyle(.cyan)
                        Spacer()
                        if let historyCreditStatus, let onLoadHistory, history.isEmpty, !historyLoading, !showsHistoryPlaceholder {
                            Button("Load (\(historyCreditStatus.remaining) left)") {
                                onLoadHistory()
                            }
                            .buttonStyle(.bordered)
                            .font(appDensity.font(.caption2))
                        }
                    }
                    if historyLoading {
                        ProgressView("Loading DNS history…")
                            .appLoadingStyle()
                    } else if !history.isEmpty {
                        ForEach(history) { event in
                            VStack(alignment: .leading, spacing: 3) {
                                Text(event.date.formatted(date: .abbreviated, time: .omitted))
                                    .font(appDensity.font(.caption2))
                                    .foregroundStyle(.secondary)
                                Text(event.summary)
                                    .font(appDensity.font(.caption))
                                if !event.aRecords.isEmpty {
                                    Text("A: \(event.aRecords.joined(separator: ", "))")
                                        .font(appDensity.font(.caption2))
                                        .foregroundStyle(.secondary)
                                }
                                if !event.nameservers.isEmpty {
                                    Text("NS: \(event.nameservers.joined(separator: ", "))")
                                        .font(appDensity.font(.caption2))
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    } else if let historyError {
                        MessageRowView(text: historyError, isError: false)
                    } else if showsHistoryPlaceholder {
                        MessageRowView(text: "DNS history available in Data+", isError: false)
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
    let tlsSummary: WebResultSummary?
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
                    if !sslLoading {
                        AppStatusBadgeView(model: AppStatusFactory.tls(sslInfo: sslInfo, error: sslError))
                    }
                }
                SectionTrustMetadataView(provenance: tlsProvenance, confidence: nil)
                if !sslLoading, let tlsSummary {
                    LabeledValueRow(row: InfoRowViewData(label: "TLS Grade", value: tlsSummary.tlsGrade.rawValue, tone: tlsSummary.tlsGrade == .a ? .success : (tlsSummary.tlsGrade == .f ? .failure : .warning)))
                    ForEach(Array(tlsSummary.tlsHighlights.enumerated()), id: \.offset) { _, highlight in
                        MessageRowView(text: highlight, isError: isTLSHighlightError(highlight))
                    }
                }
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
                            HStack(alignment: .top, spacing: 8) {
                                Text(san)
                                    .font(appDensity.font(.caption))
                                    .lineLimit(nil)
                                    .fixedSize(horizontal: false, vertical: true)
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

    private func isTLSHighlightError(_ highlight: String) -> Bool {
        let normalized = highlight.lowercased()
        if normalized.contains("no weak tls indicators were detected") {
            return false
        }
        return normalized.contains("expires")
            || normalized.contains("weak")
            || normalized.contains("tls 1.0")
            || normalized.contains("tls 1.1")
    }
}

struct EmailSectionView: View {
    @Environment(\.appDensity) private var appDensity
    @Binding var isCollapsed: Bool
    let rows: [EmailRowViewData]
    let assessment: EmailSecuritySummary?
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
                if let assessment, let grade = assessment.grade {
                    LabeledValueRow(row: InfoRowViewData(label: "Grade", value: grade.rawValue, tone: grade == .a ? .success : (grade == .f ? .failure : .warning)))
                    if !assessment.reasons.isEmpty {
                        Text(assessment.reasons.joined(separator: " | "))
                            .font(appDensity.font(.caption2))
                            .foregroundStyle(.secondary)
                    }
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
            .lineLimit(nil)
            .fixedSize(horizontal: false, vertical: true)
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
                        .lineLimit(nil)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .layoutPriority(1)
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

struct SettingsView: View {
    @Environment(\.appDensity) private var appDensity
    @Bindable var viewModel: DomainViewModel
    @State private var purchaseService = PurchaseService.shared
    @AppStorage(DNSResolverOption.userDefaultsKey)
    private var storedResolverURL = DNSResolverOption.defaultURLString
    @AppStorage(AppDensity.userDefaultsKey)
    private var storedDensity = AppDensity.compact.rawValue

    @State private var resolverOption: DNSResolverOption = .cloudflare
    @State private var customResolverURL = DNSResolverOption.defaultURLString
    @State private var showClearHistoryConfirmation = false
    @State private var showClearCacheConfirmation = false
    @State private var showClearWorkflowsConfirmation = false
    @State private var showClearTrackedDomainsConfirmation = false

    private var customResolverError: String? {
        guard resolverOption == .custom else {
            return nil
        }
        return DNSResolverOption.isValidCustomURL(customResolverURL) ? nil : "Resolver URL must start with https://"
    }

    var body: some View {
        let _ = purchaseService.currentTier

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

                Button("Clear Workflows", role: .destructive) {
                    showClearWorkflowsConfirmation = true
                }

                Button("Clear Tracked Domains", role: .destructive) {
                    showClearTrackedDomainsConfirmation = true
                }
            }

            Section("Tier") {
                LabeledContent("Status", value: purchaseService.currentTier.title)

                if purchaseService.currentTier == .free {
                    Button("Upgrade") {
                        viewModel.isPaywallPresented = true
                    }
                } else {
                    Button("Manage Subscription") {
                        Task {
                            await purchaseService.manageSubscription()
                        }
                    }
                }

                Button(purchaseService.isRestoring ? "Restoring…" : "Restore Purchases") {
                    Task {
                        await purchaseService.restorePurchases()
                    }
                }
                .disabled(purchaseService.isRestoring || purchaseService.isPurchasing)

                if let statusMessage = purchaseService.statusMessage {
                    Text(statusMessage)
                        .font(appDensity.font(.caption, design: .default))
                        .foregroundStyle(.secondary)
                }

                if let errorMessage = purchaseService.errorMessage {
                    Text(errorMessage)
                        .font(appDensity.font(.caption, design: .default))
                        .foregroundStyle(.red)
                }
            }

            Section("Data+ Usage") {
                ForEach(UsageCreditFeature.allCases) { feature in
                    let status = viewModel.usageCredits[feature] ?? UsageCreditStatus(
                        feature: feature,
                        remaining: feature.defaultAllowance,
                        total: feature.defaultAllowance,
                        resetContext: "Resets with app version \(AppVersion.current)"
                    )
                    VStack(alignment: .leading, spacing: 2) {
                        LabeledContent(feature.title, value: status.summary)
                        Text(status.resetContext)
                            .font(appDensity.font(.caption, design: .default))
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section("Features") {
                ForEach(FeatureAccessService.enabledFeatureLabels(), id: \.self) { label in
                    Text(label)
                }
            }

            Section("About") {
                LabeledContent("Version", value: appVersion)
                LabeledContent("Storage", value: "Local-only")
                LabeledContent("Report Schema", value: "3.2.0")
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
        .alert("Clear workflows?", isPresented: $showClearWorkflowsConfirmation) {
            Button("Clear", role: .destructive) {
                viewModel.clearWorkflows()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes saved workflows only. History, tracked domains, and saved reports stay intact.")
        }
        .alert("Clear tracked domains?", isPresented: $showClearTrackedDomainsConfirmation) {
            Button("Clear", role: .destructive) {
                viewModel.clearTrackedDomains()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the watchlist only. History and workflows stay intact.")
        }
        .onAppear {
            let currentResolverURL = storedResolverURL.trimmingCharacters(in: .whitespacesAndNewlines)
            resolverOption = DNSResolverOption.option(for: currentResolverURL)
            customResolverURL = resolverOption == .custom ? currentResolverURL : DNSResolverOption.defaultURLString
            Task {
                await viewModel.refreshUsageCredits()
            }
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
    ContentView(viewModel: DomainViewModel())
}
