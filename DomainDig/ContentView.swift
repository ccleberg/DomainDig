import MapKit
import SwiftUI

enum LookupInputMode: String, CaseIterable, Identifiable {
    case single
    case bulk

    var id: String { rawValue }
}

struct ContentView: View {
    @State private var viewModel = DomainViewModel()
    @State private var navigationPath = NavigationPath()
    @FocusState private var domainFieldFocused: Bool
    @State private var customPortInput = ""
    @State private var customPortsExpanded = false
    @State private var trackingNoteDraft = ""
    @State private var editingTrackedDomain: TrackedDomain?
    @State private var showTrackLimitAlert = false
    @State private var inputMode: LookupInputMode = .single

    var body: some View {
        NavigationStack(path: $navigationPath) {
            ScrollView(.vertical) {
                VStack(spacing: 0) {
                    inputSection
                    if !viewModel.batchResults.isEmpty || viewModel.batchLookupRunning {
                        batchSection
                            .padding(.top, 8)
                    }
                    if viewModel.hasRun {
                        actionButtons
                        SummaryView(fields: viewModel.summaryFields)
                            .padding(.top, 8)
                        if let changeSummary = viewModel.currentChangeSummary {
                            DomainChangeSummaryView(summary: changeSummary)
                                .padding(.top, 12)
                        }
                        DomainSectionView(
                            rows: viewModel.domainRows,
                            suggestions: viewModel.suggestionRows,
                            showSuggestions: viewModel.availabilityResult?.status == .registered || viewModel.suggestionsLoading,
                            availabilityLoading: viewModel.availabilityLoading,
                            suggestionsLoading: viewModel.suggestionsLoading,
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
                            .padding(.top, 16)
                        if !viewModel.currentDiffSections.isEmpty {
                            DomainDiffView(
                                title: "Latest Changes",
                                sections: viewModel.currentDiffSections,
                                showsUnchanged: false
                            )
                            .padding(.top, 16)
                        }
                        DNSSectionView(
                            dnssecLabel: viewModel.dnssecLabel,
                            sections: viewModel.dnsRows,
                            ptrMessage: viewModel.ptrMessage,
                            loading: viewModel.dnsLoading || viewModel.ptrLoading,
                            sectionError: viewModel.dnsError
                        )
                        .padding(.top, 16)
                        WebSectionView(
                            certificateRows: viewModel.webCertificateRows,
                            sslInfo: viewModel.sslInfo,
                            sslLoading: viewModel.sslLoading || viewModel.hstsLoading,
                            sslError: viewModel.sslError,
                            responseRows: viewModel.webResponseRows,
                            headers: viewModel.httpHeaders,
                            headersLoading: viewModel.httpHeadersLoading,
                            headersError: viewModel.httpHeadersError,
                            redirects: viewModel.redirectRows,
                            redirectLoading: viewModel.redirectChainLoading,
                            redirectError: viewModel.redirectChainError,
                            finalURL: viewModel.currentSnapshot.redirectChain.last?.url
                        )
                        .padding(.top, 16)
                        EmailSectionView(
                            rows: viewModel.emailRows,
                            loading: viewModel.emailSecurityLoading,
                            error: viewModel.emailSecurityError
                        )
                        .padding(.top, 16)
                        NetworkSectionView(
                            reachabilityRows: viewModel.reachabilityRows,
                            reachabilityLoading: viewModel.reachabilityLoading,
                            reachabilityError: viewModel.reachabilityError,
                            locationRows: viewModel.locationRows,
                            geolocation: viewModel.ipGeolocation,
                            geolocationLoading: viewModel.ipGeolocationLoading,
                            geolocationError: viewModel.ipGeolocationError,
                            standardPortRows: viewModel.standardPortRows,
                            customPortRows: viewModel.customPortRows,
                            portScanLoading: viewModel.portScanLoading,
                            portScanError: viewModel.portScanError,
                            customPortScanLoading: viewModel.customPortScanLoading,
                            customPortScanError: viewModel.customPortScanError,
                            isCloudflareProxied: viewModel.isCloudflareProxied,
                            customPortsExpanded: $customPortsExpanded,
                            customPortInput: $customPortInput,
                            onScanCustomPorts: runCustomPortScan
                        )
                        .padding(.top, 16)
                    } else if !viewModel.recentSearches.isEmpty {
                        recentSearchesSection
                    }
                }
                .padding(.horizontal)
                .padding(.bottom, 32)
            }
            .background(Color.black)
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
                            SettingsView()
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
        VStack(spacing: 12) {
            Picker("Mode", selection: $inputMode) {
                Text("Single").tag(LookupInputMode.single)
                Text("Bulk").tag(LookupInputMode.bulk)
            }
            .pickerStyle(.segmented)

            if inputMode == .single {
                TextField("e.g. cleberg.net", text: $viewModel.domain)
                    .font(.system(.title3, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .padding(12)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                    .focused($domainFieldFocused)
                    .onSubmit { viewModel.run() }

                Button {
                    domainFieldFocused = false
                    viewModel.run()
                } label: {
                    Text("Run")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.trimmedDomain.isEmpty)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Paste domains separated by new lines or commas.")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)

                    TextField(
                        "example.com\napple.com, openai.com",
                        text: $viewModel.bulkInput,
                        axis: .vertical
                    )
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .lineLimit(4...10)
                    .padding(12)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)

                    Button {
                        domainFieldFocused = false
                        viewModel.runBulkLookup()
                    } label: {
                        Text(viewModel.batchLookupRunning ? "Running Batch…" : "Run Batch")
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.bulkInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || viewModel.batchLookupRunning)
                }
            }
        }
        .padding(.vertical, 16)
    }

    private var actionButtons: some View {
        HStack {
            Spacer()
            if viewModel.resultsLoaded {
                Button {
                    viewModel.toggleSavedDomain()
                } label: {
                    Image(systemName: viewModel.isCurrentDomainSaved ? "bookmark.fill" : "bookmark")
                        .font(.system(.body))
                        .foregroundStyle(viewModel.isCurrentDomainSaved ? .yellow : .secondary)
                }
                Menu {
                    Button("Export TXT") {
                        shareSingleResults(asCSV: false)
                    }
                    Button("Export CSV") {
                        shareSingleResults(asCSV: true)
                    }
                } label: {
                    Image(systemName: "square.and.arrow.up")
                        .font(.system(.body))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var batchSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Spacer()
                if viewModel.batchLookupRunning {
                    Button("Cancel") {
                        viewModel.cancelBatchLookup()
                    }
                    .buttonStyle(.bordered)
                    .font(.system(.caption, design: .monospaced))
                }
                if !viewModel.currentBatchResultEntries.isEmpty {
                    Menu {
                        Button("Export Batch TXT") {
                            shareBatchResults(asCSV: false)
                        }
                        Button("Export Batch CSV") {
                            shareBatchResults(asCSV: true)
                        }
                    } label: {
                        Label("Export", systemImage: "square.and.arrow.up")
                            .font(.system(.caption, design: .monospaced))
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
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("RECENT")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Clear") {
                    viewModel.clearRecentSearches()
                }
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            }

            ForEach(viewModel.recentSearches, id: \.self) { domain in
                Button {
                    viewModel.domain = domain
                    domainFieldFocused = false
                    viewModel.run()
                } label: {
                    Text(domain)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.primary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 6)
                        .padding(.horizontal, 10)
                        .background(Color(.systemGray6).opacity(0.5))
                        .cornerRadius(6)
                }
            }
        }
        .padding(.top, 8)
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

    private func shareSingleResults(asCSV: Bool) {
        let (filename, contents) = exportPayload(
            prefix: "domaindig_single",
            text: viewModel.exportText(),
            csv: viewModel.exportCSV(),
            asCSV: asCSV
        )
        ExportPresenter.share(filename: filename, contents: contents)
    }

    private func shareBatchResults(asCSV: Bool) {
        let (filename, contents) = exportPayload(
            prefix: "domaindig_batch",
            text: viewModel.exportBatchText(),
            csv: viewModel.exportBatchCSV(),
            asCSV: asCSV
        )
        ExportPresenter.share(filename: filename, contents: contents)
    }

    private func exportPayload(prefix: String, text: String, csv: String, asCSV: Bool) -> (String, String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = formatter.string(from: Date())
        let fileExtension = asCSV ? "csv" : "txt"
        let filename = "\(timestamp)_\(prefix).\(fileExtension)"
        return (filename, asCSV ? csv : text)
    }
}

struct SummaryView: View {
    let fields: [SummaryFieldViewData]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitleView(title: "Summary")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                ForEach(fields) { field in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(field.label)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text(field.value)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(ResultColors.color(for: field.tone))
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Color(.systemGray6).opacity(0.5))
                    .cornerRadius(6)
                }
            }
        }
    }
}

struct DomainChangeSummaryView: View {
    let summary: DomainChangeSummary

    var body: some View {
        CardView(allowsHorizontalScroll: false) {
            HStack {
                Label(summary.hasChanges ? "Changed" : "Stable", systemImage: summary.hasChanges ? "arrow.triangle.2.circlepath" : "checkmark.circle")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(summary.hasChanges ? severityColor(summary.severity) : .green)
                Spacer()
                Text(summary.severity.title.uppercased())
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(summary.hasChanges ? severityColor(summary.severity) : .secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background((summary.hasChanges ? severityColor(summary.severity) : .secondary).opacity(0.16))
                    .clipShape(Capsule())
                Text(summary.generatedAt, style: .time)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Text(summary.message)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.primary)
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
    let rows: [InfoRowViewData]
    let suggestions: [DomainSuggestionViewData]
    let showSuggestions: Bool
    let availabilityLoading: Bool
    let suggestionsLoading: Bool
    let trackedDomain: TrackedDomain?
    let trackingLimitMessage: String?
    let onTrack: () -> Void
    let onTogglePinned: () -> Void
    let onEditNote: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                SectionTitleView(title: "Domain")
                Spacer()
                if let trackedDomain {
                    HStack(spacing: 8) {
                        Text("Tracked")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.green)
                        Button {
                            onTogglePinned()
                        } label: {
                            Image(systemName: trackedDomain.isPinned ? "pin.fill" : "pin")
                        }
                        .buttonStyle(.bordered)
                        .font(.system(.caption, design: .monospaced))
                        if let onEditNote {
                            Button("Note") {
                                onEditNote()
                            }
                            .buttonStyle(.bordered)
                            .font(.system(.caption, design: .monospaced))
                        }
                    }
                } else {
                    Button("Track") {
                        onTrack()
                    }
                    .buttonStyle(.bordered)
                    .font(.system(.caption, design: .monospaced))
                }
            }
            CardView(allowsHorizontalScroll: false) {
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
                        .font(.system(.caption, design: .monospaced))
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
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.primary)
                                    .textSelection(.enabled)
                                Spacer()
                                Text(suggestion.status)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(ResultColors.color(for: suggestion.tone))
                            }
                        }
                    }
                }
            }
        }
    }
}

struct DNSSectionView: View {
    let dnssecLabel: String?
    let sections: [DNSRecordSectionViewData]
    let ptrMessage: SectionMessageViewData?
    let loading: Bool
    let sectionError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 8) {
                SectionTitleView(title: "DNS")
                Spacer()
                if let dnssecLabel {
                    Text(dnssecLabel)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
            }

            if loading {
                LoadingCardView(text: "Querying DNS…")
            } else if let sectionError, sections.isEmpty {
                MessageCardView(text: sectionError, isError: true)
            } else {
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
                        MessageRowView(text: ptrMessage.text, isError: ptrMessage.isError)
                    }
                }
            }
        }
    }
}

struct WebSectionView: View {
    let certificateRows: [InfoRowViewData]
    let sslInfo: SSLCertificateInfo?
    let sslLoading: Bool
    let sslError: String?
    let responseRows: [InfoRowViewData]
    let headers: [HTTPHeader]
    let headersLoading: Bool
    let headersError: String?
    let redirects: [RedirectHopViewData]
    let redirectLoading: Bool
    let redirectError: String?
    let finalURL: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitleView(title: "Web")

            CardView {
                Text("TLS")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)
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
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                        ForEach(sslInfo.subjectAltNames, id: \.self) { san in
                            Text(san)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                }
            }

            CardView {
                Text("Headers")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)
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
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(header.isSecurityHeader ? .yellow : .cyan)
                                Text(header.value)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.primary)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }
            }

            CardView {
                Text("Redirects")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)
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
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .frame(width: 16, alignment: .trailing)
                            Text(redirect.statusCode)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.cyan)
                                .frame(width: 36, alignment: .leading)
                            Text(redirect.url)
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                            if redirect.isFinal {
                                Text("(final)")
                                    .font(.system(.caption2, design: .monospaced))
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
    let rows: [EmailRowViewData]
    let loading: Bool
    let error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitleView(title: "Email")
            CardView {
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
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.cyan)
                                    .frame(width: 76, alignment: .leading)
                                Text(row.status)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(ResultColors.color(for: row.statusTone))
                            }
                            Text(row.detail)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                            if let auxiliaryDetail = row.auxiliaryDetail {
                                Text(auxiliaryDetail)
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
    }
}

struct NetworkSectionView: View {
    let reachabilityRows: [ReachabilityRowViewData]
    let reachabilityLoading: Bool
    let reachabilityError: String?
    let locationRows: [InfoRowViewData]
    let geolocation: IPGeolocation?
    let geolocationLoading: Bool
    let geolocationError: String?
    let standardPortRows: [PortScanRowViewData]
    let customPortRows: [PortScanRowViewData]
    let portScanLoading: Bool
    let portScanError: String?
    let customPortScanLoading: Bool
    let customPortScanError: String?
    let isCloudflareProxied: Bool
    @Binding var customPortsExpanded: Bool
    @Binding var customPortInput: String
    let onScanCustomPorts: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitleView(title: "Network")

            CardView {
                Text("Reachability")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)
                if reachabilityLoading {
                    ProgressView("Checking ports…")
                        .appLoadingStyle()
                } else if let reachabilityError {
                    MessageRowView(text: reachabilityError, isError: true)
                } else {
                    ForEach(reachabilityRows) { row in
                        HStack {
                            Text(row.portLabel)
                                .font(.system(.caption, design: .monospaced))
                            Spacer()
                            Text(row.latencyLabel)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                            Text(row.statusLabel)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(ResultColors.color(for: row.statusTone))
                        }
                    }
                }
            }

            CardView(allowsHorizontalScroll: false) {
                Text("Location")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)
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
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)

                if isCloudflareProxied {
                    Text("Domain is behind Cloudflare's proxy. Results reflect the edge, not the origin.")
                        .font(.system(.caption2, design: .monospaced))
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
                            .font(.system(.caption, design: .monospaced))
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.numberPad)
                            .padding(10)
                            .background(Color(.systemGray6).opacity(0.5))
                            .cornerRadius(6)

                        Button("Scan") {
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
}

struct PortRowsView: View {
    let rows: [PortScanRowViewData]

    var body: some View {
        if rows.isEmpty {
            MessageRowView(text: "No results", isError: false)
        } else {
            ForEach(rows) { row in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(row.portLabel)
                            .font(.system(.caption, design: .monospaced))
                            .frame(width: 52, alignment: .leading)
                        Text(row.service)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.primary)
                        Spacer()
                        if let durationLabel = row.durationLabel {
                            Text(durationLabel)
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        Text(row.statusLabel)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(ResultColors.color(for: row.statusTone))
                    }
                    if let banner = row.banner {
                        Text(banner)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .padding(.leading, 8)
                    }
                }
            }
        }
    }
}

struct SectionTitleView: View {
    let title: String

    var body: some View {
        Text(title)
            .font(.system(.headline))
            .foregroundStyle(.white)
    }
}

struct CardView<Content: View>: View {
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
        .padding(10)
        .background(Color(.systemGray6).opacity(0.5))
        .cornerRadius(6)
    }

    private var cardContent: some View {
        VStack(alignment: .leading, spacing: 6) {
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
    let text: String
    let isError: Bool

    var body: some View {
        Label(text, systemImage: isError ? "exclamationmark.triangle.fill" : "info.circle")
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(isError ? .red : .secondary)
    }
}

struct LabeledValueRow: View {
    let row: InfoRowViewData

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(row.label)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            Text(row.value)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(ResultColors.color(for: row.tone))
                .textSelection(.enabled)
        }
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
    @AppStorage(DNSResolverOption.userDefaultsKey)
    private var storedResolverURL = DNSResolverOption.defaultURLString

    @State private var resolverOption: DNSResolverOption = .cloudflare
    @State private var customResolverURL = DNSResolverOption.defaultURLString

    private var customResolverError: String? {
        guard resolverOption == .custom else {
            return nil
        }
        return DNSResolverOption.isValidCustomURL(customResolverURL) ? nil : "Resolver URL must start with https://"
    }

    var body: some View {
        Form {
            Section {
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
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
            }
        }
        .navigationTitle("Settings")
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
}

#Preview {
    ContentView()
}
