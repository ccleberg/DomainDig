import MapKit
import SwiftUI

struct ContentView: View {
    @State private var viewModel = DomainViewModel()
    @FocusState private var domainFieldFocused: Bool
    @State private var customPortInput = ""
    @State private var customPortsExpanded = false

    var body: some View {
        NavigationStack {
            ScrollView(.vertical) {
                VStack(spacing: 0) {
                    inputSection
                    if viewModel.hasRun {
                        actionButtons
                        SummaryView(fields: viewModel.summaryFields)
                            .padding(.top, 8)
                        DomainSectionView(rows: viewModel.domainRows)
                            .padding(.top, 16)
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
                        SavedDomainsView(viewModel: viewModel)
                    } label: {
                        Image(systemName: "bookmark")
                            .foregroundStyle(.secondary)
                    }
                    NavigationLink {
                        HistoryView(viewModel: viewModel)
                    } label: {
                        Image(systemName: "clock.arrow.trianglehead.counterclockwise.rotate.90")
                            .foregroundStyle(.secondary)
                    }
                    NavigationLink {
                        SettingsView()
                    } label: {
                        Image(systemName: "gearshape")
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .onAppear {
            domainFieldFocused = true
        }
    }

    private var inputSection: some View {
        VStack(spacing: 12) {
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
                Button {
                    shareResults()
                } label: {
                    Image(systemName: "square.and.arrow.up")
                        .font(.system(.body))
                        .foregroundStyle(.secondary)
                }
            }
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

    private func shareResults() {
        let text = viewModel.exportText()
        let dateFmt = DateFormatter()
        dateFmt.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = dateFmt.string(from: Date())
        let filename = "\(timestamp)_domaindigresults.txt"
        let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent(filename)

        do {
            try text.write(to: tempURL, atomically: true, encoding: .utf8)
        } catch {
            return
        }

        let activityVC = UIActivityViewController(activityItems: [tempURL], applicationActivities: nil)
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let rootVC = windowScene.keyWindow?.rootViewController else { return }
        var presenter = rootVC
        while let presented = presenter.presentedViewController {
            presenter = presented
        }
        activityVC.popoverPresentationController?.sourceView = presenter.view
        presenter.present(activityVC, animated: true)
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

struct DomainSectionView: View {
    let rows: [InfoRowViewData]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionTitleView(title: "Domain")
            CardView {
                ForEach(rows) { row in
                    LabeledValueRow(row: row)
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

            CardView {
                Text("Location")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)
                if geolocationLoading {
                    ProgressView("Looking up location…")
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
                        .frame(height: 180)
                        .cornerRadius(8)
                    }
                } else {
                    MessageRowView(text: "No location data available", isError: false)
                }
            }

            CardView {
                Text("Port Scan")
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.semibold)
                    .foregroundStyle(.cyan)

                if isCloudflareProxied {
                    Text("Domain is behind Cloudflare's proxy. Results reflect the edge, not the origin.")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.orange)
                }

                if portScanLoading {
                    ProgressView("Scanning ports…")
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
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        ScrollView(.horizontal) {
            VStack(alignment: .leading, spacing: 6) {
                content
            }
            .scrollTargetLayout()
        }
        .scrollBounceBehavior(.basedOnSize, axes: .horizontal)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(Color(.systemGray6).opacity(0.5))
        .cornerRadius(6)
    }
}

struct LoadingCardView: View {
    let text: String

    var body: some View {
        CardView {
            ProgressView(text)
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
