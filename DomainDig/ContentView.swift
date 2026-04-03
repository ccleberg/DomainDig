import SwiftUI
import MapKit

struct ContentView: View {
    @State private var viewModel = DomainViewModel()
    @FocusState private var domainFieldFocused: Bool

    var body: some View {
        NavigationStack {
            ScrollView(.vertical) {
                VStack(spacing: 0) {
                    inputSection
                    if viewModel.hasRun {
                        actionButtons
                        reachabilitySection
                        redirectChainSection
                        dnsResultsSection
                        emailSecuritySection
                        sslResultsSection
                        httpHeadersSection
                        ipGeolocationSection
                        portScanSection
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
                }
                ToolbarItem(placement: .topBarTrailing) {
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

    // MARK: - Input

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

    // MARK: - Action Buttons (Share + Bookmark)

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
        .padding(.top, 8)
    }

    // MARK: - Recent Searches

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

    // MARK: - Reachability

    private var reachabilitySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Reachability")

            if viewModel.reachabilityLoading {
                ProgressView("Checking ports…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.reachabilityError {
                errorLabel(error)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(viewModel.reachabilityResults) { result in
                        HStack(spacing: 8) {
                            Circle()
                                .fill(result.reachable ? Color.green : Color.red)
                                .frame(width: 8, height: 8)
                            Text("Port \(result.port)")
                                .font(.system(.caption, design: .monospaced))
                            if result.reachable, let ms = result.latencyMs {
                                Text("\(ms)ms")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            } else if !result.reachable {
                                Text("—")
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(result.reachable ? "Reachable" : "Unreachable")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(result.reachable ? .green : .red)
                        }
                    }
                }
                .padding(10)
                .background(Color(.systemGray6).opacity(0.5))
                .cornerRadius(6)
            }
        }
        .padding(.top, 8)
    }

    // MARK: - Redirect Chain

    private var redirectChainSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Redirect Chain")

            if viewModel.redirectChainLoading {
                ProgressView("Tracing redirects…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.redirectChainError {
                errorLabel(error)
            } else if viewModel.redirectChain.isEmpty {
                Text("No redirect data")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .padding(8)
            } else if viewModel.redirectChain.count == 1,
                      let only = viewModel.redirectChain.first,
                      only.isFinal, !(300...399).contains(only.statusCode) {
                Text("No redirects — direct connection")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.systemGray6).opacity(0.5))
                    .cornerRadius(6)
            } else {
                horizontallyScrollableCard {
                    ForEach(viewModel.redirectChain) { hop in
                        HStack(alignment: .top, spacing: 6) {
                            Text("\(hop.stepNumber)")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .frame(width: 16, alignment: .trailing)
                            Text("\(hop.statusCode)")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.cyan)
                                .frame(width: 30, alignment: .leading)
                            Text(hop.url)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                            if hop.isFinal {
                                Text("(final)")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .padding(.top, 16)
    }

    // MARK: - DNS Results

    private var dnsResultsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 8) {
                sectionHeader("DNS Records")
                Spacer()
                if let dnssecSigned = dnssecStatus {
                    Text(dnssecSigned ? "DNSSEC ✓" : "DNSSEC ✗")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(dnssecSigned ? .green : .red)
                        .padding(.top, 1)
                }
            }

            if viewModel.dnsLoading {
                ProgressView("Querying DNS…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.dnsError {
                errorLabel(error)
            } else {
                ForEach(viewModel.dnsSections) { section in
                    dnsRecordSection(section)
                    if section.recordType == .A {
                        ptrRow
                    }
                }
            }
        }
        .padding(.top, 16)
    }

    private var ptrRow: some View {
        horizontallyScrollableCard {
            Text("PTR (Reverse DNS)")
                .font(.system(.subheadline, design: .monospaced))
                .fontWeight(.semibold)
                .foregroundStyle(.cyan)

            if viewModel.ptrLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(4)
            } else if let ptr = viewModel.ptrRecord {
                Text(ptr)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
            } else {
                Text("No PTR record found")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func dnsRecordSection(_ section: DNSSection) -> some View {
        horizontallyScrollableCard {
            Text(section.recordType.rawValue)
                .font(.system(.subheadline, design: .monospaced))
                .fontWeight(.semibold)
                .foregroundStyle(.cyan)

            if let error = section.error {
                errorLabel(error)
            } else if section.records.isEmpty {
                Text("No records found")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            } else {
                dnsRecordRows(section.records)
            }

            if !section.wildcardRecords.isEmpty {
                Text("*.\(viewModel.searchedDomain)")
                    .font(.system(.caption, design: .monospaced))
                    .fontWeight(.medium)
                    .foregroundStyle(.cyan.opacity(0.7))
                    .padding(.top, 4)

                dnsRecordRows(section.wildcardRecords)
            }
        }
    }

    private func dnsRecordRows(_ records: [DNSRecord]) -> some View {
        ForEach(records) { record in
            HStack(alignment: .top) {
                Text(record.value)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.primary)
                    .textSelection(.enabled)
                Spacer()
                Text("TTL \(record.ttl)")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - Email Security

    @State private var expandedEmailField: String?

    private var emailSecuritySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Email Security")

            if viewModel.emailSecurityLoading {
                ProgressView("Checking email records…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.emailSecurityError {
                errorLabel(error)
            } else if let email = viewModel.emailSecurity {
                horizontallyScrollableCard(spacing: 6) {
                    emailSecurityRow("SPF", record: email.spf)
                    emailSecurityRow("DMARC", record: email.dmarc)
                    emailSecurityRow("DKIM", record: email.dkim)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 16)
    }

    private func emailSecurityRow(_ label: String, record: EmailSecurityRecord) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                Text(label)
                    .font(.system(.caption, design: .monospaced))
                    .fontWeight(.semibold)
                    .frame(width: 52, alignment: .leading)
                Text(record.found ? "✓" : "✗")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(record.found ? .green : .red)
                if let value = record.value {
                    let isExpanded = expandedEmailField == label
                    let displayValue = isExpanded ? value : String(value.prefix(80))
                    Text(displayValue)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                        .lineLimit(isExpanded ? nil : 1)
                        .onTapGesture {
                            withAnimation {
                                expandedEmailField = isExpanded ? nil : label
                            }
                        }
                } else {
                    Text("No record found")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: - SSL Results

    private var sslResultsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("SSL / TLS Certificate")

            if viewModel.sslLoading {
                ProgressView("Checking certificate…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.sslError {
                errorLabel(error)
            } else if let info = viewModel.sslInfo {
                sslDetail(info)
            }
        }
        .padding(.top, 16)
    }

    private func sslDetail(_ info: SSLCertificateInfo) -> some View {
        horizontallyScrollableCard(spacing: 8) {
            certRow("Common Name", info.commonName)
            certRow("Issuer", info.issuer)

            VStack(alignment: .leading, spacing: 2) {
                Text("SANs")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                ForEach(info.subjectAltNames, id: \.self) { san in
                    Text(san)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            let formatter = DateFormatter.certDate
            certRow("Valid From", formatter.string(from: info.validFrom))
            certRow("Valid Until", formatter.string(from: info.validUntil))

            HStack {
                Text("Days Until Expiry")
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.secondary)
                Spacer()
                Text("\(info.daysUntilExpiry)")
                    .font(.system(.caption, design: .monospaced))
                    .fontWeight(.bold)
                    .foregroundStyle(expiryColor(info.daysUntilExpiry))
            }

            certRow("Chain Depth", "\(info.chainDepth)")
        }
    }

    // MARK: - HTTP Headers

    private var httpHeadersSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("HTTP Headers")

            if viewModel.httpHeadersLoading {
                ProgressView("Fetching headers…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.httpHeadersError {
                errorLabel(error)
            } else {
                horizontallyScrollableCard {
                    ForEach(viewModel.httpHeaders) { header in
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
        .padding(.top, 16)
    }

    // MARK: - IP Geolocation

    private var ipGeolocationSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("IP Location")

            if viewModel.ipGeolocationLoading {
                ProgressView("Looking up location…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let geo = viewModel.ipGeolocation {
                ipGeolocationDetail(geo)
            } else if let error = viewModel.ipGeolocationError {
                if error == "No A record available" {
                    Text("No location data available")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(8)
                } else {
                    errorLabel(error)
                }
            }
        }
        .padding(.top, 16)
    }

    private func ipGeolocationDetail(_ geo: IPGeolocation) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            horizontallyScrollableContent(spacing: 6) {
                certRow("IP", geo.ip)
                if let org = geo.org {
                    certRow("Org / ISP", org)
                }
                let location = [geo.city, geo.region, geo.country_name].compactMap { $0 }.joined(separator: ", ")
                if !location.isEmpty {
                    certRow("Location", location)
                }
            }

            if let lat = geo.latitude, let lon = geo.longitude {
                let coordinate = CLLocationCoordinate2D(latitude: lat, longitude: lon)
                Map(initialPosition: .region(MKCoordinateRegion(
                    center: coordinate,
                    span: MKCoordinateSpan(latitudeDelta: 1, longitudeDelta: 1)
                ))) {
                    Marker(geo.ip, coordinate: coordinate)
                }
                .mapStyle(.standard)
                .frame(maxWidth: .infinity)
                .frame(height: 180)
                .cornerRadius(8)
            }
        }
        .padding(10)
        .background(Color(.systemGray6).opacity(0.5))
        .cornerRadius(6)
    }

    // MARK: - Port Scan

    private var portScanSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("Open Ports")

            if viewModel.portScanLoading {
                ProgressView("Scanning ports…")
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else if let error = viewModel.portScanError {
                errorLabel(error)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(viewModel.portScanResults) { result in
                        HStack(spacing: 8) {
                            Circle()
                                .fill(result.open ? Color.green : Color(.systemGray4))
                                .frame(width: 8, height: 8)
                            Text("\(result.port)")
                                .font(.system(.caption, design: .monospaced))
                                .frame(width: 44, alignment: .leading)
                            Text(result.service)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(result.open ? .primary : .secondary)
                            Spacer()
                            if result.open {
                                Text("Open")
                                    .font(.system(.caption2, design: .monospaced))
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                }
                .padding(10)
                .background(Color(.systemGray6).opacity(0.5))
                .cornerRadius(6)
            }
        }
        .padding(.top, 16)
    }

    // MARK: - Helpers

    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(.headline, design: .default))
            .foregroundStyle(.white)
    }

    private var dnssecStatus: Bool? {
        viewModel.dnsSections.compactMap(\.dnssecSigned).first
    }

    private func certRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
        }
    }

    private func horizontallyScrollableCard<Content: View>(
        spacing: CGFloat = 4,
        @ViewBuilder content: () -> Content
    ) -> some View {
        horizontallyScrollableContent(spacing: spacing) {
            content()
        }
        .padding(10)
        .background(Color(.systemGray6).opacity(0.5))
        .cornerRadius(6)
    }

    private func horizontallyScrollableContent<Content: View>(
        spacing: CGFloat = 4,
        @ViewBuilder content: () -> Content
    ) -> some View {
        ScrollView(.horizontal) {
            VStack(alignment: .leading, spacing: spacing) {
                content()
            }
            .scrollTargetLayout()
        }
        .scrollBounceBehavior(.basedOnSize, axes: .horizontal)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func errorLabel(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.red)
            .padding(8)
    }

    private func expiryColor(_ days: Int) -> Color {
        if days < 30 { return .red }
        if days < 60 { return .yellow }
        return .green
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

extension DateFormatter {
    static let certDate: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
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

        return DNSResolverOption.isValidCustomURL(customResolverURL)
            ? nil
            : "Resolver URL must start with https://"
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
            customResolverURL = resolverOption == .custom
                ? currentResolverURL
                : DNSResolverOption.defaultURLString
        }
        .onChange(of: resolverOption) { _, newValue in
            guard let presetURL = newValue.urlString else {
                storedResolverURL = customResolverURL.trimmingCharacters(in: .whitespacesAndNewlines)
                return
            }
            storedResolverURL = presetURL
        }
        .onChange(of: customResolverURL) { _, newValue in
            guard resolverOption == .custom else {
                return
            }
            storedResolverURL = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }
}

#Preview {
    ContentView()
}
