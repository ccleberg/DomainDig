import SwiftUI
import MapKit

struct HistoryView: View {
    @Bindable var viewModel: DomainViewModel
    @Environment(\.dismiss) private var dismiss

    private let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
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
                        HistoryDetailView(entry: entry)
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.domain)
                                .font(.system(.callout, design: .monospaced))
                                .foregroundStyle(.primary)
                            Text(dateFmt.string(from: entry.timestamp))
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

// MARK: - History Detail View (Read-Only Cached Results)

struct HistoryDetailView: View {
    let entry: HistoryEntry

    private let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    var body: some View {
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 0) {
                cachedBanner
                reachabilitySection
                redirectChainSection
                dnsSection
                emailSecuritySection
                sslSection
                httpHeadersSection
                ipGeolocationSection
                portScanSection
            }
            .padding(.horizontal)
            .padding(.bottom, 32)
        }
        .background(Color.black)
        .navigationTitle(entry.domain)
        .preferredColorScheme(.dark)
    }

    // MARK: - Cached Banner

    private var cachedBanner: some View {
        HStack(spacing: 6) {
            Image(systemName: "archivebox")
                .font(.caption)
            Text("Cached result from \(dateFmt.string(from: entry.timestamp))")
                .font(.system(.caption, design: .monospaced))
        }
        .foregroundStyle(.secondary)
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.systemGray6).opacity(0.3))
        .cornerRadius(6)
        .padding(.vertical, 12)
    }

    // MARK: - Reachability

    private var reachabilitySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !entry.reachabilityResults.isEmpty {
                sectionHeader("Reachability")
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(entry.reachabilityResults) { result in
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
            if !entry.redirectChain.isEmpty {
                sectionHeader("Redirect Chain")
                if entry.redirectChain.count == 1,
                   let only = entry.redirectChain.first,
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
                        ForEach(entry.redirectChain) { hop in
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
        }
        .padding(.top, 16)
    }

    // MARK: - DNS

    private var dnsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeader("DNS Records")
            ForEach(entry.dnsSections) { section in
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
                        recordRows(section.records)
                    }

                    if !section.wildcardRecords.isEmpty {
                        Text("*.\(entry.domain)")
                            .font(.system(.caption, design: .monospaced))
                            .fontWeight(.medium)
                            .foregroundStyle(.cyan.opacity(0.7))
                            .padding(.top, 4)
                        recordRows(section.wildcardRecords)
                    }
                }

                if section.recordType == .A {
                    horizontallyScrollableCard {
                        Text("PTR (Reverse DNS)")
                            .font(.system(.subheadline, design: .monospaced))
                            .fontWeight(.semibold)
                            .foregroundStyle(.cyan)

                        if let ptr = entry.ptrRecord {
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
            }
        }
        .padding(.top, 16)
    }

    // MARK: - Email Security

    @State private var expandedEmailField: String?

    private var emailSecuritySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let email = entry.emailSecurity {
                sectionHeader("Email Security")
                horizontallyScrollableCard(spacing: 6) {
                    historyEmailRow("SPF", record: email.spf)
                    historyEmailRow("DMARC", record: email.dmarc)
                    historyEmailRow("DKIM", record: email.dkim)
                    historyEmailRow("MTA-STS", mtaSts: entry.mtaSts ?? email.mtaSts)
                    historyEmailRow("BIMI", record: email.bimi)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.top, 16)
    }

    private func historyEmailRow(_ label: String, record: EmailSecurityRecord) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                Text(label)
                    .font(.system(.caption, design: .monospaced))
                    .fontWeight(.semibold)
                    .frame(width: 72, alignment: .leading)
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
                    if let selector = record.matchedSelector {
                        Text("(selector: \(selector))")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("No record found")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func historyEmailRow(_ label: String, mtaSts: MTASTSResult?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 8) {
                Text(label)
                    .font(.system(.caption, design: .monospaced))
                    .fontWeight(.semibold)
                    .frame(width: 72, alignment: .leading)
                Text(mtaSts?.txtFound == true ? "✓" : "✗")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(mtaSts?.txtFound == true ? .green : .red)
                if let policyMode = mtaSts?.policyMode {
                    Text(policyMode)
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.primary)
                        .textSelection(.enabled)
                } else {
                    Text(mtaSts?.txtFound == true ? "Policy unavailable" : "No record found")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: - SSL

    private var sslSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let info = entry.sslInfo {
                sectionHeader("SSL / TLS Certificate")
                horizontallyScrollableCard(spacing: 8) {
                    labelRow("Common Name", info.commonName)
                    labelRow("Issuer", info.issuer)

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

                    labelRow("Valid From", DateFormatter.certDate.string(from: info.validFrom))
                    labelRow("Valid Until", DateFormatter.certDate.string(from: info.validUntil))

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

                    labelRow("Chain Depth", "\(info.chainDepth)")
                }
            }
        }
        .padding(.top, 16)
    }

    // MARK: - HTTP Headers

    private var httpHeadersSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !entry.httpHeaders.isEmpty {
                sectionHeader("HTTP Headers")
                horizontallyScrollableCard {
                    ForEach(entry.httpHeaders) { header in
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
            if let geo = entry.ipGeolocation {
                sectionHeader("IP Location")
                VStack(alignment: .leading, spacing: 6) {
                    horizontallyScrollableContent(spacing: 6) {
                        labelRow("IP", geo.ip)
                        if let org = geo.org {
                            labelRow("Org / ISP", org)
                        }
                        let location = [geo.city, geo.region, geo.country_name].compactMap { $0 }.joined(separator: ", ")
                        if !location.isEmpty {
                            labelRow("Location", location)
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
        }
        .padding(.top, 16)
    }

    // MARK: - Port Scan

    private var portScanSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if !entry.portScanResults.isEmpty {
                sectionHeader("Open Ports")
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(entry.portScanResults) { result in
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

    private func labelRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
        }
    }

    private func recordRows(_ records: [DNSRecord]) -> some View {
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
}
