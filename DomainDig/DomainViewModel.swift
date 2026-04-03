import Foundation
import SwiftUI

@MainActor
@Observable
final class DomainViewModel {
    var domain: String = ""

    // DNS
    var dnsSections: [DNSSection] = []
    var dnsLoading = false
    var dnsError: String?

    // SSL
    var sslInfo: SSLCertificateInfo?
    var sslLoading = false
    var sslError: String?
    var hstsPreloaded: Bool?
    var hstsLoading = false

    // HTTP Headers
    var httpHeaders: [HTTPHeader] = []
    var httpSecurityGrade: String?
    var httpStatusCode: Int?
    var httpResponseTimeMs: Int?
    var httpProtocol: String?
    var http3Advertised = false
    var httpHeadersLoading = false
    var httpHeadersError: String?

    // Reachability
    var reachabilityResults: [PortReachability] = []
    var reachabilityLoading = false
    var reachabilityError: String?

    // IP Geolocation
    var ipGeolocation: IPGeolocation?
    var ipGeolocationLoading = false
    var ipGeolocationError: String?

    // Email Security
    var emailSecurity: EmailSecurityResult?
    var emailSecurityLoading = false
    var emailSecurityError: String?

    // PTR / Reverse DNS
    var ptrRecord: String?
    var ptrLoading = false
    var ptrError: String?

    // Redirect Chain
    var redirectChain: [RedirectHop] = []
    var redirectChainLoading = false
    var redirectChainError: String?

    // Port Scan
    var portScanResults: [PortScanResult] = []
    var portScanLoading = false
    var portScanError: String?

    var hasRun = false
    private(set) var searchedDomain: String = ""

    // MARK: - Recent Searches

    private static let recentSearchesKey = "recentSearches"
    private static let maxRecent = 20

    var recentSearches: [String] = UserDefaults.standard.stringArray(forKey: recentSearchesKey) ?? []

    // MARK: - Saved Domains

    private static let savedDomainsKey = "savedDomains"

    var savedDomains: [String] = UserDefaults.standard.stringArray(forKey: savedDomainsKey) ?? []

    var isCurrentDomainSaved: Bool {
        !searchedDomain.isEmpty && savedDomains.contains(where: { $0.lowercased() == searchedDomain.lowercased() })
    }

    func toggleSavedDomain() {
        if isCurrentDomainSaved {
            savedDomains.removeAll { $0.lowercased() == searchedDomain.lowercased() }
        } else {
            savedDomains.append(searchedDomain)
        }
        UserDefaults.standard.set(savedDomains, forKey: Self.savedDomainsKey)
    }

    func removeSavedDomain(_ domain: String) {
        savedDomains.removeAll { $0 == domain }
        UserDefaults.standard.set(savedDomains, forKey: Self.savedDomainsKey)
    }

    func removeSavedDomains(at offsets: IndexSet) {
        savedDomains.remove(atOffsets: offsets)
        UserDefaults.standard.set(savedDomains, forKey: Self.savedDomainsKey)
    }

    // MARK: - History

    private static let historyKey = "lookupHistory"
    private static let maxHistory = 50

    var history: [HistoryEntry] = {
        guard let data = UserDefaults.standard.data(forKey: "lookupHistory"),
              let entries = try? JSONDecoder().decode([HistoryEntry].self, from: data) else {
            return []
        }
        return entries
    }()

    private func saveHistoryEntry() {
        let entry = HistoryEntry(
            domain: searchedDomain,
            timestamp: Date(),
            dnsSections: dnsSections,
            sslInfo: sslInfo,
            httpHeaders: httpHeaders,
            reachabilityResults: reachabilityResults,
            ipGeolocation: ipGeolocation,
            emailSecurity: emailSecurity,
            mtaSts: emailSecurity?.mtaSts,
            ptrRecord: ptrRecord,
            redirectChain: redirectChain,
            portScanResults: portScanResults,
            hstsPreloaded: hstsPreloaded
        )
        history.insert(entry, at: 0)
        if history.count > Self.maxHistory {
            history = Array(history.prefix(Self.maxHistory))
        }
        if let data = try? JSONEncoder().encode(history) {
            UserDefaults.standard.set(data, forKey: Self.historyKey)
        }
    }

    func removeHistoryEntries(at offsets: IndexSet) {
        history.remove(atOffsets: offsets)
        if let data = try? JSONEncoder().encode(history) {
            UserDefaults.standard.set(data, forKey: Self.historyKey)
        }
    }

    // MARK: - Computed

    var trimmedDomain: String {
        domain
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "https://", with: "")
            .replacingOccurrences(of: "http://", with: "")
            .components(separatedBy: "/").first ?? ""
    }

    /// True when all lookups have finished (regardless of success/failure).
    var resultsLoaded: Bool {
        hasRun && !dnsLoading && !sslLoading && !hstsLoading && !httpHeadersLoading && !reachabilityLoading
            && !ipGeolocationLoading && !emailSecurityLoading && !ptrLoading
            && !redirectChainLoading && !portScanLoading
    }

    // MARK: - Reset

    func reset() {
        hasRun = false
        searchedDomain = ""
        dnsSections = []
        dnsError = nil
        dnsLoading = false
        sslInfo = nil
        sslError = nil
        sslLoading = false
        hstsPreloaded = nil
        hstsLoading = false
        httpHeaders = []
        httpSecurityGrade = nil
        httpStatusCode = nil
        httpResponseTimeMs = nil
        httpProtocol = nil
        http3Advertised = false
        httpHeadersError = nil
        httpHeadersLoading = false
        reachabilityResults = []
        reachabilityError = nil
        reachabilityLoading = false
        ipGeolocation = nil
        ipGeolocationError = nil
        ipGeolocationLoading = false
        emailSecurity = nil
        emailSecurityError = nil
        emailSecurityLoading = false
        ptrRecord = nil
        ptrError = nil
        ptrLoading = false
        redirectChain = []
        redirectChainError = nil
        redirectChainLoading = false
        portScanResults = []
        portScanError = nil
        portScanLoading = false
    }

    // MARK: - Run

    func run() {
        let target = trimmedDomain
        guard !target.isEmpty else { return }

        addRecentSearch(target)
        searchedDomain = target
        hasRun = true

        // Reset all state
        dnsSections = []
        dnsError = nil
        dnsLoading = true
        sslInfo = nil
        sslError = nil
        sslLoading = true
        hstsPreloaded = nil
        hstsLoading = true
        httpHeaders = []
        httpSecurityGrade = nil
        httpStatusCode = nil
        httpResponseTimeMs = nil
        httpProtocol = nil
        http3Advertised = false
        httpHeadersError = nil
        httpHeadersLoading = true
        reachabilityResults = []
        reachabilityError = nil
        reachabilityLoading = true
        ipGeolocation = nil
        ipGeolocationError = nil
        ipGeolocationLoading = true
        emailSecurity = nil
        emailSecurityError = nil
        emailSecurityLoading = true
        ptrRecord = nil
        ptrError = nil
        ptrLoading = true
        redirectChain = []
        redirectChainError = nil
        redirectChainLoading = true
        portScanResults = []
        portScanError = nil
        portScanLoading = true

        Task {
            await withTaskGroup(of: Void.self) { group in
                // DNS → chained: email security, PTR, geolocation
                group.addTask { @MainActor in
                    await self.runDNS(domain: target)
                    // These depend on DNS results and run in parallel after DNS
                    await withTaskGroup(of: Void.self) { postDNS in
                        postDNS.addTask { @MainActor in
                            await self.runEmailSecurity(domain: target)
                        }
                        postDNS.addTask { @MainActor in
                            await self.runReverseDNS()
                        }
                        postDNS.addTask { @MainActor in
                            await self.runIPGeolocation()
                        }
                    }
                }
                group.addTask { @MainActor in
                    await self.runSSL(domain: target)
                }
                group.addTask { @MainActor in
                    await self.runHSTSPreload(domain: target)
                }
                group.addTask { @MainActor in
                    await self.runHTTPHeaders(domain: target)
                }
                group.addTask { @MainActor in
                    await self.runReachability(domain: target)
                }
                group.addTask { @MainActor in
                    await self.runRedirectChain(domain: target)
                }
                group.addTask { @MainActor in
                    await self.runPortScan(domain: target)
                }
            }
            // Save history after all lookups complete so the snapshot is complete
            saveHistoryEntry()
        }
    }

    // MARK: - Lookup Methods

    private func runDNS(domain: String) async {
        do {
            let sections = await DNSLookupService.lookupAll(domain: domain)
            dnsSections = sections
        }
        dnsLoading = false
    }

    private func runSSL(domain: String) async {
        do {
            let info = try await SSLCheckService.check(domain: domain)
            sslInfo = info
        } catch {
            sslError = error.localizedDescription
        }
        sslLoading = false
    }

    private func runHSTSPreload(domain: String) async {
        hstsPreloaded = await SSLCheckService.checkHSTSPreload(domain: domain)
        hstsLoading = false
    }

    private func runHTTPHeaders(domain: String) async {
        do {
            let result = try await HTTPHeadersService.fetch(domain: domain)
            httpHeaders = result.headers
            httpSecurityGrade = HTTPSecurityGrade.grade(for: result.headers).rawValue
            httpStatusCode = result.statusCode
            httpResponseTimeMs = result.responseTimeMs
            httpProtocol = result.httpProtocol
            http3Advertised = result.http3Advertised
        } catch {
            httpHeadersError = error.localizedDescription
        }
        httpHeadersLoading = false
    }

    private func runReachability(domain: String) async {
        let results = await ReachabilityService.checkAll(domain: domain)
        reachabilityResults = results
        reachabilityLoading = false
    }

    private func runIPGeolocation() async {
        // Find the first A record IP
        guard let aSection = dnsSections.first(where: { $0.recordType == .A }),
              let firstIP = aSection.records.first?.value else {
            ipGeolocationError = "No A record available"
            ipGeolocationLoading = false
            return
        }
        do {
            let geo = try await IPGeolocationService.lookup(ip: firstIP)
            ipGeolocation = geo
        } catch {
            ipGeolocationError = error.localizedDescription
        }
        ipGeolocationLoading = false
    }

    private func runEmailSecurity(domain: String) async {
        // Extract TXT records from already-fetched DNS sections
        let txtRecords = dnsSections.first(where: { $0.recordType == .TXT })?.records ?? []
        let result = await EmailSecurityService.analyze(domain: domain, txtRecords: txtRecords)
        emailSecurity = result
        emailSecurityLoading = false
    }

    private func runReverseDNS() async {
        guard let aSection = dnsSections.first(where: { $0.recordType == .A }),
              let firstIP = aSection.records.first?.value else {
            ptrError = "No A record available"
            ptrLoading = false
            return
        }
        let result = await ReverseDNSService.lookup(ip: firstIP)
        ptrRecord = result
        if result == nil {
            ptrError = "No PTR record found"
        }
        ptrLoading = false
    }

    private func runRedirectChain(domain: String) async {
        do {
            let hops = try await RedirectChainService.trace(domain: domain)
            redirectChain = hops
        } catch {
            redirectChainError = error.localizedDescription
        }
        redirectChainLoading = false
    }

    private func runPortScan(domain: String) async {
        let results = await PortScanService.scanAll(domain: domain)
        portScanResults = results
        portScanLoading = false
    }

    // MARK: - Export

    func exportText() -> String {
        return Self.formatExportText(
            domain: searchedDomain,
            date: Date(),
            dnsSections: dnsSections,
            sslInfo: sslInfo,
            sslError: sslError,
            hstsPreloaded: hstsPreloaded,
            httpHeaders: httpHeaders,
            httpSecurityGrade: httpSecurityGrade,
            httpStatusCode: httpStatusCode,
            httpResponseTimeMs: httpResponseTimeMs,
            httpProtocol: httpProtocol,
            http3Advertised: http3Advertised,
            httpHeadersError: httpHeadersError,
            reachabilityResults: reachabilityResults,
            ipGeolocation: ipGeolocation,
            ipGeolocationError: ipGeolocationError,
            emailSecurity: emailSecurity,
            ptrRecord: ptrRecord,
            redirectChain: redirectChain,
            portScanResults: portScanResults
        )
    }

    static func formatExportText(
        domain: String,
        date: Date,
        dnsSections: [DNSSection],
        sslInfo: SSLCertificateInfo?,
        sslError: String? = nil,
        hstsPreloaded: Bool? = nil,
        httpHeaders: [HTTPHeader],
        httpSecurityGrade: String? = nil,
        httpStatusCode: Int? = nil,
        httpResponseTimeMs: Int? = nil,
        httpProtocol: String? = nil,
        http3Advertised: Bool = false,
        httpHeadersError: String? = nil,
        reachabilityResults: [PortReachability],
        ipGeolocation: IPGeolocation?,
        ipGeolocationError: String? = nil,
        emailSecurity: EmailSecurityResult? = nil,
        ptrRecord: String? = nil,
        redirectChain: [RedirectHop] = [],
        portScanResults: [PortScanResult] = []
    ) -> String {
        let dateFmt = DateFormatter()
        dateFmt.dateFormat = "yyyy-MM-dd HH:mm"

        var lines: [String] = [
            "DomainDig Export",
            "Domain: \(domain)",
            "Date: \(dateFmt.string(from: date))",
        ]

        // Reachability
        if !reachabilityResults.isEmpty {
            lines.append("")
            lines.append("Reachability")
            lines.append("------------")
            for result in reachabilityResults {
                if result.reachable, let ms = result.latencyMs {
                    lines.append("  Port \(result.port)  \(ms)ms  Reachable")
                } else {
                    lines.append("  Port \(result.port)  —  Unreachable")
                }
            }
        }

        // Redirect Chain
        if !redirectChain.isEmpty {
            lines.append("")
            lines.append("Redirect Chain")
            lines.append("--------------")
            if redirectChain.count == 1 && redirectChain[0].isFinal && !(300...399).contains(redirectChain[0].statusCode) {
                lines.append("  No redirects — direct connection")
            } else {
                for hop in redirectChain {
                    let final = hop.isFinal ? "  (final)" : ""
                    lines.append("  \(hop.stepNumber)  \(hop.statusCode)  \(hop.url)\(final)")
                }
            }
        }

        // DNS
        lines.append("")
        lines.append("DNS Records")
        lines.append("-----------")
        for section in dnsSections {
            lines.append(section.recordType.rawValue)
            if let error = section.error {
                lines.append("  Error: \(error)")
            } else if section.records.isEmpty {
                lines.append("  No records found")
            } else {
                for record in section.records {
                    lines.append("  \(record.value)  TTL \(record.ttl)")
                }
            }
            if !section.wildcardRecords.isEmpty {
                lines.append("*.\(domain)")
                for record in section.wildcardRecords {
                    lines.append("  \(record.value)  TTL \(record.ttl)")
                }
            }
        }

        // PTR
        if let ptr = ptrRecord {
            lines.append("PTR (Reverse DNS)")
            lines.append("  \(ptr)")
        }

        // Email Security
        if let email = emailSecurity {
            lines.append("")
            lines.append("Email Security")
            lines.append("--------------")
            lines.append("  SPF:   \(email.spf.found ? "✓" : "✗")  \(email.spf.value ?? "No record found")")
            lines.append("  DMARC: \(email.dmarc.found ? "✓" : "✗")  \(email.dmarc.value ?? "No record found")")
            let dkimValue = if let selector = email.dkim.matchedSelector,
                               let value = email.dkim.value {
                "\(value) (selector: \(selector))"
            } else {
                email.dkim.value ?? "No record found"
            }
            lines.append("  DKIM:  \(email.dkim.found ? "✓" : "✗")  \(dkimValue)")
            let mtaDescription = if let mode = email.mtaSts?.policyMode {
                "mode: \(mode)"
            } else if email.mtaSts?.txtFound == true {
                "Policy unavailable"
            } else {
                "No record found"
            }
            lines.append("  MTA-STS: \(email.mtaSts?.txtFound == true ? "✓" : "✗")  \(mtaDescription)")
            lines.append("  BIMI:  \(email.bimi.found ? "✓" : "✗")  \(email.bimi.value ?? "No record found")")
        }

        // SSL
        if let info = sslInfo {
            let certDateFmt = DateFormatter()
            certDateFmt.dateStyle = .medium
            certDateFmt.timeStyle = .none

            lines.append("")
            lines.append("SSL / TLS Certificate")
            lines.append("---------------------")
            lines.append("Common Name: \(info.commonName)")
            lines.append("Issuer: \(info.issuer)")
            lines.append("SANs: \(info.subjectAltNames.joined(separator: ", "))")
            lines.append("Valid From: \(certDateFmt.string(from: info.validFrom))")
            lines.append("Valid Until: \(certDateFmt.string(from: info.validUntil))")
            lines.append("Days Until Expiry: \(info.daysUntilExpiry)")
            lines.append("Chain Depth: \(info.chainDepth)")
            if let tlsVersion = info.tlsVersion {
                lines.append("TLS Version: \(tlsVersion)")
            }
            if let cipherSuite = info.cipherSuite {
                lines.append("Cipher Suite: \(cipherSuite)")
            }
            if let hstsPreloaded {
                lines.append("HSTS Preload: \(hstsPreloaded ? "Preloaded" : "Not preloaded")")
            }
            if !info.chain.isEmpty {
                lines.append("Certificate Chain:")
                for certificate in info.chain {
                    lines.append("  Subject: \(certificate.subject)")
                    lines.append("  Issuer: \(certificate.issuer)")
                }
            }
        } else if let error = sslError {
            lines.append("")
            lines.append("SSL / TLS Certificate")
            lines.append("---------------------")
            lines.append("Error: \(error)")
        }

        // HTTP Headers
        if !httpHeaders.isEmpty {
            lines.append("")
            lines.append("HTTP Headers")
            lines.append("------------")
            for header in httpHeaders {
                lines.append("  \(header.name): \(header.value)")
            }
            if let httpSecurityGrade {
                lines.append("Grade: \(httpSecurityGrade)")
            }
            if let httpStatusCode {
                lines.append("Status: \(httpStatusCode)")
            }
            if let httpResponseTimeMs {
                lines.append("Response Time: \(httpResponseTimeMs)ms")
            }
            if let httpProtocol {
                lines.append("Protocol: \(httpProtocol)")
            }
            if http3Advertised {
                lines.append("HTTP/3 Advertised: Yes")
            }
        } else if let error = httpHeadersError {
            lines.append("")
            lines.append("HTTP Headers")
            lines.append("------------")
            lines.append("Error: \(error)")
        }

        // IP Geolocation
        if let geo = ipGeolocation {
            lines.append("")
            lines.append("IP Location")
            lines.append("-----------")
            lines.append("IP: \(geo.ip)")
            if let org = geo.org { lines.append("Org: \(org)") }
            let location = [geo.city, geo.region, geo.country_name].compactMap { $0 }.joined(separator: ", ")
            if !location.isEmpty { lines.append("Location: \(location)") }
            if let lat = geo.latitude, let lon = geo.longitude {
                lines.append("Coordinates: \(lat), \(lon)")
            }
        } else if let error = ipGeolocationError, error != "No A record available" {
            lines.append("")
            lines.append("IP Location")
            lines.append("-----------")
            lines.append("Error: \(error)")
        }

        // Open Ports
        if !portScanResults.isEmpty {
            lines.append("")
            lines.append("Open Ports")
            lines.append("----------")
            let openPorts = portScanResults.filter { $0.open }
            if openPorts.isEmpty {
                lines.append("  No open ports detected")
            } else {
                for port in openPorts {
                    lines.append("  \(port.port)  \(port.service)")
                }
            }
            let closedPorts = portScanResults.filter { !$0.open }
            if !closedPorts.isEmpty {
                lines.append("Closed: \(closedPorts.map { "\($0.port)" }.joined(separator: ", "))")
            }
        }

        return lines.joined(separator: "\n")
    }

    // MARK: - Recent Searches

    private func addRecentSearch(_ domain: String) {
        recentSearches.removeAll { $0.lowercased() == domain.lowercased() }
        recentSearches.insert(domain, at: 0)
        if recentSearches.count > Self.maxRecent {
            recentSearches = Array(recentSearches.prefix(Self.maxRecent))
        }
        UserDefaults.standard.set(recentSearches, forKey: Self.recentSearchesKey)
    }

    func clearRecentSearches() {
        recentSearches.removeAll()
        UserDefaults.standard.removeObject(forKey: Self.recentSearchesKey)
    }
}
