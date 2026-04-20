import Foundation

struct EmailSecurityService {
    private static let dkimSelectors = [
        "default", "google", "mail", "selector1", "selector2", "k1",
        "smtp", "dkim", "zoho", "mailchimp"
    ]

    /// Analyze email security records. SPF is parsed from existing TXT records;
    /// DMARC and DKIM require additional DoH queries.
    static func analyze(domain: String, txtRecords: [DNSRecord]) async -> ServiceResult<EmailSecurityResult> {
        // SPF: prefer the already-fetched apex TXT records, but fall back to a direct lookup
        // in case the earlier DNS section missed or normalized the record differently.
        let localSPFRecord = txtRecords.first(where: { isMatchingTXTRecord($0.value, prefix: "v=spf1") })?.value
        async let remoteSPFRecord = queryMatchingTXT(subdomain: domain, prefix: "v=spf1")

        // DMARC, DKIM, BIMI, and MTA-STS queries in parallel.
        async let dmarcResult = queryTXT(subdomain: "_dmarc.\(domain)")
        async let dkimResult = queryDKIM(domain: domain)
        async let bimiResult = queryMatchingTXT(
            subdomain: "default._bimi.\(domain)",
            prefix: "v=BIMI1"
        )
        async let mtaStsResult = queryMTASTS(domain: domain)

        let dmarcValue = await dmarcResult
        let dkimValue = await dkimResult
        let bimiValue = await bimiResult
        let mtaSts = await mtaStsResult
        let fetchedSPFRecord = await remoteSPFRecord
        let spfValue = localSPFRecord ?? fetchedSPFRecord

        let spf = EmailSecurityRecord(
            found: spfValue != nil,
            value: spfValue
        )

        let dmarc = EmailSecurityRecord(
            found: dmarcValue != nil,
            value: dmarcValue
        )
        let dkim = EmailSecurityRecord(
            found: dkimValue != nil,
            value: dkimValue?.value,
            matchedSelector: dkimValue?.selector
        )
        let bimi = EmailSecurityRecord(
            found: bimiValue != nil,
            value: bimiValue
        )

        let result = EmailSecurityResult(
            spf: spf,
            dmarc: dmarc,
            dkim: dkim,
            bimi: bimi,
            mtaSts: mtaSts
        )

        let hasAnyRecord = result.spf.found || result.dmarc.found || result.dkim.found || result.bimi.found || result.mtaSts?.txtFound == true
        return hasAnyRecord ? .success(result) : .empty("No email security records found")
    }

    /// Query a TXT record for the given subdomain via DoH.
    private static func queryTXT(subdomain: String) async -> String? {
        do {
            let records = try await DNSLookupService.lookup(domain: subdomain, recordType: .TXT)
            return records.first?.value
        } catch {
            return nil
        }
    }

    private static func queryMatchingTXT(subdomain: String, prefix: String) async -> String? {
        do {
            let records = try await DNSLookupService.lookup(domain: subdomain, recordType: .TXT)
            return records.first(where: { isMatchingTXTRecord($0.value, prefix: prefix) })?.value
        } catch {
            return nil
        }
    }

    /// Try common DKIM selectors concurrently and return the first valid result.
    private static func queryDKIM(domain: String) async -> (selector: String, value: String)? {
        await withTaskGroup(of: (selector: String, value: String?).self) { group in
            for selector in dkimSelectors {
                group.addTask {
                    let value = await queryTXT(subdomain: "\(selector)._domainkey.\(domain)")
                    return (selector, value)
                }
            }

            for await result in group {
                if let value = result.value, !value.isEmpty {
                    group.cancelAll()
                    return (result.selector, value)
                }
            }

            return nil
        }
    }

    private static func queryMTASTS(domain: String) async -> MTASTSResult? {
        let txtValue = await queryMatchingTXT(subdomain: "_mta-sts.\(domain)", prefix: "v=STSv1")
        guard txtValue != nil else {
            return nil
        }

        return MTASTSResult(
            txtFound: true,
            policyMode: await fetchMTASTSPolicyMode(domain: domain)
        )
    }

    private static func fetchMTASTSPolicyMode(domain: String) async -> String? {
        guard let url = URL(string: "https://mta-sts.\(domain)/.well-known/mta-sts.txt") else {
            return nil
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 5

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            let policy = String(decoding: data, as: UTF8.self)

            for line in policy.split(whereSeparator: \.isNewline) {
                let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard trimmedLine.lowercased().hasPrefix("mode:") else {
                    continue
                }

                let mode = trimmedLine.dropFirst("mode:".count)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .lowercased()
                return ["enforce", "testing", "none"].contains(mode) ? mode : nil
            }
        } catch {
            return nil
        }

        return nil
    }

    private static func isMatchingTXTRecord(_ value: String, prefix: String) -> Bool {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            .lowercased()
            .hasPrefix(prefix.lowercased())
    }
}
