import Foundation

// MARK: - DNS Models

enum DNSRecordType: String, CaseIterable, Codable {
    case A
    case AAAA
    case MX
    case NS
    case TXT
    case CNAME
    case SOA
    case SRV
    case CAA
    case DS

    var queryType: Int {
        switch self {
        case .A: return 1
        case .AAAA: return 28
        case .MX: return 15
        case .NS: return 2
        case .TXT: return 16
        case .CNAME: return 5
        case .SOA: return 6
        case .SRV: return 33
        case .CAA: return 257
        case .DS: return 43
        }
    }

    var usesRawDataValue: Bool {
        switch self {
        case .TXT, .SOA, .DS:
            return true
        default:
            return false
        }
    }
}

struct DNSRecord: Identifiable, Codable {
    var id = UUID()
    let value: String
    let ttl: Int
}

struct DNSSection: Identifiable, Codable {
    var id = UUID()
    let recordType: DNSRecordType
    var records: [DNSRecord]
    var wildcardRecords: [DNSRecord] = []
    var dnssecSigned: Bool?
    var error: String?
}

// MARK: - SSL Models

struct SSLCertificateInfo: Codable {
    let commonName: String
    let subjectAltNames: [String]
    let issuer: String
    let validFrom: Date
    let validUntil: Date
    let daysUntilExpiry: Int
    let chainDepth: Int
}

// MARK: - HTTP Headers Models

struct HTTPHeader: Identifiable, Codable {
    var id = UUID()
    let name: String
    let value: String

    static let securityHeaders: Set<String> = [
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "referrer-policy"
    ]

    var isSecurityHeader: Bool {
        Self.securityHeaders.contains(name.lowercased())
    }
}

// MARK: - Reachability Models

struct PortReachability: Identifiable, Codable {
    var id = UUID()
    let port: UInt16
    let reachable: Bool
    let latencyMs: Int?
}

// MARK: - IP Geolocation Models

struct IPGeolocation: Codable {
    let ip: String
    let city: String?
    let region: String?
    let country_name: String?
    let org: String?
    let latitude: Double?
    let longitude: Double?
}

// MARK: - Email Security Models

struct EmailSecurityResult: Codable {
    let spf: EmailSecurityRecord
    let dmarc: EmailSecurityRecord
    let dkim: EmailSecurityRecord
}

struct EmailSecurityRecord: Codable {
    let found: Bool
    let value: String?
}

// MARK: - Redirect Chain Models

struct RedirectHop: Identifiable, Codable {
    var id = UUID()
    let stepNumber: Int
    let statusCode: Int
    let url: String
    let isFinal: Bool
}

// MARK: - Port Scan Models

struct PortScanResult: Identifiable, Codable {
    var id = UUID()
    let port: UInt16
    let service: String
    let open: Bool
}

// MARK: - History Models

struct HistoryEntry: Identifiable, Codable {
    var id = UUID()
    let domain: String
    let timestamp: Date
    let dnsSections: [DNSSection]
    let sslInfo: SSLCertificateInfo?
    let httpHeaders: [HTTPHeader]
    let reachabilityResults: [PortReachability]
    let ipGeolocation: IPGeolocation?
    var emailSecurity: EmailSecurityResult?
    var ptrRecord: String?
    var redirectChain: [RedirectHop]
    var portScanResults: [PortScanResult]

    init(domain: String, timestamp: Date, dnsSections: [DNSSection],
         sslInfo: SSLCertificateInfo?, httpHeaders: [HTTPHeader],
         reachabilityResults: [PortReachability], ipGeolocation: IPGeolocation?,
         emailSecurity: EmailSecurityResult? = nil, ptrRecord: String? = nil,
         redirectChain: [RedirectHop] = [], portScanResults: [PortScanResult] = []) {
        self.domain = domain
        self.timestamp = timestamp
        self.dnsSections = dnsSections
        self.sslInfo = sslInfo
        self.httpHeaders = httpHeaders
        self.reachabilityResults = reachabilityResults
        self.ipGeolocation = ipGeolocation
        self.emailSecurity = emailSecurity
        self.ptrRecord = ptrRecord
        self.redirectChain = redirectChain
        self.portScanResults = portScanResults
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        domain = try container.decode(String.self, forKey: .domain)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        dnsSections = try container.decode([DNSSection].self, forKey: .dnsSections)
        sslInfo = try container.decodeIfPresent(SSLCertificateInfo.self, forKey: .sslInfo)
        httpHeaders = try container.decode([HTTPHeader].self, forKey: .httpHeaders)
        reachabilityResults = try container.decode([PortReachability].self, forKey: .reachabilityResults)
        ipGeolocation = try container.decodeIfPresent(IPGeolocation.self, forKey: .ipGeolocation)
        emailSecurity = try container.decodeIfPresent(EmailSecurityResult.self, forKey: .emailSecurity)
        ptrRecord = try container.decodeIfPresent(String.self, forKey: .ptrRecord)
        redirectChain = try container.decodeIfPresent([RedirectHop].self, forKey: .redirectChain) ?? []
        portScanResults = try container.decodeIfPresent([PortScanResult].self, forKey: .portScanResults) ?? []
    }
}

// MARK: - Cloudflare DNS-over-HTTPS Response

struct CloudflareDNSResponse: Decodable {
    let Status: Int
    let Answer: [CloudflareDNSAnswer]?

    struct CloudflareDNSAnswer: Decodable {
        let name: String
        let type: Int
        let TTL: Int
        let data: String
    }
}
