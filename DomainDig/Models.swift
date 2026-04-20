import Foundation

enum ServiceResult<Value> {
    case success(Value)
    case empty(String)
    case error(String)
}

enum DomainAvailabilityStatus: String, Codable {
    case available
    case registered
    case unknown
}

struct DomainAvailabilityResult: Codable {
    let domain: String
    let status: DomainAvailabilityStatus
}

struct DomainSuggestionResult: Identifiable, Codable {
    let id: UUID
    let domain: String
    let status: DomainAvailabilityStatus

    init(id: UUID = UUID(), domain: String, status: DomainAvailabilityStatus) {
        self.id = id
        self.domain = domain
        self.status = status
    }
}

struct WatchedDomain: Codable, Identifiable {
    let id: UUID
    let domain: String
    let createdAt: Date
    var lastKnownAvailability: DomainAvailabilityStatus?

    init(
        id: UUID = UUID(),
        domain: String,
        createdAt: Date = Date(),
        lastKnownAvailability: DomainAvailabilityStatus? = nil
    ) {
        self.id = id
        self.domain = domain
        self.createdAt = createdAt
        self.lastKnownAvailability = lastKnownAvailability
    }
}

struct DomainChangeSummary: Codable, Equatable {
    let hasChanges: Bool
    let changedSections: [String]
    let generatedAt: Date
}

enum PremiumCapability: String, Codable {
    case unlimitedTrackedDomains
    case automatedMonitoring
    case pushAlerts
    case batchTracking
    case advancedExports
}

struct TrackedDomain: Codable, Identifiable, Equatable {
    let id: UUID
    var domain: String
    var createdAt: Date
    var updatedAt: Date
    var note: String?
    var isPinned: Bool
    var lastKnownAvailability: DomainAvailabilityStatus?
    var lastSnapshotID: UUID?
    var lastChangeSummary: DomainChangeSummary?

    init(
        id: UUID = UUID(),
        domain: String,
        createdAt: Date = Date(),
        updatedAt: Date = Date(),
        note: String? = nil,
        isPinned: Bool = false,
        lastKnownAvailability: DomainAvailabilityStatus? = nil,
        lastSnapshotID: UUID? = nil,
        lastChangeSummary: DomainChangeSummary? = nil
    ) {
        self.id = id
        self.domain = domain
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.note = note
        self.isPinned = isPinned
        self.lastKnownAvailability = lastKnownAvailability
        self.lastSnapshotID = lastSnapshotID
        self.lastChangeSummary = lastChangeSummary
    }
}

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
    case PTR

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
        case .PTR: return 12
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
    struct CertChainEntry: Codable {
        let subject: String
        let issuer: String
    }

    let commonName: String
    let subjectAltNames: [String]
    let issuer: String
    let validFrom: Date
    let validUntil: Date
    let daysUntilExpiry: Int
    let chainDepth: Int
    let tlsVersion: String?
    let cipherSuite: String?
    let chain: [CertChainEntry]

    init(
        commonName: String,
        subjectAltNames: [String],
        issuer: String,
        validFrom: Date,
        validUntil: Date,
        daysUntilExpiry: Int,
        chainDepth: Int,
        tlsVersion: String? = nil,
        cipherSuite: String? = nil,
        chain: [CertChainEntry] = []
    ) {
        self.commonName = commonName
        self.subjectAltNames = subjectAltNames
        self.issuer = issuer
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.daysUntilExpiry = daysUntilExpiry
        self.chainDepth = chainDepth
        self.tlsVersion = tlsVersion
        self.cipherSuite = cipherSuite
        self.chain = chain
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        commonName = try container.decode(String.self, forKey: .commonName)
        subjectAltNames = try container.decode([String].self, forKey: .subjectAltNames)
        issuer = try container.decode(String.self, forKey: .issuer)
        validFrom = try container.decode(Date.self, forKey: .validFrom)
        validUntil = try container.decode(Date.self, forKey: .validUntil)
        daysUntilExpiry = try container.decode(Int.self, forKey: .daysUntilExpiry)
        chainDepth = try container.decode(Int.self, forKey: .chainDepth)
        tlsVersion = try container.decodeIfPresent(String.self, forKey: .tlsVersion)
        cipherSuite = try container.decodeIfPresent(String.self, forKey: .cipherSuite)
        chain = try container.decodeIfPresent([CertChainEntry].self, forKey: .chain) ?? []
    }
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
    let bimi: EmailSecurityRecord
    let mtaSts: MTASTSResult?

    init(
        spf: EmailSecurityRecord,
        dmarc: EmailSecurityRecord,
        dkim: EmailSecurityRecord,
        bimi: EmailSecurityRecord = EmailSecurityRecord(found: false, value: nil),
        mtaSts: MTASTSResult? = nil
    ) {
        self.spf = spf
        self.dmarc = dmarc
        self.dkim = dkim
        self.bimi = bimi
        self.mtaSts = mtaSts
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        spf = try container.decode(EmailSecurityRecord.self, forKey: .spf)
        dmarc = try container.decode(EmailSecurityRecord.self, forKey: .dmarc)
        dkim = try container.decode(EmailSecurityRecord.self, forKey: .dkim)
        bimi = try container.decodeIfPresent(EmailSecurityRecord.self, forKey: .bimi)
            ?? EmailSecurityRecord(found: false, value: nil)
        mtaSts = try container.decodeIfPresent(MTASTSResult.self, forKey: .mtaSts)
    }
}

struct EmailSecurityRecord: Codable {
    let found: Bool
    let value: String?
    let matchedSelector: String?

    init(found: Bool, value: String?, matchedSelector: String? = nil) {
        self.found = found
        self.value = value
        self.matchedSelector = matchedSelector
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        found = try container.decode(Bool.self, forKey: .found)
        value = try container.decodeIfPresent(String.self, forKey: .value)
        matchedSelector = try container.decodeIfPresent(String.self, forKey: .matchedSelector)
    }
}

struct MTASTSResult: Codable {
    let txtFound: Bool
    let policyMode: String?
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

enum PortScanKind: String, Codable {
    case standard
    case custom
}

struct PortScanResult: Identifiable, Codable {
    var id = UUID()
    let port: UInt16
    let service: String
    let open: Bool
    var banner: String?
    let kind: PortScanKind
    let durationMs: Int?

    nonisolated init(
        port: UInt16,
        service: String,
        open: Bool,
        banner: String? = nil,
        kind: PortScanKind = .standard,
        durationMs: Int? = nil
    ) {
        self.port = port
        self.service = service
        self.open = open
        self.banner = banner
        self.kind = kind
        self.durationMs = durationMs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        port = try container.decode(UInt16.self, forKey: .port)
        service = try container.decode(String.self, forKey: .service)
        open = try container.decode(Bool.self, forKey: .open)
        banner = try container.decodeIfPresent(String.self, forKey: .banner)
        kind = try container.decodeIfPresent(PortScanKind.self, forKey: .kind) ?? .standard
        durationMs = try container.decodeIfPresent(Int.self, forKey: .durationMs)
    }
}

// MARK: - History Models

struct HistoryEntry: Identifiable, Codable {
    var id = UUID()
    let domain: String
    let timestamp: Date
    var trackedDomainID: UUID?
    let dnsSections: [DNSSection]
    let sslInfo: SSLCertificateInfo?
    let httpHeaders: [HTTPHeader]
    let reachabilityResults: [PortReachability]
    let ipGeolocation: IPGeolocation?
    var emailSecurity: EmailSecurityResult?
    var mtaSts: MTASTSResult?
    var ptrRecord: String?
    var redirectChain: [RedirectHop]
    var portScanResults: [PortScanResult]
    var hstsPreloaded: Bool?
    var availabilityResult: DomainAvailabilityResult?
    var suggestions: [DomainSuggestionResult]
    var resolverDisplayName: String
    var resolverURLString: String
    var totalLookupDurationMs: Int?
    var primaryIP: String?
    var finalRedirectURL: String?
    var tlsStatusSummary: String?
    var emailSecuritySummary: String?
    var httpGradeSummary: String?
    var changeSummary: DomainChangeSummary?
    var sslError: String?
    var httpHeadersError: String?
    var reachabilityError: String?
    var ipGeolocationError: String?
    var emailSecurityError: String?
    var ptrError: String?
    var redirectChainError: String?
    var portScanError: String?

    init(domain: String, timestamp: Date, trackedDomainID: UUID? = nil, dnsSections: [DNSSection],
         sslInfo: SSLCertificateInfo?, httpHeaders: [HTTPHeader],
         reachabilityResults: [PortReachability], ipGeolocation: IPGeolocation?,
         emailSecurity: EmailSecurityResult? = nil, mtaSts: MTASTSResult? = nil, ptrRecord: String? = nil,
         redirectChain: [RedirectHop] = [], portScanResults: [PortScanResult] = [],
         hstsPreloaded: Bool? = nil, availabilityResult: DomainAvailabilityResult? = nil,
         suggestions: [DomainSuggestionResult] = [], resolverDisplayName: String, resolverURLString: String,
         totalLookupDurationMs: Int? = nil, primaryIP: String? = nil, finalRedirectURL: String? = nil,
         tlsStatusSummary: String? = nil, emailSecuritySummary: String? = nil, httpGradeSummary: String? = nil,
         changeSummary: DomainChangeSummary? = nil, sslError: String? = nil, httpHeadersError: String? = nil,
         reachabilityError: String? = nil, ipGeolocationError: String? = nil,
         emailSecurityError: String? = nil, ptrError: String? = nil,
         redirectChainError: String? = nil, portScanError: String? = nil) {
        self.domain = domain
        self.timestamp = timestamp
        self.trackedDomainID = trackedDomainID
        self.dnsSections = dnsSections
        self.sslInfo = sslInfo
        self.httpHeaders = httpHeaders
        self.reachabilityResults = reachabilityResults
        self.ipGeolocation = ipGeolocation
        self.emailSecurity = emailSecurity
        self.mtaSts = mtaSts ?? emailSecurity?.mtaSts
        self.ptrRecord = ptrRecord
        self.redirectChain = redirectChain
        self.portScanResults = portScanResults
        self.hstsPreloaded = hstsPreloaded
        self.availabilityResult = availabilityResult
        self.suggestions = suggestions
        self.resolverDisplayName = resolverDisplayName
        self.resolverURLString = resolverURLString
        self.totalLookupDurationMs = totalLookupDurationMs
        self.primaryIP = primaryIP
        self.finalRedirectURL = finalRedirectURL
        self.tlsStatusSummary = tlsStatusSummary
        self.emailSecuritySummary = emailSecuritySummary
        self.httpGradeSummary = httpGradeSummary
        self.changeSummary = changeSummary
        self.sslError = sslError
        self.httpHeadersError = httpHeadersError
        self.reachabilityError = reachabilityError
        self.ipGeolocationError = ipGeolocationError
        self.emailSecurityError = emailSecurityError
        self.ptrError = ptrError
        self.redirectChainError = redirectChainError
        self.portScanError = portScanError
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        domain = try container.decode(String.self, forKey: .domain)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        trackedDomainID = try container.decodeIfPresent(UUID.self, forKey: .trackedDomainID)
        dnsSections = try container.decode([DNSSection].self, forKey: .dnsSections)
        sslInfo = try container.decodeIfPresent(SSLCertificateInfo.self, forKey: .sslInfo)
        httpHeaders = try container.decode([HTTPHeader].self, forKey: .httpHeaders)
        reachabilityResults = try container.decode([PortReachability].self, forKey: .reachabilityResults)
        ipGeolocation = try container.decodeIfPresent(IPGeolocation.self, forKey: .ipGeolocation)
        emailSecurity = try container.decodeIfPresent(EmailSecurityResult.self, forKey: .emailSecurity)
        mtaSts = try container.decodeIfPresent(MTASTSResult.self, forKey: .mtaSts) ?? emailSecurity?.mtaSts
        ptrRecord = try container.decodeIfPresent(String.self, forKey: .ptrRecord)
        redirectChain = try container.decodeIfPresent([RedirectHop].self, forKey: .redirectChain) ?? []
        portScanResults = try container.decodeIfPresent([PortScanResult].self, forKey: .portScanResults) ?? []
        hstsPreloaded = try container.decodeIfPresent(Bool.self, forKey: .hstsPreloaded)
        availabilityResult = try container.decodeIfPresent(DomainAvailabilityResult.self, forKey: .availabilityResult)
        suggestions = try container.decodeIfPresent([DomainSuggestionResult].self, forKey: .suggestions) ?? []
        resolverDisplayName = try container.decodeIfPresent(String.self, forKey: .resolverDisplayName) ?? "Cloudflare"
        resolverURLString = try container.decodeIfPresent(String.self, forKey: .resolverURLString) ?? DNSResolverOption.defaultURLString
        totalLookupDurationMs = try container.decodeIfPresent(Int.self, forKey: .totalLookupDurationMs)
        primaryIP = try container.decodeIfPresent(String.self, forKey: .primaryIP)
        finalRedirectURL = try container.decodeIfPresent(String.self, forKey: .finalRedirectURL)
        tlsStatusSummary = try container.decodeIfPresent(String.self, forKey: .tlsStatusSummary)
        emailSecuritySummary = try container.decodeIfPresent(String.self, forKey: .emailSecuritySummary)
        httpGradeSummary = try container.decodeIfPresent(String.self, forKey: .httpGradeSummary)
        changeSummary = try container.decodeIfPresent(DomainChangeSummary.self, forKey: .changeSummary)
        sslError = try container.decodeIfPresent(String.self, forKey: .sslError)
        httpHeadersError = try container.decodeIfPresent(String.self, forKey: .httpHeadersError)
        reachabilityError = try container.decodeIfPresent(String.self, forKey: .reachabilityError)
        ipGeolocationError = try container.decodeIfPresent(String.self, forKey: .ipGeolocationError)
        emailSecurityError = try container.decodeIfPresent(String.self, forKey: .emailSecurityError)
        ptrError = try container.decodeIfPresent(String.self, forKey: .ptrError)
        redirectChainError = try container.decodeIfPresent(String.self, forKey: .redirectChainError)
        portScanError = try container.decodeIfPresent(String.self, forKey: .portScanError)
    }
}

// MARK: - Cloudflare DNS-over-HTTPS Response

struct CloudflareDNSResponse: Decodable {
    let Status: Int
    let AD: Bool?
    let Answer: [CloudflareDNSAnswer]?

    struct CloudflareDNSAnswer: Decodable {
        let name: String
        let type: Int
        let TTL: Int
        let data: String
    }
}
