import Foundation
import Security

struct SSLCheckService {

    static func check(domain: String) async -> ServiceResult<SSLCertificateInfo> {
        let delegate = SSLSessionDelegate()
        let session = URLSession(
            configuration: .ephemeral,
            delegate: delegate,
            delegateQueue: nil
        )
        defer { session.invalidateAndCancel() }

        let url = URL(string: "https://\(domain)")!
        let request = URLRequest(url: url, timeoutInterval: 10)

        do {
            _ = try await session.data(for: request)

            guard let trust = delegate.serverTrust else {
                return .empty(SSLError.noCertificate.localizedDescription)
            }

            return .success(try extractCertificateInfo(from: trust, metadata: delegate.tlsMetadata))
        } catch {
            return .error(error.localizedDescription)
        }
    }

    static func checkHSTSPreload(domain: String) async -> Bool? {
        var components = URLComponents(string: "https://hstspreload.org/api/v2/status")
        components?.queryItems = [
            URLQueryItem(name: "domain", value: domain)
        ]

        guard let url = components?.url else {
            return nil
        }

        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let response = try JSONDecoder().decode(HSTSPreloadResponse.self, from: data)
            return response.status == "preloaded"
        } catch {
            return nil
        }
    }

    private static func extractCertificateInfo(
        from trust: SecTrust,
        metadata: TLSMetadata?
    ) throws -> SSLCertificateInfo {
        let chainCount = SecTrustGetCertificateCount(trust)
        guard chainCount > 0,
              let certChain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = certChain.first else {
            throw SSLError.noCertificate
        }

        // Common Name — use subject summary (available on iOS)
        let commonName = SecCertificateCopySubjectSummary(leaf) as String? ?? "Unknown"

        // Validity dates
        let validFrom: Date
        let validUntil: Date

        if let notBefore = SecCertificateCopyNotValidBeforeDate(leaf) as Date? {
            validFrom = notBefore
        } else {
            validFrom = Date.distantPast
        }

        if let notAfter = SecCertificateCopyNotValidAfterDate(leaf) as Date? {
            validUntil = notAfter
        } else {
            validUntil = Date.distantFuture
        }

        let daysUntilExpiry = Calendar.current.dateComponents([.day], from: Date(), to: validUntil).day ?? 0

        // Parse the DER-encoded certificate to extract SANs and Issuer
        let derData = SecCertificateCopyData(leaf) as Data
        let parsed = DERCertificateParser.parse(derData)

        let sans = parsed.subjectAltNames.isEmpty ? [commonName] : parsed.subjectAltNames

        // Issuer: prefer parsed issuer, fall back to chain's next cert summary
        var issuer = parsed.issuerCommonName ?? "Unknown"
        if issuer == "Unknown" && certChain.count > 1 {
            let issuerCert = certChain[1]
            if let issuerSummary = SecCertificateCopySubjectSummary(issuerCert) as String? {
                issuer = issuerSummary
            }
        }

        let chain = certChain.map { certificate in
            let subject = SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown"
            let parsedCertificate = DERCertificateParser.parse(SecCertificateCopyData(certificate) as Data)
            return SSLCertificateInfo.CertChainEntry(
                subject: subject,
                issuer: parsedCertificate.issuerCommonName ?? "Unknown"
            )
        }

        return SSLCertificateInfo(
            commonName: commonName,
            subjectAltNames: sans,
            issuer: issuer,
            validFrom: validFrom,
            validUntil: validUntil,
            daysUntilExpiry: daysUntilExpiry,
            chainDepth: Int(chainCount),
            tlsVersion: metadata?.tlsVersion,
            cipherSuite: metadata?.cipherSuite,
            chain: chain
        )
    }
}

fileprivate struct TLSMetadata {
    let tlsVersion: String?
    let cipherSuite: String?
}

private struct HSTSPreloadResponse: Decodable {
    let status: String
}

// MARK: - Minimal DER/ASN.1 parser for X.509 certificate fields

private enum DERCertificateParser {
    struct Result {
        var issuerCommonName: String?
        var subjectAltNames: [String] = []
    }

    static func parse(_ data: Data) -> Result {
        var result = Result()
        let bytes = [UInt8](data)

        // X.509 structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        // tbsCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... extensions }
        guard let tbsRange = readSequence(bytes, offset: 0),
              let tbsContent = readSequence(bytes, offset: tbsRange.contentStart) else {
            return result
        }

        var offset = tbsContent.contentStart

        // Skip version (explicit tag [0]) if present
        if offset < bytes.count && (bytes[offset] & 0xE0) == 0xA0 {
            if let tagLen = readTagAndLength(bytes, offset: offset) {
                offset = tagLen.contentStart + tagLen.length
            }
        }

        // Skip serialNumber
        if let serial = readTagAndLength(bytes, offset: offset) {
            offset = serial.contentStart + serial.length
        }

        // Skip signature algorithm
        if let sigAlg = readTagAndLength(bytes, offset: offset) {
            offset = sigAlg.contentStart + sigAlg.length
        }

        // Issuer — a SEQUENCE of SETs of attribute type-value pairs
        if let issuerSeq = readTagAndLength(bytes, offset: offset) {
            result.issuerCommonName = extractCommonName(bytes, sequenceStart: issuerSeq.contentStart, length: issuerSeq.length)
            offset = issuerSeq.contentStart + issuerSeq.length
        }

        // Skip validity
        if let validity = readTagAndLength(bytes, offset: offset) {
            offset = validity.contentStart + validity.length
        }

        // Skip subject
        if let subject = readTagAndLength(bytes, offset: offset) {
            offset = subject.contentStart + subject.length
        }

        // Skip subjectPublicKeyInfo
        if let spki = readTagAndLength(bytes, offset: offset) {
            offset = spki.contentStart + spki.length
        }

        // Extensions are in an explicit tag [3]
        while offset < tbsContent.contentStart + tbsContent.length {
            if bytes[offset] == 0xA3 {
                if let extWrapper = readTagAndLength(bytes, offset: offset) {
                    // Inside is a SEQUENCE of SEQUENCE extensions
                    if let extsSeq = readTagAndLength(bytes, offset: extWrapper.contentStart) {
                        result.subjectAltNames = extractSANs(bytes, sequenceStart: extsSeq.contentStart, length: extsSeq.length)
                    }
                }
                break
            }
            // Skip optional implicit tags (issuerUniqueID [1], subjectUniqueID [2])
            if let tl = readTagAndLength(bytes, offset: offset) {
                offset = tl.contentStart + tl.length
            } else {
                break
            }
        }

        return result
    }

    // OID for commonName: 2.5.4.3 = 55 04 03
    private static let cnOID: [UInt8] = [0x55, 0x04, 0x03]

    // OID for subjectAltName: 2.5.29.17 = 55 1D 11
    private static let sanOID: [UInt8] = [0x55, 0x1D, 0x11]

    private static func extractCommonName(_ bytes: [UInt8], sequenceStart: Int, length: Int) -> String? {
        let end = sequenceStart + length
        var pos = sequenceStart
        while pos < end {
            // Each SET in the issuer
            guard let setTL = readTagAndLength(bytes, offset: pos) else { break }
            let setEnd = setTL.contentStart + setTL.length

            // Inside the SET is a SEQUENCE with OID + value
            if let seqTL = readTagAndLength(bytes, offset: setTL.contentStart) {
                let seqEnd = seqTL.contentStart + seqTL.length
                if let oidTL = readTagAndLength(bytes, offset: seqTL.contentStart) {
                    let oidBytes = Array(bytes[oidTL.contentStart..<oidTL.contentStart + oidTL.length])
                    if oidBytes == cnOID {
                        let valueStart = oidTL.contentStart + oidTL.length
                        if let valueTL = readTagAndLength(bytes, offset: valueStart) {
                            let strBytes = bytes[valueTL.contentStart..<valueTL.contentStart + valueTL.length]
                            return String(bytes: strBytes, encoding: .utf8)
                        }
                    }
                    _ = seqEnd // suppress unused warning
                }
            }
            pos = setEnd
        }
        return nil
    }

    private static func extractSANs(_ bytes: [UInt8], sequenceStart: Int, length: Int) -> [String] {
        let end = sequenceStart + length
        var pos = sequenceStart
        var sans: [String] = []

        while pos < end {
            guard let extSeq = readTagAndLength(bytes, offset: pos) else { break }
            let extEnd = extSeq.contentStart + extSeq.length

            // Each extension is SEQUENCE { OID, [critical], value }
            if let oidTL = readTagAndLength(bytes, offset: extSeq.contentStart) {
                let oidBytes = Array(bytes[oidTL.contentStart..<oidTL.contentStart + oidTL.length])
                if oidBytes == sanOID {
                    var valuePos = oidTL.contentStart + oidTL.length
                    // Skip optional critical BOOLEAN
                    if valuePos < extEnd && bytes[valuePos] == 0x01 {
                        if let boolTL = readTagAndLength(bytes, offset: valuePos) {
                            valuePos = boolTL.contentStart + boolTL.length
                        }
                    }
                    // The value is an OCTET STRING wrapping a SEQUENCE of GeneralNames
                    if let octetTL = readTagAndLength(bytes, offset: valuePos) {
                        if let sanSeq = readTagAndLength(bytes, offset: octetTL.contentStart) {
                            let sanEnd = sanSeq.contentStart + sanSeq.length
                            var sanPos = sanSeq.contentStart
                            while sanPos < sanEnd {
                                guard let nameTL = readTagAndLength(bytes, offset: sanPos) else { break }
                                // Context tag [2] = dNSName (IA5String)
                                if (bytes[sanPos] & 0x1F) == 2 {
                                    let nameBytes = bytes[nameTL.contentStart..<nameTL.contentStart + nameTL.length]
                                    if let name = String(bytes: nameBytes, encoding: .ascii) {
                                        sans.append(name)
                                    }
                                }
                                sanPos = nameTL.contentStart + nameTL.length
                            }
                        }
                    }
                }
            }
            pos = extEnd
        }
        return sans
    }

    private struct TLV {
        let contentStart: Int
        let length: Int
    }

    private static func readSequence(_ bytes: [UInt8], offset: Int) -> TLV? {
        guard offset < bytes.count, bytes[offset] == 0x30 else { return nil }
        return readTagAndLength(bytes, offset: offset)
    }

    private static func readTagAndLength(_ bytes: [UInt8], offset: Int) -> TLV? {
        guard offset < bytes.count else { return nil }
        var pos = offset + 1 // skip tag byte
        guard pos < bytes.count else { return nil }

        let firstLen = bytes[pos]
        pos += 1

        let length: Int
        if firstLen < 0x80 {
            length = Int(firstLen)
        } else {
            let numBytes = Int(firstLen & 0x7F)
            guard numBytes > 0, numBytes <= 4, pos + numBytes <= bytes.count else { return nil }
            var len = 0
            for i in 0..<numBytes {
                len = (len << 8) | Int(bytes[pos + i])
            }
            pos += numBytes
            length = len
        }

        return TLV(contentStart: pos, length: length)
    }
}

enum SSLError: LocalizedError {
    case noCertificate
    case connectionFailed

    var errorDescription: String? {
        switch self {
        case .noCertificate:
            return "No certificate found"
        case .connectionFailed:
            return "Failed to connect to server"
        }
    }
}

final class SSLSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var _serverTrust: SecTrust?
    private var _tlsMetadata: TLSMetadata?

    var serverTrust: SecTrust? {
        lock.lock()
        defer { lock.unlock() }
        return _serverTrust
    }

    fileprivate var tlsMetadata: TLSMetadata? {
        lock.lock()
        defer { lock.unlock() }
        return _tlsMetadata
    }

    func urlSession(
        _ _: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        lock.lock()
        _serverTrust = trust
        lock.unlock()

        let credential = URLCredential(trust: trust)
        completionHandler(.useCredential, credential)
    }
}

extension SSLSessionDelegate: URLSessionTaskDelegate {
    func urlSession(
        _ _: URLSession,
        task _: URLSessionTask,
        didFinishCollecting metrics: URLSessionTaskMetrics
    ) {
        guard let transaction = metrics.transactionMetrics.last else {
            return
        }

        let tlsVersion = transaction.negotiatedTLSProtocolVersion.map {
            Self.describeTLSVersion($0)
        }
        let cipherSuite = transaction.negotiatedTLSCipherSuite.map {
            Self.describeCipherSuite($0)
        }

        lock.lock()
        _tlsMetadata = TLSMetadata(tlsVersion: tlsVersion, cipherSuite: cipherSuite)
        lock.unlock()
    }

    private static func describeTLSVersion(_ version: tls_protocol_version_t) -> String {
        switch version.rawValue {
        case 0x0301:
            return "TLS 1.0"
        case 0x0302:
            return "TLS 1.1"
        case 0x0303:
            return "TLS 1.2"
        case 0x0304:
            return "TLS 1.3"
        default:
            return String(describing: version)
        }
    }

    private static func describeCipherSuite(_ suite: tls_ciphersuite_t) -> String {
        switch suite.rawValue {
        case 0x1301:
            return "TLS_AES_128_GCM_SHA256"
        case 0x1302:
            return "TLS_AES_256_GCM_SHA384"
        case 0x1303:
            return "TLS_CHACHA20_POLY1305_SHA256"
        case 0xC02F:
            return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        case 0xC030:
            return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        case 0xC02B:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        case 0xC02C:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        case 0xCCA8:
            return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        case 0xCCA9:
            return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        default:
            return String(format: "0x%04X", suite.rawValue)
        }
    }
}
