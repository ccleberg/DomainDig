import Foundation
import SwiftUI

enum AuditStatus: String, Codable, Sendable, CaseIterable {
    case draft
    case inReview
    case complete

    var title: String {
        switch self {
        case .draft: return "Draft"
        case .inReview: return "In Review"
        case .complete: return "Complete"
        }
    }
}

enum AuditFindingSeverity: String, Codable, Sendable, CaseIterable {
    case informational
    case low
    case medium
    case high
}

struct AuditEvidenceSnapshot: Codable, Sendable {
    var capturedAt: Date
    var dnsSections: [DNSSection]
    var headers: [HTTPHeader]
    var tls: SSLCertificateInfo?
    var redirects: [RedirectHop]
    var reachability: [PortReachability]
    var ownership: DomainOwnership?
    var ownershipHistory: [DomainOwnershipHistoryEvent]
    var dnsHistory: [DNSHistoryEvent]
    var screenshotPath: String?
}

struct AuditFinding: Codable, Sendable, Identifiable {
    var id: UUID
    var title: String
    var severity: AuditFindingSeverity
    var summary: String
    var evidenceReferences: [String]
    var notes: String
    var status: AuditStatus

    init(
        id: UUID = UUID(),
        title: String,
        severity: AuditFindingSeverity,
        summary: String,
        evidenceReferences: [String] = [],
        notes: String = "",
        status: AuditStatus = .draft
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.summary = summary
        self.evidenceReferences = evidenceReferences
        self.notes = notes
        self.status = status
    }
}

struct AuditChecklistItem: Codable, Sendable, Identifiable {
    var id: String
    var title: String
    var isComplete: Bool

    static let defaults: [AuditChecklistItem] = [
        .init(id: "dns_review", title: "DNS review", isComplete: false),
        .init(id: "certificate_review", title: "Certificate review", isComplete: false),
        .init(id: "redirect_review", title: "Redirect review", isComplete: false),
        .init(id: "header_review", title: "Header review", isComplete: false),
        .init(id: "ownership_review", title: "Ownership review", isComplete: false),
        .init(id: "infrastructure_review", title: "Infrastructure review", isComplete: false),
        .init(id: "monitoring_history_review", title: "Monitoring history review", isComplete: false)
    ]
}

struct AuditSession: Codable, Sendable, Identifiable {
    var id: UUID
    var domain: String
    var createdAt: Date
    var reviewer: String
    var status: AuditStatus
    var evidence: AuditEvidenceSnapshot
    var findings: [AuditFinding]
    var notes: String
    var checklist: [AuditChecklistItem]
}

enum AuditExportFormat: String, CaseIterable, Identifiable {
    case json
    case markdown
    case pdf

    var id: String { rawValue }
}

@MainActor
@Observable
final class AuditStore {
    private(set) var sessions: [AuditSession] = []
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let fileURL: URL

    init() {
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601

        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let directory = base.appendingPathComponent("DomainDig", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        self.fileURL = directory.appendingPathComponent("audits.json")
        load()
    }

    func startAudit(domain: String, reviewer: String, source: DomainViewModel) {
        let snapshot = AuditEvidenceSnapshot(
            capturedAt: Date(),
            dnsSections: source.dnsSections,
            headers: source.httpHeaders,
            tls: source.sslInfo,
            redirects: source.redirectChain,
            reachability: source.reachabilityResults,
            ownership: source.ownershipResult,
            ownershipHistory: source.ownershipHistory,
            dnsHistory: source.dnsHistory,
            screenshotPath: nil
        )
        let session = AuditSession(
            id: UUID(),
            domain: domain,
            createdAt: Date(),
            reviewer: reviewer,
            status: .draft,
            evidence: snapshot,
            findings: [],
            notes: "",
            checklist: AuditChecklistItem.defaults
        )
        sessions.insert(session, at: 0)
        persist()
    }

    func update(session: AuditSession) {
        guard let index = sessions.firstIndex(where: { $0.id == session.id }) else { return }
        sessions[index] = session
        persist()
    }

    func sessions(for domain: String) -> [AuditSession] {
        sessions.filter { $0.domain.caseInsensitiveCompare(domain) == .orderedSame }
            .sorted { $0.createdAt > $1.createdAt }
    }

    func export(session: AuditSession, format: AuditExportFormat) async throws -> URL {
        let exportDir = fileURL.deletingLastPathComponent().appendingPathComponent("exports", isDirectory: true)
        try FileManager.default.createDirectory(at: exportDir, withIntermediateDirectories: true)
        let stamp = ISO8601DateFormatter().string(from: session.createdAt).replacingOccurrences(of: ":", with: "-")
        let base = "audit-\(session.domain)-\(stamp)"
        switch format {
        case .json:
            let url = exportDir.appendingPathComponent("\(base).json")
            try encoder.encode(session).write(to: url)
            return url
        case .markdown:
            let url = exportDir.appendingPathComponent("\(base).md")
            try markdown(for: session).write(to: url, atomically: true, encoding: .utf8)
            return url
        case .pdf:
            let url = exportDir.appendingPathComponent("\(base).pdf")
            try markdown(for: session).write(to: url, atomically: true, encoding: .utf8)
            return url
        }
    }

    private func markdown(for session: AuditSession) -> String {
        var lines: [String] = []
        lines.append("# Audit Summary")
        lines.append("- Domain: \(session.domain)")
        lines.append("- Review date: \(session.createdAt.formatted(date: .abbreviated, time: .shortened))")
        lines.append("- Reviewer: \(session.reviewer)")
        lines.append("- Status: \(session.status.title)")
        lines.append("\n## Findings")
        for finding in session.findings {
            lines.append("### \(finding.title) [\(finding.severity.rawValue)]")
            lines.append(finding.summary)
            if !finding.evidenceReferences.isEmpty {
                lines.append("Evidence: \(finding.evidenceReferences.joined(separator: ", "))")
            }
        }
        lines.append("\n## Notes")
        lines.append(session.notes)
        return lines.joined(separator: "\n")
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL), let decoded = try? decoder.decode([AuditSession].self, from: data) else { return }
        sessions = decoded.sorted { $0.createdAt > $1.createdAt }
    }

    private func persist() {
        guard let data = try? encoder.encode(sessions) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}
