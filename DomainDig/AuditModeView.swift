import SwiftUI

struct AuditModeView: View {
    @Bindable var viewModel: DomainViewModel
    @State private var auditStore = AuditStore()
    @State private var reviewer = "Local Reviewer"
    @State private var selectedSession: AuditSession?
    @State private var exportMessage: String?

    var body: some View {
        List {
            Section("Start Audit") {
                TextField("Domain", text: $viewModel.domain)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                TextField("Reviewer", text: $reviewer)
                Button("Start Audit") {
                    let domain = viewModel.domain.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !domain.isEmpty else { return }
                    auditStore.startAudit(domain: domain, reviewer: reviewer, source: viewModel)
                }
                .disabled(viewModel.domain.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Section("Audit Timeline") {
                if auditStore.sessions.isEmpty {
                    Text("No audits yet.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(auditStore.sessions) { session in
                        Button {
                            selectedSession = session
                        } label: {
                            VStack(alignment: .leading) {
                                Text(session.domain).font(.headline)
                                Text("\(session.createdAt.formatted(date: .abbreviated, time: .shortened)) • \(session.status.title)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle("Audit Mode")
        .sheet(item: $selectedSession) { session in
            AuditSessionDetailView(session: session) { updated in
                auditStore.update(session: updated)
                selectedSession = updated
            } onExport: { updated, format in
                do {
                    let url = try await auditStore.export(session: updated, format: format)
                    exportMessage = "Exported to \(url.lastPathComponent)"
                } catch {
                    exportMessage = "Export failed: \(error.localizedDescription)"
                }
            }
        }
        .alert("Audit Export", isPresented: Binding(get: { exportMessage != nil }, set: { if !$0 { exportMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(exportMessage ?? "")
        }
    }
}

private struct AuditSessionDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @State var session: AuditSession
    let onSave: (AuditSession) -> Void
    let onExport: (AuditSession, AuditExportFormat) async -> Void

    var body: some View {
        NavigationStack {
            List {
                Section("Session") {
                    Text(session.domain)
                    Picker("Status", selection: $session.status) {
                        ForEach(AuditStatus.allCases, id: \.self) { Text($0.title).tag($0) }
                    }
                    TextField("Notes", text: $session.notes, axis: .vertical)
                }
                Section("Checklist") {
                    ForEach($session.checklist) { $item in
                        Toggle(item.title, isOn: $item.isComplete)
                    }
                }
                Section("Findings") {
                    ForEach($session.findings) { $finding in
                        VStack(alignment: .leading) {
                            TextField("Title", text: $finding.title)
                            Picker("Severity", selection: $finding.severity) {
                                ForEach(AuditFindingSeverity.allCases, id: \.self) { Text($0.rawValue.capitalized).tag($0) }
                            }
                            TextField("Summary", text: $finding.summary, axis: .vertical)
                        }
                    }
                    Button("Add Finding") {
                        session.findings.append(.init(title: "New finding", severity: .informational, summary: ""))
                    }
                }
                Section("Export") {
                    ForEach(AuditExportFormat.allCases) { format in
                        Button("Export \(format.rawValue.uppercased())") {
                            Task { await onExport(session, format) }
                        }
                    }
                }
            }
            .navigationTitle("Audit Session")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Close") { dismiss() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Save") {
                        onSave(session)
                        dismiss()
                    }
                }
            }
        }
    }
}
