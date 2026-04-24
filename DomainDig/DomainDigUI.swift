import SwiftUI

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

enum AppDensity: String, CaseIterable, Identifiable {
    case compact
    case comfortable

    static let userDefaultsKey = "appDensity"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .compact:
            return "Compact"
        case .comfortable:
            return "Comfortable"
        }
    }

    var metrics: AppDensityMetrics {
        switch self {
        case .compact:
            return AppDensityMetrics(
                sectionSpacing: 14,
                cardSpacing: 6,
                cardPadding: 10,
                rowSpacing: 4,
                rowMinHeight: 30,
                controlVerticalPadding: 10,
                controlMinHeight: 42,
                cardCornerRadius: 10
            )
        case .comfortable:
            return AppDensityMetrics(
                sectionSpacing: 18,
                cardSpacing: 10,
                cardPadding: 14,
                rowSpacing: 7,
                rowMinHeight: 38,
                controlVerticalPadding: 14,
                controlMinHeight: 48,
                cardCornerRadius: 14
            )
        }
    }

    func font(_ textStyle: Font.TextStyle, design: Font.Design = .monospaced, weight: Font.Weight? = nil) -> Font {
        var font = Font.system(textStyle, design: design)
        if let weight {
            font = font.weight(weight)
        }
        return font
    }
}

struct AppDensityMetrics: Equatable {
    let sectionSpacing: CGFloat
    let cardSpacing: CGFloat
    let cardPadding: CGFloat
    let rowSpacing: CGFloat
    let rowMinHeight: CGFloat
    let controlVerticalPadding: CGFloat
    let controlMinHeight: CGFloat
    let cardCornerRadius: CGFloat
}

private struct AppDensityKey: EnvironmentKey {
    static let defaultValue: AppDensity = .compact
}

extension EnvironmentValues {
    var appDensity: AppDensity {
        get { self[AppDensityKey.self] }
        set { self[AppDensityKey.self] = newValue }
    }
}

struct AppStatusBadgeModel: Equatable {
    let title: String
    let systemImage: String?
    let foregroundColor: Color
    let backgroundColor: Color
}

enum AppStatusFactory {
    static func availability(_ status: DomainAvailabilityStatus?) -> AppStatusBadgeModel {
        switch status {
        case .available:
            return .init(title: "Available", systemImage: "checkmark.circle.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        case .registered:
            return .init(title: "Registered", systemImage: "circle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        case .unknown, .none:
            return .init(title: "Unknown", systemImage: "questionmark.circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }
    }

    static func tls(sslInfo: SSLCertificateInfo?, error: String?) -> AppStatusBadgeModel {
        if error != nil || sslInfo == nil {
            return .init(title: "Invalid", systemImage: "xmark.octagon.fill", foregroundColor: .red, backgroundColor: .red.opacity(0.16))
        }
        if let sslInfo, sslInfo.daysUntilExpiry <= 14 {
            return .init(title: "Expiring", systemImage: "exclamationmark.triangle.fill", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        }
        return .init(title: "Valid", systemImage: "lock.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
    }

    static func email(_ result: EmailSecurityResult?, error: String?) -> AppStatusBadgeModel {
        guard error == nil, let result else {
            return .init(title: "Missing", systemImage: "minus.circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }

        let foundCount = [result.spf.found, result.dmarc.found, result.dkim.found].filter { $0 }.count
        switch foundCount {
        case 3:
            return .init(title: "Secure", systemImage: "checkmark.shield.fill", foregroundColor: .green, backgroundColor: .green.opacity(0.16))
        case 1, 2:
            return .init(title: "Partial", systemImage: "shield.lefthalf.filled", foregroundColor: .yellow, backgroundColor: .yellow.opacity(0.16))
        default:
            return .init(title: "Missing", systemImage: "minus.circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }
    }

    static func change(_ summary: DomainChangeSummary?) -> AppStatusBadgeModel {
        guard let summary else {
            return .init(title: "Unchanged", systemImage: "circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
        }
        if summary.hasChanges {
            return .init(title: "Changed", systemImage: "arrow.triangle.2.circlepath", foregroundColor: .cyan, backgroundColor: .cyan.opacity(0.16))
        }
        return .init(title: "Unchanged", systemImage: "checkmark.circle", foregroundColor: .secondary, backgroundColor: Color(.systemGray5).opacity(0.55))
    }
}

struct AppStatusBadgeView: View {
    @Environment(\.appDensity) private var appDensity

    let model: AppStatusBadgeModel

    var body: some View {
        HStack(spacing: 6) {
            if let systemImage = model.systemImage {
                Image(systemName: systemImage)
                    .font(.caption2)
            }
            Text(model.title)
        }
        .font(appDensity.font(.caption, weight: .semibold))
        .foregroundStyle(model.foregroundColor)
        .padding(.horizontal, 9)
        .padding(.vertical, 5)
        .background(model.backgroundColor)
        .clipShape(Capsule())
    }
}

struct AppCopyButton: View {
    @Environment(\.appDensity) private var appDensity
    @State private var didCopy = false

    let value: String
    let label: String

    var body: some View {
        Button {
            AppClipboard.copy(value)
            AppHaptics.copy()
            withAnimation(.easeInOut(duration: 0.18)) {
                didCopy = true
            }
            Task {
                try? await Task.sleep(nanoseconds: 900_000_000)
                await MainActor.run {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        didCopy = false
                    }
                }
            }
        } label: {
            Image(systemName: didCopy ? "checkmark" : "doc.on.doc")
                .font(appDensity.font(.caption))
                .foregroundStyle(didCopy ? Color.green : .secondary)
                .frame(width: 30, height: 30)
                .background(Color(.systemGray5).opacity(0.35))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .accessibilityLabel(didCopy ? "\(label) copied" : label)
    }
}

enum AppClipboard {
    static func copy(_ value: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = value
        #elseif canImport(AppKit)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
        #endif
    }
}

enum AppHaptics {
    static func copy() {
        #if canImport(UIKit)
        let generator = UINotificationFeedbackGenerator()
        generator.notificationOccurred(.success)
        #endif
    }

    static func refresh() {
        #if canImport(UIKit)
        let generator = UIImpactFeedbackGenerator(style: .light)
        generator.impactOccurred()
        #endif
    }

    static func track() {
        #if canImport(UIKit)
        let generator = UIImpactFeedbackGenerator(style: .soft)
        generator.impactOccurred()
        #endif
    }
}

struct EmptyStateCardView: View {
    @Environment(\.appDensity) private var appDensity

    let title: String
    let message: String
    let suggestion: String
    let systemImage: String
    let showsCardBackground: Bool

    init(
        title: String,
        message: String,
        suggestion: String,
        systemImage: String,
        showsCardBackground: Bool = true
    ) {
        self.title = title
        self.message = message
        self.suggestion = suggestion
        self.systemImage = systemImage
        self.showsCardBackground = showsCardBackground
    }

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            Label(title, systemImage: systemImage)
                .font(appDensity.font(.headline, weight: .semibold))
                .foregroundStyle(.primary)

            Text(message)
                .font(appDensity.font(.body))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Text(suggestion)
                .font(appDensity.font(.caption))
                .foregroundStyle(.cyan)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(appDensity.metrics.cardPadding)
        .background(showsCardBackground ? Color(.systemGray6).opacity(0.45) : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: appDensity.metrics.cardCornerRadius))
    }
}

struct CollapsibleSectionView<HeaderTrailing: View, Content: View>: View {
    @Environment(\.appDensity) private var appDensity

    let title: String
    @Binding var isCollapsed: Bool
    let subtitle: String?
    @ViewBuilder let trailing: () -> HeaderTrailing
    @ViewBuilder let content: () -> Content

    init(
        title: String,
        isCollapsed: Binding<Bool>,
        subtitle: String? = nil,
        @ViewBuilder trailing: @escaping () -> HeaderTrailing = { EmptyView() },
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        self._isCollapsed = isCollapsed
        self.subtitle = subtitle
        self.trailing = trailing
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: appDensity.metrics.cardSpacing) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    isCollapsed.toggle()
                }
            } label: {
                HStack(alignment: .center, spacing: 10) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .font(appDensity.font(.headline, design: .default, weight: .semibold))
                            .foregroundStyle(.white)
                        if let subtitle {
                            Text(subtitle)
                                .font(appDensity.font(.caption))
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 8)
                    trailing()
                    Image(systemName: isCollapsed ? "chevron.down" : "chevron.up")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
                .frame(minHeight: appDensity.metrics.controlMinHeight, alignment: .center)
            }
            .buttonStyle(.plain)

            if !isCollapsed {
                content()
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }
}
