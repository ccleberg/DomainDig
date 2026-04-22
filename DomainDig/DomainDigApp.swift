//
//  DomainDigApp.swift
//  DomainDig
//
//  Created by cmc on 2026-03-10.
//

import SwiftUI

@main
struct DomainDigApp: App {
    @AppStorage(AppDensity.userDefaultsKey) private var density = AppDensity.compact.rawValue
    @State private var viewModel = DomainViewModel()
    @State private var purchaseService = PurchaseService.shared

    init() {
        LocalNotificationService.shared.configureForegroundPresentation()
    }

    var body: some Scene {
        WindowGroup {
            RootTabView(viewModel: viewModel)
                .environment(\.appDensity, AppDensity(rawValue: density) ?? .compact)
                .task {
                    let _ = purchaseService.currentTier
                    await purchaseService.refreshEntitlements()
                }
        }
    }
}
