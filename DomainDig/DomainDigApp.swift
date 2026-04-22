//
//  DomainDigApp.swift
//  DomainDig
//
//  Created by cmc on 2026-03-10.
//

import SwiftUI

@main
struct DomainDigApp: App {
    init() {
        LocalNotificationService.shared.configureForegroundPresentation()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
