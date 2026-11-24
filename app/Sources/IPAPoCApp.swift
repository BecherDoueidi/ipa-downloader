import SwiftUI

@main
struct IPAPoCApp: App {
    init() { KeychainStore.registerWithBridge() }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
