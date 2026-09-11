import Foundation
import Security

/// A person's permission for one keychain read to show the password dialogue.
///
/// Granted by "Allow access…" and by nothing else. Spent by the read it is
/// taken for, whatever that read's outcome — a Deny that left it standing would
/// hand the next poll a dialogue to show. And it lapses: the click is followed
/// by a refresh at once, but where that refresh never reached the keychain the
/// permission would otherwise sit there until some later poll spent it, and the
/// dialogue would appear on a timer after all.
final class PromptPermission: @unchecked Sendable {
    static let window: TimeInterval = 60

    private let now: () -> Date
    private var owedUntil: Date?
    private let lock = NSLock()

    init(now: @escaping () -> Date = Date.init) {
        self.now = now
    }

    func grant() {
        lock.lock()
        owedUntil = now().addingTimeInterval(Self.window)
        lock.unlock()
    }

    func take() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let until = owedUntil else { return false }
        owedUntil = nil
        return now() < until
    }
}

/// Background reads must stay in this process: the interaction setting does
/// not apply to a spawned `security` process, which can display its own prompt.
enum KeychainSecret {
    private static let interactionLock = NSLock()

    static func read(query: [CFString: Any], interactive: Bool) -> (status: OSStatus, data: Data?) {
        interactionLock.lock()
        defer { interactionLock.unlock() }

        var wasAllowed: DarwinBoolean = true
        if !interactive {
            SecKeychainGetUserInteractionAllowed(&wasAllowed)
            SecKeychainSetUserInteractionAllowed(false)
        }
        defer { if !interactive { SecKeychainSetUserInteractionAllowed(wasAllowed.boolValue) } }

        var query = query
        if !interactive { query[kSecUseAuthenticationUI] = kSecUseAuthenticationUIFail }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? Data)
    }
}
