import Foundation
import DeviceCheck
import MachO

/// FightRE iOS guard — reference implementation.
///
/// The same rules as the Android guard: checks are advisory, the server decides,
/// and signal names match fightre/signals.py. Compile into your app; call
/// `FightREGuard.run()` off the main thread at launch and on foreground.
enum FightREGuard {

    struct Signal {
        let name: String
        let weight: Int
        let detected: Bool
        let detail: String
    }

    private static let fridaPorts = [27042, 27043]

    private static let jailbreakPaths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt",
        "/var/jb",
        "/usr/lib/libhooker.dylib",
        "/usr/lib/libsubstitute.dylib"
    ]

    private static let jailbreakSchemes = ["cydia://", "sileo://", "zbra://", "filza://"]

    /// Run every check. Returns all signals; use `findings()` for only the fired ones.
    static func run() -> [Signal] {
        [fridaPortsCheck(), debuggerCheck(), jailbreakCheck(), hookCheck()]
    }

    static func findings() -> [Signal] {
        run().filter { $0.detected }
    }

    // MARK: - Instrumentation

    private static func fridaPortsCheck() -> Signal {
        var open: [Int] = []
        for port in fridaPorts {
            let socketFD = socket(AF_INET, SOCK_STREAM, 0)
            if socketFD < 0 { continue }
            defer { close(socketFD) }
            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = in_port_t(UInt16(port).bigEndian)
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            let result = withUnsafePointer(to: &addr) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { raw in
                    connect(socketFD, raw, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if result == 0 { open.append(port) }
        }
        return Signal(
            name: "client.instrumentation_detected",
            weight: 70,
            detected: !open.isEmpty,
            detail: open.isEmpty ? "" : "frida port(s): \(open)"
        )
    }

    private static func debuggerCheck() -> Signal {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = name.withUnsafeMutableBufferPointer { buffer in
            sysctl(buffer.baseAddress, u_int(buffer.count), &info, &size, nil, 0)
        }
        let traced = result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
        return Signal(
            name: "client.debugger_attached",
            weight: 55,
            detected: traced,
            detail: traced ? "P_TRACED set" : ""
        )
    }

    // MARK: - Device posture

    private static func jailbreakCheck() -> Signal {
        let paths = jailbreakPaths.filter { FileManager.default.fileExists(atPath: $0) }
        let schemes = jailbreakSchemes.filter { UIApplication.shared.canOpenURL(URL(string: $0)!) }

        // Sandbox escape probe: writing outside the container fails on stock iOS.
        let escaped = (try? "probe".write(
            toFile: "/private/fightre_probe",
            atomically: true,
            encoding: .utf8
        )) != nil
        if escaped {
            try? FileManager.default.removeItem(atPath: "/private/fightre_probe")
        }

        let detected = !paths.isEmpty || !schemes.isEmpty || escaped
        var detail: [String] = []
        if let first = paths.first { detail.append("path: \(first)") }
        if let first = schemes.first { detail.append("scheme: \(first)") }
        if escaped { detail.append("sandbox escape") }

        return Signal(
            name: "client.root_or_jailbreak",
            weight: 35,
            detected: detected,
            detail: detail.joined(separator: ", ")
        )
    }

    private static func hookCheck() -> Signal {
        // Substrate/Substitute leave known images loaded in the process.
        let markers = ["MobileSubstrate", "libsubstitute", "libhooker", "frida"]
        let detected = markers.contains { marker in
            _dyld_image_count() > 0 && (0..<_dyld_image_count()).contains { index in
                guard let name = _dyld_get_image_name(index) else { return false }
                return String(cString: name).lowercased().contains(marker.lowercased())
            }
        }
        return Signal(
            name: "client.instrumentation_detected",
            weight: 70,
            detected: detected,
            detail: detected ? "hook library loaded" : ""
        )
    }

    // MARK: - Hardware attestation

    /// The only check the server should treat as authoritative.
    ///
    /// `DCAppAttestService` (iOS 14+) attests that a request came from an
    /// unmodified build of your app on genuine Apple hardware. Generate a key
    /// once, ask Apple for an attestation bound to a server nonce, and verify the
    /// signature chain server-side before granting a session:
    ///
    ///     let service = DCAppAttestService.shared
    ///     guard service.isSupported else { return nil }
    ///     let keyId = try await service.generateKey()
    ///     let attestation = try await service.attestKey(keyId, clientDataHash: nonceHash)
    ///
    /// A jailbreak check can be patched out; an App Attest verdict cannot.
    enum Integrity {
        static func isSupported() -> Bool {
            if #available(iOS 14.0, *) {
                return DCAppAttestService.shared.isSupported
            }
            return false
        }
    }
}
