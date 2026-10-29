package com.fightre.guard

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * FightRE Android guard — reference implementation.
 *
 * Design rules:
 *  - every check is advisory; the SERVER decides, using these signals plus its own
 *    attestation checks;
 *  - signals use the same names and weights as fightre/signals.py so the payload
 *    can be verified server-side without a translation table;
 *  - nothing here blocks the user by itself. A rooted developer device is not an
 *    attacker; it is a reason to ask for stronger proof.
 *
 * Compile into your app (Kotlin, no third-party dependency). Call [run] on a
 * background thread at startup and after resume.
 */
object FightREGuard {

    data class Signal(
        val name: String,
        val weight: Int,
        val detected: Boolean,
        val detail: String = ""
    )

    private val FRIDA_PORTS = intArrayOf(27042, 27043)

    private val ROOT_PATHS = listOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/magisk/.core/bin/su"
    )

    private val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser"
    )

    private val HOOK_PACKAGES = listOf(
        "de.robv.android.xposed",
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "com.saurik.substrate"
    )

    private val FRIDA_MARKERS = listOf(
        "frida", "gum-js-loop", "gum-js", "libfrida", "frida-agent", "linjector"
    )

    /** Run every check. Safe to call from a worker thread. */
    fun run(context: Context): List<Signal> = listOf(
        fridaPorts(),
        fridaInMaps(),
        debugger(),
        root(context),
        hookFramework(context),
        emulator()
    )

    /** Signals that fired, ready to be signed into an attestation payload. */
    fun findings(context: Context): List<Signal> = run(context).filter { it.detected }

    // -- instrumentation ---------------------------------------------------

    private fun fridaPorts(): Signal {
        val open = FRIDA_PORTS.filter { port ->
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("127.0.0.1", port), 120)
                    true
                }
            } catch (_: Exception) {
                false
            }
        }
        return Signal(
            "client.instrumentation_detected",
            70,
            open.isNotEmpty(),
            if (open.isEmpty()) "" else "frida port(s): ${open.joinToString()}"
        )
    }

    private fun fridaInMaps(): Signal {
        val hit = try {
            File("/proc/self/maps").useLines { lines ->
                lines.firstOrNull { line ->
                    FRIDA_MARKERS.any { marker -> line.contains(marker, ignoreCase = true) }
                }
            }
        } catch (_: Exception) {
            null
        }
        return Signal(
            "client.instrumentation_detected",
            70,
            hit != null,
            hit?.take(120) ?: ""
        )
    }

    private fun debugger(): Signal {
        val attached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        return Signal("client.debugger_attached", 55, attached, if (attached) "debugger attached" else "")
    }

    // -- device posture ----------------------------------------------------

    private fun root(context: Context): Signal {
        val paths = ROOT_PATHS.filter { File(it).exists() }
        val packages = ROOT_PACKAGES.filter { installed(context, it) }
        val testKeys = Build.TAGS?.contains("test-keys") == true
        val detected = paths.isNotEmpty() || packages.isNotEmpty() || testKeys
        val detail = buildList {
            if (paths.isNotEmpty()) add("su: ${paths.first()}")
            if (packages.isNotEmpty()) add("pkg: ${packages.first()}")
            if (testKeys) add("build tags=test-keys")
        }.joinToString(", ")
        return Signal("client.root_or_jailbreak", 35, detected, detail)
    }

    private fun hookFramework(context: Context): Signal {
        val packages = HOOK_PACKAGES.filter { installed(context, it) }
        return Signal(
            "client.instrumentation_detected",
            70,
            packages.isNotEmpty(),
            packages.joinToString()
        )
    }

    private fun emulator(): Signal {
        val fingerprints = listOf(
            Build.FINGERPRINT.startsWith("generic"),
            Build.FINGERPRINT.contains("emulator"),
            Build.MODEL.contains("Emulator"),
            Build.MODEL.contains("Android SDK built for"),
            Build.HARDWARE.contains("goldfish"),
            Build.HARDWARE.contains("ranchu"),
            Build.PRODUCT.contains("sdk")
        ).count { it } >= 2
        return Signal(
            "client.env_anomaly",
            18,
            fingerprints,
            if (fingerprints) "emulator build fingerprint" else ""
        )
    }

    private fun installed(context: Context, packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    // -- hardware attestation ---------------------------------------------

    /**
     * The interface the server actually trusts. Implement it with Play Integrity
     * (or your vendor), bind the token to a server nonce, and let the server
     * verify the signature chain:
     *
     *   val token = integrity.attest(serverNonce) ?: return null
     *   POST /_fightre/attest { nonce, integrity_token = token, env = collect() }
     *
     * A client-side check can be patched. A Play Integrity verdict cannot, which
     * is why it belongs in the same attestation payload as these signals.
     */
    fun interface IntegrityProvider {
        suspend fun attest(nonce: String): String?
    }
}
