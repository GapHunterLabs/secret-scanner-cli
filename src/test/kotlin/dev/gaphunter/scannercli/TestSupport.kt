package dev.gaphunter.scannercli

import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Test-only secrets, always assembled at runtime from pieces so that no
 * complete provider-format token is ever committed to this public repository
 * (push protection and other scanners would rightly flag one). Every value is
 * fake: GitHub tokens fail their checksum, the AWS key has the right shape but is made up
 * (AWS's documented example key, ending in EXAMPLE, is treated as a placeholder since 0.3.0), the Stripe key is the one Stripe's public docs show.
 */
internal object Fake {
    val AWS = "AKIA" + "Q7LM2XV9RT4KP8WZ"
    val GITHUB = "ghp_" + "a".repeat(36)
    val SLACK = "xox" + "b-" + "1234567890-abcdefghij"
    val JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJmYWtlIn0" + "." + "ZmFrZXNpZ25hdHVyZQ"
    val PEM = "-----BEGIN RSA " + "PRIVATE KEY-----"
    val STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    const val GENERIC = "Xk9mQ2pL8vRnZ4wT7Ba3"

    /** kind -> a line that must produce exactly that kind, and the secret the line holds. */
    val BY_KIND: Map<String, Pair<String, String>> = linkedMapOf(
        "AWS_ACCESS_KEY" to ("AWS_ACCESS_KEY_ID=$AWS" to AWS),
        "GITHUB_TOKEN" to ("val gh = \"$GITHUB\"" to GITHUB),
        "SLACK_TOKEN" to ("slack: \"$SLACK\"" to SLACK),
        "JWT" to ("auth: \"$JWT\"" to JWT),
        "PRIVATE_KEY" to ("key: \"$PEM\"" to PEM),
        "STRIPE_KEY" to ("curl -u $STRIPE: https://api.example.com" to STRIPE),
        "GENERIC_HIGH_ENTROPY" to ("db.password=$GENERIC" to GENERIC),
    )
}

internal data class CliResult(val exitCode: Int, val stdout: String, val stderr: String)

/** Runs the CLI's real main() in a child JVM, so exitProcess codes and stream routing are observed for real. */
internal fun runCli(vararg args: String, workDir: File? = null, timeoutSeconds: Long = 60): CliResult {
    val java = File(System.getProperty("java.home"), "bin/java").path
    val cmd = listOf(java, "-Xmx256m", "-cp", System.getProperty("java.class.path"), "dev.gaphunter.scannercli.MainKt") + args
    val pb = ProcessBuilder(cmd)
    if (workDir != null) pb.directory(workDir)
    val outFile = File.createTempFile("cli-out", ".txt")
    val errFile = File.createTempFile("cli-err", ".txt")
    try {
        pb.redirectOutput(outFile).redirectError(errFile)
        val process = pb.start()
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            error("CLI did not finish in ${timeoutSeconds}s: $args")
        }
        return CliResult(process.exitValue(), outFile.readText(), errFile.readText())
    } finally {
        outFile.delete()
        errFile.delete()
    }
}

/**
 * Minimal strict JSON parser (RFC 8259) used only to prove the SARIF output is
 * valid JSON: rejects raw control characters in strings, bad escapes, trailing
 * commas and trailing garbage. Returns Map/List/String/Double/Boolean/null.
 */
internal class StrictJson(private val s: String) {
    private var i = 0

    fun parse(): Any? {
        val v = value()
        ws()
        if (i != s.length) fail("trailing content")
        return v
    }

    private fun fail(msg: String): Nothing = throw IllegalArgumentException("$msg at offset $i")

    private fun ws() {
        while (i < s.length && s[i] in " \t\r\n") i++
    }

    private fun value(): Any? {
        ws()
        if (i >= s.length) fail("unexpected end")
        return when (s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> lit("true", true)
            'f' -> lit("false", false)
            'n' -> lit("null", null)
            else -> num()
        }
    }

    private fun lit(word: String, v: Any?): Any? {
        if (!s.startsWith(word, i)) fail("bad literal")
        i += word.length
        return v
    }

    private fun num(): Double {
        val m = Regex("""-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?""").matchAt(s, i) ?: fail("bad number")
        i += m.value.length
        return m.value.toDouble()
    }

    private fun str(): String {
        i++
        val sb = StringBuilder()
        while (true) {
            if (i >= s.length) fail("unterminated string")
            val c = s[i++]
            when {
                c == '"' -> return sb.toString()
                c == '\\' -> {
                    if (i >= s.length) fail("bad escape")
                    when (val e = s[i++]) {
                        '"', '\\', '/' -> sb.append(e)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(i, minOf(i + 4, s.length))
                            if (!hex.matches(Regex("[0-9a-fA-F]{4}"))) fail("bad \\u escape")
                            sb.append(hex.toInt(16).toChar())
                            i += 4
                        }
                        else -> fail("bad escape \\$e")
                    }
                }
                c < ' ' -> fail("raw control character U+%04X in string".format(c.code))
                else -> sb.append(c)
            }
        }
    }

    private fun obj(): Map<String, Any?> {
        i++
        val m = LinkedHashMap<String, Any?>()
        ws()
        if (s.getOrNull(i) == '}') { i++; return m }
        while (true) {
            ws()
            if (s.getOrNull(i) != '"') fail("expected key")
            val k = str()
            ws()
            if (s.getOrNull(i) != ':') fail("expected ':'")
            i++
            m[k] = value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> i++
                '}' -> { i++; return m }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun arr(): List<Any?> {
        i++
        val l = ArrayList<Any?>()
        ws()
        if (s.getOrNull(i) == ']') { i++; return l }
        while (true) {
            l += value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> i++
                ']' -> { i++; return l }
                else -> fail("expected ',' or ']'")
            }
        }
    }
}

@Suppress("UNCHECKED_CAST")
internal fun sarifResults(json: String): List<Map<String, Any?>> {
    val root = StrictJson(json).parse() as Map<String, Any?>
    val run = (root["runs"] as List<Any?>)[0] as Map<String, Any?>
    return run["results"] as List<Map<String, Any?>>
}

@Suppress("UNCHECKED_CAST")
internal fun sarifUris(json: String): List<String> = sarifResults(json).map { r ->
    val loc = (r["locations"] as List<Any?>)[0] as Map<String, Any?>
    val phys = loc["physicalLocation"] as Map<String, Any?>
    (phys["artifactLocation"] as Map<String, Any?>)["uri"] as String
}
