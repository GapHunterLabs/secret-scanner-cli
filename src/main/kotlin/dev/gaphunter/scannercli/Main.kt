package dev.gaphunter.scannercli

import java.io.File
import java.io.PrintStream
import kotlin.system.exitProcess

private const val VERSION = "0.1.0"

private data class Args(
    val path: File,
    val format: String,
    val outFile: File?,
    val failOnFind: Boolean,
    val bannerFlag: Boolean,
    val noBannerFlag: Boolean,
)

/** Thrown to end a run with an exit code; caught only by [cliMain]. */
private class CliExit(val code: Int) : RuntimeException(null, null, false, false)

/** Where a run writes, and whether a real console is attached (`System.console() != null`). */
private class Io(val out: PrintStream, val err: PrintStream, val isConsole: Boolean)

fun main(rawArgs: Array<String>) {
    val code = cliMain(rawArgs, System.out, System.err, System.console() != null)
    System.out.flush()
    if (code != 0) exitProcess(code)
}

/**
 * The whole CLI as a function that returns its exit code instead of ending the
 * process, so the tests run every argument and exit-code case in-process.
 * [main] is the only caller that turns the code into a real process exit.
 */
internal fun cliMain(rawArgs: Array<String>, out: PrintStream, err: PrintStream, isConsole: Boolean): Int {
    val io = Io(out, err, isConsole)
    return try {
        execute(rawArgs, io)
    } catch (e: CliExit) {
        e.code
    }
}

private fun execute(rawArgs: Array<String>, io: Io): Int {
    val args = parseArgs(rawArgs, io) ?: return 0

    if (!args.path.exists()) pathError(io, "path not found: ${args.path}")
    // Checked before the scan, not after: a bad --out used to surface only
    // once the whole scan had run, as an uncaught FileNotFoundException with
    // a stack trace and exit code 1, the same code that means "findings".
    args.outFile?.let { out -> outFileProblem(out)?.let { pathError(io, it) } }

    val machineReadable = args.format == "sarif" || args.outFile != null
    if (Banner.shouldShow(args.bannerFlag, args.noBannerFlag, io.isConsole, machineReadable)) {
        io.out.println(Banner.TEXT)
        io.out.println()
    }

    val hits = Scanner.scan(args.path)
    val output = when (args.format) {
        "sarif" -> renderSarif(hits, sarifUriPrefix(args.path, File("").absoluteFile))
        else -> renderText(hits, args.path)
    }

    if (args.outFile != null) {
        try {
            args.outFile.writeText(output)
        } catch (e: java.io.IOException) {
            pathError(io, "cannot write --out file ${args.outFile}: ${e.message}")
        }
    } else {
        io.out.println(output)
    }

    return if (hits.isNotEmpty() && args.failOnFind) 1 else 0
}

private fun parseArgs(rawArgs: Array<String>, io: Io): Args? {
    var path = File(".")
    var format = "text"
    var outFile: File? = null
    var failOnFind = true
    var bannerFlag = false
    var noBannerFlag = false
    var pathSeen = false

    var i = 0
    while (i < rawArgs.size) {
        when (val arg = rawArgs[i]) {
            "--format" -> {
                format = rawArgs.getOrNull(++i) ?: usageError(io, "--format needs a value (text|sarif)")
                if (format != "text" && format != "sarif") usageError(io, "unknown --format '$format' (expected text|sarif)")
            }
            "--out" -> {
                val value = rawArgs.getOrNull(++i) ?: usageError(io, "--out needs a file path")
                // `--out --no-fail` used to write a file literally named
                // "--no-fail" and drop the flag the user meant.
                if (value.startsWith("--")) usageError(io, "--out needs a file path, got the flag '$value'")
                outFile = File(value)
            }
            "--no-fail" -> failOnFind = false
            "--banner" -> bannerFlag = true
            "--no-banner" -> noBannerFlag = true
            "--version" -> { io.out.println("secret-scanner-cli $VERSION"); return null }
            "-h", "--help" -> {
                if (Banner.shouldShow(bannerFlag, noBannerFlag, io.isConsole, machineReadable = false)) {
                    io.out.println(Banner.TEXT)
                    io.out.println()
                }
                printHelp(io.out)
                return null
            }
            else -> {
                if (arg.startsWith("-")) usageError(io, "unknown flag '$arg'")
                // A second path used to replace the first one silently.
                if (pathSeen) usageError(io, "only one path can be scanned per run, got '$path' and '$arg'")
                path = File(arg)
                pathSeen = true
            }
        }
        i++
    }
    if (bannerFlag && noBannerFlag) usageError(io, "--banner and --no-banner are mutually exclusive")
    return Args(path, format, outFile, failOnFind, bannerFlag, noBannerFlag)
}

/** Why [out] can't be written, or null when it looks writable. Pure, so it is tested without a process exit. */
internal fun outFileProblem(out: File): String? {
    if (out.isDirectory) return "--out points to a directory, not a file: $out"
    val parent = out.absoluteFile.parentFile
    if (parent != null && !parent.isDirectory) return "--out directory does not exist: $parent"
    return null
}

private fun pathError(io: Io, message: String): Nothing {
    io.err.println("secret-scanner-cli: $message")
    throw CliExit(2)
}

private fun usageError(io: Io, message: String): Nothing {
    io.err.println("secret-scanner-cli: $message")
    // Help goes to stderr on a usage error, so `... --format sarif > out.sarif`
    // with a typo leaves no help text inside the file a later step parses.
    printHelp(io.err)
    throw CliExit(2)
}

private fun printHelp(stream: PrintStream) {
    stream.println(
        """
        secret-scanner-cli $VERSION -- local, offline secret scanning
        (ported from Gap Hunter Labs' api-security-companion detection engine)

        Usage: secret-scanner-cli [path] [options]

          path              Directory or single file to scan (default: current directory)
          --format <fmt>    Output format: text (default) or sarif
          --out <file>      Write output to a file instead of stdout
          --no-fail         Always exit 0, even if findings are reported
          --banner          Always print the startup banner (even piped or sarif)
          --no-banner       Never print the startup banner
          --version         Print version and exit
          -h, --help        Print this help and exit

        The startup banner shows by default only in an interactive terminal with
        --format text and no --out: never when the output is piped, redirected, or
        meant for a script or CI to parse.

        Exit codes: 0 = no findings (or --no-fail), 1 = findings reported, 2 = usage/path error.
        """.trimIndent()
    )
}

// internal, not private: OutputFormatTest exercises these directly
// rather than only through the process-exiting main() entrypoint.
internal fun renderText(hits: List<ScanHit>, root: File): String {
    if (hits.isEmpty()) return "secret-scanner-cli: no findings in ${root.path}"
    val lines = hits.sortedWith(compareBy({ it.file }, { it.line })).map {
        "${it.file}:${it.line}:${it.column}: [${it.kind}] ${it.description}"
    }
    return (lines + "" + "secret-scanner-cli: ${hits.size} finding(s) in ${root.path}").joinToString("\n")
}

private val RULE_DESCRIPTIONS = mapOf(
    "AWS_ACCESS_KEY" to "Hardcoded AWS access key ID",
    "GITHUB_TOKEN" to "Hardcoded GitHub personal access token",
    "SLACK_TOKEN" to "Hardcoded Slack API token",
    "JWT" to "Hardcoded JSON Web Token",
    "PRIVATE_KEY" to "Hardcoded PEM private key",
    "STRIPE_KEY" to "Hardcoded Stripe secret/restricted API key",
    "OPENAI_API_KEY" to "Hardcoded OpenAI API key",
    "ANTHROPIC_API_KEY" to "Hardcoded Anthropic API key",
    "HUGGINGFACE_TOKEN" to "Hardcoded Hugging Face access token",
    "GROQ_API_KEY" to "Hardcoded Groq API key",
    "PERPLEXITY_API_KEY" to "Hardcoded Perplexity API key",
    "GOOGLE_API_KEY" to "Hardcoded Google API key",
    "GITHUB_FINE_GRAINED_TOKEN" to "Hardcoded GitHub fine-grained personal access token",
    "GITLAB_TOKEN" to "Hardcoded GitLab personal access token",
    "NPM_TOKEN" to "Hardcoded npm access token",
    "PYPI_TOKEN" to "Hardcoded PyPI upload token",
    "SENDGRID_API_KEY" to "Hardcoded SendGrid API key",
    "SHOPIFY_TOKEN" to "Hardcoded Shopify access token",
    "DIGITALOCEAN_TOKEN" to "Hardcoded DigitalOcean personal access token",
    "DATABRICKS_TOKEN" to "Hardcoded Databricks access token",
    "VAULT_TOKEN" to "Hardcoded HashiCorp Vault service token",
    "SLACK_WEBHOOK" to "Hardcoded Slack incoming-webhook URL",
    "GENERIC_HIGH_ENTROPY" to "High-entropy value assigned to a credential-like variable name",
)

/**
 * What goes in front of every SARIF uri so it is relative to [workingDir], the
 * directory a CI job runs in (the repository root on GitHub Actions). Code
 * scanning resolves a relative uri against the repository root: scanning
 * `path: src` used to report `Config.kt` instead of `src/Config.kt`, so the
 * alert pointed at a file that does not exist. A [root] outside [workingDir]
 * keeps uris relative to [root]; no absolute path is ever written, since it
 * would put the local user's home directory into the report.
 */
internal fun sarifUriPrefix(root: File, workingDir: File): String {
    val dir = (if (root.isFile) root.absoluteFile.parentFile else root.absoluteFile)?.normalize() ?: return ""
    val base = workingDir.absoluteFile.normalize()
    val rel = try {
        dir.relativeTo(base).path.replace(File.separatorChar, '/')
    } catch (e: IllegalArgumentException) {
        return ""  // another drive on Windows
    }
    if (rel.isEmpty()) return ""
    if (rel == ".." || rel.startsWith("../")) return ""
    return "$rel/"
}

internal fun renderSarif(hits: List<ScanHit>, uriPrefix: String = ""): String {
    val rules = hits.map { it.kind }.distinct().sorted()
    val rulesJson = rules.joinToString(",\n") { kind ->
        """    {"id": "${jsonEscape(kind)}", "shortDescription": {"text": "${jsonEscape(RULE_DESCRIPTIONS[kind] ?: kind)}"}}"""
    }
    val resultsJson = hits.joinToString(",\n") { hit ->
        """    {
      "ruleId": "${jsonEscape(hit.kind)}",
      "level": "warning",
      "message": {"text": "${jsonEscape(hit.description)}"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "${jsonEscape(sarifUri(uriPrefix + hit.file))}"},
          "region": {"startLine": ${hit.line}, "startColumn": ${hit.column}}
        }
      }]
    }"""
    }
    return """
{
  "${'$'}schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "secret-scanner-cli",
        "informationUri": "https://github.com/GapHunterLabs/secret-scanner-cli",
        "version": "$VERSION",
        "rules": [
$rulesJson
        ]
      }
    },
    "results": [
$resultsJson
    ]
  }]
}
    """.trimIndent()
}

// Every control character is escaped, not only \n: a tab or any other
// character below U+0020 in a file name (legal on Linux) used to go into the
// SARIF raw, which is invalid JSON, so the action's jq step failed on it.
internal fun jsonEscape(value: String): String {
    val sb = StringBuilder(value.length + 8)
    for (c in value) {
        when {
            c == '\\' -> sb.append("\\\\")
            c == '"' -> sb.append("\\\"")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            c < ' ' || c == '\u2028' || c == '\u2029' -> sb.append("\\u%04x".format(c.code))
            else -> sb.append(c)
        }
    }
    return sb.toString()
}

private const val URI_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=@/"

/**
 * A relative path as an RFC 3986 URI reference for SARIF's artifactLocation.uri.
 * A space, `#`, `%`, `?`, `:` or any non-ASCII character in a file name used to
 * go in raw, which is not a valid URI reference. `:` is encoded too, so a name
 * like `c:x.kt` is never read as a URI scheme.
 */
internal fun sarifUri(path: String): String {
    val sb = StringBuilder(path.length)
    for (b in path.toByteArray(Charsets.UTF_8)) {
        val c = (b.toInt() and 0xFF).toChar()
        if (b >= 0 && c in URI_SAFE) sb.append(c) else sb.append("%%%02X".format(b.toInt() and 0xFF))
    }
    return sb.toString()
}
