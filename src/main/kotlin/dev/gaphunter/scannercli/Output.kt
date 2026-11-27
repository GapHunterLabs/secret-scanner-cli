package dev.gaphunter.scannercli

/** How findings are shown: how much of each secret, how many findings, and the run's numbers. */
data class View(
    /** Leading characters of each secret to show (`--reveal`); null = the masked view `abcd...wxyz`. */
    val reveal: Int? = null,
    /** Findings listed at most (`--max-findings`); null = all. The exit code always counts all of them. */
    val maxFindings: Int? = null,
    /** Printed after the findings in text, embedded in JSON and SARIF; null = none (0.2.0 output). */
    val stats: ScanStats? = null,
    val toolSha256: String? = null,
)

internal object Mask {
    const val MAX_REVEAL = 64

    /**
     * The masked view of a secret: 4 leading and 4 trailing characters for 16 or more,
     * 2 leading for 8 to 15, nothing below that. Never the whole secret.
     */
    fun masked(hit: ScanHit, reveal: Int? = null): String {
        val len = hit.secretLength
        if (len == 0) return ""
        if (reveal != null) {
            val n = minOf(reveal, hit.secretHead.length, len)
            return if (n >= len) hit.secretHead else hit.secretHead.take(n) + "..."
        }
        return when {
            len >= 16 -> hit.secretHead.take(4) + "..." + hit.secretTail
            len >= 8 -> hit.secretHead.take(2) + "..."
            else -> "..."
        }
    }
}

/**
 * Text that is safe to print to a terminal or a CI log: every control character
 * (C0, DEL, C1, which covers ANSI escape sequences) and every bidirectional
 * override (the "Trojan Source" characters) becomes a visible `\uXXXX`. A file
 * name with an escape sequence in it (legal on Linux) used to recolor or rewrite
 * the terminal, and a reader of the log could not tell what was real.
 */
internal fun consoleSafe(value: String): String {
    var clean = true
    for (c in value) if (unsafe(c)) { clean = false; break }
    if (clean) return value
    val sb = StringBuilder(value.length + 16)
    for (c in value) if (unsafe(c)) sb.append("\\u%04x".format(c.code)) else sb.append(c)
    return sb.toString()
}

private fun unsafe(c: Char): Boolean =
    c < ' ' || c in '\u007f'..'\u009f' || c in '‪'..'‮' || c in '⁦'..'⁩' ||
        c == '‎' || c == '‏' || c == '؜' || c == ' ' || c == ' '

private val ORDER = compareBy<ScanHit>({ it.file }, { it.line }, { it.column }, { it.kind })

private fun shown(hits: List<ScanHit>, view: View): List<ScanHit> {
    val sorted = hits.sortedWith(ORDER)
    return if (view.maxFindings != null && sorted.size > view.maxFindings) sorted.take(view.maxFindings) else sorted
}

private fun formatBytes(b: Long): String = when {
    b >= 1024 * 1024 -> "%.1f MB".format(java.util.Locale.ROOT, b / 1048576.0)
    b >= 1024 -> "%.1f KB".format(java.util.Locale.ROOT, b / 1024.0)
    else -> "$b bytes"
}

/** The numbers of a run, as the text summary prints them (one line per item). */
internal fun summaryLines(hits: List<ScanHit>, stats: ScanStats): List<String> {
    val out = mutableListOf<String>()
    val skipped = listOf(
        "too large" to stats.tooLarge.size, "binary" to stats.binary.size,
        "unreadable" to stats.unreadable.size, "outside links" to stats.externalLinks.size,
    ).filter { it.second > 0 }
    val skipText = if (skipped.isEmpty()) "" else "; skipped ${stats.skipped} (${skipped.joinToString(", ") { "${it.second} ${it.first}" }})"
    val excludedText = if (stats.excluded > 0) "; excluded ${stats.excluded} by ignore rules" else ""
    out += "secret-scanner-cli: scanned ${stats.filesScanned} file(s), ${formatBytes(stats.bytesScanned)}, in " +
        "%.2f s".format(java.util.Locale.ROOT, stats.durationMs / 1000.0) + skipText + excludedText
    if (hits.isNotEmpty()) {
        val byRule = hits.groupingBy { it.kind }.eachCount().toSortedMap()
        out += "secret-scanner-cli: by rule: " + byRule.entries.joinToString(", ") { "${it.key} ${it.value}" }
        val bySeverity = Severity.entries.reversed().mapNotNull { s -> hits.count { it.severity == s }.takeIf { it > 0 }?.let { "$it ${s.label}" } }
        out += "secret-scanner-cli: by severity: " + bySeverity.joinToString(", ")
    }
    return out
}

// internal, not private: the tests exercise the renderers directly.
internal fun renderText(hits: List<ScanHit>, root: java.io.File): String = renderText(hits, root.path)

internal fun renderText(hits: List<ScanHit>, label: String, view: View = View()): String {
    val lines = mutableListOf<String>()
    if (hits.isEmpty()) {
        lines += "secret-scanner-cli: no findings in ${consoleSafe(label)}"
    } else {
        for (h in shown(hits, view)) {
            val masked = Mask.masked(h, view.reveal)
            val tag = if (h.testPath) " [test-or-example]" else ""
            lines += consoleSafe("${h.file}:${h.line}:${h.column}: [${h.kind}] [${h.severity.label}] ${h.description}" +
                (if (masked.isEmpty()) "" else " ($masked)") + tag)
        }
        lines += ""
        val hidden = hits.size - shown(hits, view).size
        if (hidden > 0) lines += "secret-scanner-cli: $hidden more finding(s) not shown (--max-findings ${view.maxFindings})"
        lines += "secret-scanner-cli: ${hits.size} finding(s) in ${consoleSafe(label)}"
    }
    view.stats?.let { lines += summaryLines(hits, it) }
    return lines.joinToString("\n")
}

/**
 * A stable id per finding for SARIF's `partialFingerprints` and the JSON output:
 * the rule, the path, the SHA-256 of the secret and which occurrence of that
 * same secret in that same file it is. No line number, so a finding that moves
 * down a few lines is the same alert on the next run, not a new one. Built from
 * a hash of the secret, never from the secret.
 */
internal fun fingerprints(hits: List<ScanHit>, uriPrefix: String = ""): Map<ScanHit, String> {
    val out = HashMap<ScanHit, String>()
    hits.sortedWith(ORDER).groupBy { Triple(it.kind, uriPrefix + it.file, it.secretSha256) }.forEach { (key, group) ->
        group.forEachIndexed { n, hit ->
            out[hit] = Scanner.sha256Hex("v1\u0000${key.first}\u0000${key.second}\u0000${key.third}\u0000$n").take(32)
        }
    }
    return out
}

private fun jsonString(value: String) = "\"" + jsonEscape(value) + "\""

private fun statsJson(hits: List<ScanHit>, stats: ScanStats?, shownCount: Int, indent: String, timing: Boolean = true): String {
    val byRule = hits.groupingBy { it.kind }.eachCount().toSortedMap().entries.joinToString(", ") { "${jsonString(it.key)}: ${it.value}" }
    val bySeverity = Severity.entries.joinToString(", ") { s -> "${jsonString(s.label)}: ${hits.count { it.severity == s }}" }
    val parts = mutableListOf(
        "\"findings\": ${hits.size}", "\"shown\": $shownCount", "\"bySeverity\": {$bySeverity}", "\"byRule\": {$byRule}",
    )
    if (stats != null) {
        fun list(l: List<String>) = l.joinToString(", ", "[", "]") { jsonString(it) }
        parts += listOf(
            "\"filesScanned\": ${stats.filesScanned}", "\"bytesScanned\": ${stats.bytesScanned}",
            "\"excluded\": ${stats.excluded}",
        ) + (if (timing) listOf("\"durationMs\": ${stats.durationMs}") else emptyList()) + listOf(
            "\"skipped\": {\"tooLarge\": ${list(stats.tooLarge)}, \"binary\": ${list(stats.binary)}, " +
                "\"unreadable\": ${list(stats.unreadable)}, \"externalLinks\": ${list(stats.externalLinks)}}",
        )
    }
    return parts.joinToString(",\n$indent")
}

internal fun renderJson(hits: List<ScanHit>, view: View = View(), uriPrefix: String = ""): String {
    val list = shown(hits, view)
    val fp = fingerprints(hits, uriPrefix)
    val findings = list.joinToString(",\n") { h ->
        val tags = if (h.testPath) "[\"test-or-example\"]" else "[]"
        """    {"file": ${jsonString(uriPrefix + h.file)}, "line": ${h.line}, "column": ${h.column}, "endColumn": ${h.endColumn}, """ +
            """"rule": ${jsonString(h.kind)}, "severity": ${jsonString(h.severity.label)}, "description": ${jsonString(h.description)}, """ +
            """"masked": ${jsonString(Mask.masked(h, view.reveal))}, "fingerprint": ${jsonString(fp.getValue(h))}, "tags": $tags}"""
    }
    val sha = view.toolSha256?.let { ", \"sha256\": ${jsonString(it)}" } ?: ""
    return """
{
  "tool": {"name": "secret-scanner-cli", "version": "$VERSION"$sha},
  "summary": {
    ${statsJson(hits, view.stats, list.size, "    ")}
  },
  "findings": [
$findings
  ]
}
    """.trimIndent()
}

/**
 * What goes in front of every SARIF uri so it is relative to [workingDir], the
 * directory a CI job runs in (the repository root on GitHub Actions). Code
 * scanning resolves a relative uri against the repository root. A [root]
 * outside [workingDir] keeps uris relative to [root]; no absolute path is ever
 * written, since it would put the local user's home directory into the report.
 */
internal fun sarifUriPrefix(root: java.io.File, workingDir: java.io.File): String {
    val dir = (if (root.isFile) root.absoluteFile.parentFile else root.absoluteFile)?.normalize() ?: return ""
    val base = workingDir.absoluteFile.normalize()
    val rel = try {
        dir.relativeTo(base).path.replace(java.io.File.separatorChar, '/')
    } catch (e: IllegalArgumentException) {
        return ""  // another drive on Windows
    }
    if (rel.isEmpty()) return ""
    if (rel == ".." || rel.startsWith("../")) return ""
    return "$rel/"
}

internal fun renderSarif(hits: List<ScanHit>, uriPrefix: String = "", view: View = View()): String {
    val list = shown(hits, view)
    val fp = fingerprints(hits, uriPrefix)
    val rules = hits.map { it.kind }.distinct().sorted()
    val rulesJson = rules.joinToString(",\n") { kind ->
        val (text, severity) = SecretDetector.RULES[kind] ?: (kind to Severity.HIGH)
        """          {"id": ${jsonString(kind)}, "shortDescription": {"text": ${jsonString(text)}}, """ +
            """"defaultConfiguration": {"level": "${severity.sarifLevel}"}, """ +
            """"properties": {"tags": ["security", "secret"], "security-severity": "${severity.securitySeverity}", "precision": "${if (kind == SecretDetector.GENERIC_KIND) "medium" else "high"}"}}"""
    }
    val resultsJson = list.joinToString(",\n") { hit ->
        val masked = Mask.masked(hit, view.reveal)
        val text = hit.description + if (masked.isEmpty()) "" else " ($masked)"
        val tags = if (hit.testPath) ", \"properties\": {\"tags\": [\"test-or-example\"]}" else ""
        """    {
      "ruleId": ${jsonString(hit.kind)},
      "level": "${hit.severity.sarifLevel}",
      "message": {"text": ${jsonString(text)}},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": ${jsonString(sarifUri(uriPrefix + hit.file))}},
          "region": {"startLine": ${hit.line}, "startColumn": ${hit.column}, "endColumn": ${maxOf(hit.endColumn, hit.column)}}
        }
      }],
      "partialFingerprints": {"secretScanner/v1": "${fp.getValue(hit)}"}$tags
    }"""
    }
    val sha = view.toolSha256?.let { ", \"properties\": {\"sha256\": ${jsonString(it)}}" } ?: ""
    return """
{
  "${'$'}schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "secret-scanner-cli",
        "informationUri": "https://github.com/GapHunterLabs/secret-scanner-cli",
        "version": "$VERSION"$sha,
        "rules": [
$rulesJson
        ]
      }
    },
    "columnKind": "utf16CodeUnits",
    "properties": {
      ${statsJson(hits, view.stats, list.size, "      ", timing = false)}
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
            c < ' ' || c == ' ' || c == ' ' || c == '\u007f' -> sb.append("\\u%04x".format(c.code))
            else -> sb.append(c)
        }
    }
    return sb.toString()
}

private const val URI_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=@/"

/**
 * A relative path as an RFC 3986 URI reference for SARIF's artifactLocation.uri:
 * a space, `#`, `%`, `?`, `:` or any non-ASCII character is percent-encoded.
 */
internal fun sarifUri(path: String): String {
    val sb = StringBuilder(path.length)
    for (b in path.toByteArray(Charsets.UTF_8)) {
        val c = (b.toInt() and 0xFF).toChar()
        if (b >= 0 && c in URI_SAFE) sb.append(c) else sb.append("%%%02X".format(b.toInt() and 0xFF))
    }
    return sb.toString()
}
