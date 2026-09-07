package dev.gaphunter.scannercli

import java.io.File

data class ScanHit(
    val file: String,
    val line: Int,
    val column: Int,
    val kind: String,
    val description: String,
)

object Scanner {

    // Directories never worth descending into: VCS metadata, build output,
    // dependency caches. Keeps a scan of a whole repo fast and avoids
    // reporting findings buried in third-party/generated code nobody owns.
    private val SKIP_DIRS = setOf(
        ".git", ".gradle", ".idea", "node_modules", "build", "dist",
        "target", "out", "vendor", ".venv", "venv", "__pycache__",
    )

    // Extensions worth reading as text. Binary files are skipped outright
    // rather than relying on a content sniff -- cheaper, and avoids any
    // chance of misreading binary bytes as a "high entropy string".
    private val SCAN_EXTENSIONS = setOf(
        "kt", "kts", "java", "py", "js", "jsx", "ts", "tsx", "go", "rb",
        "php", "cs", "cpp", "c", "h", "hpp", "rs", "swift", "sh", "bash",
        "yml", "yaml", "json", "properties", "env", "xml", "toml", "ini",
        "cfg", "conf", "gradle",
    )

    // Coarse assignment-line heuristic: `key = "value"` / `key: "value"` /
    // `"key": "value"` across Kotlin/Java/JS/Python/YAML/JSON/.properties-ish
    // syntax. Group 1 = key, group 2 = the quote character actually used,
    // group 3 = value -- the backreference to group 2 keeps `key = "value'`
    // (mismatched quotes) from matching. Deliberately regex-based, not a
    // real parser per language -- the same trade-off standalone scanners
    // like gitleaks/trufflehog make. Known blind spot: multi-line string
    // values are not matched.
    private val ASSIGNMENT_LINE = Regex(
        """["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*(["'])([^"'\n]{6,})\2"""
    )

    // .env/.properties/shell-export style: `KEY=value` or `key: value` with
    // no quotes at all, and exactly one assignment filling the whole line
    // (anchored ^...$) -- unlike the quoted pattern above, an unquoted value
    // has no delimiter to mark where it ends other than the line itself.
    // Tried only when the quoted pattern finds nothing on a line, so a
    // quoted JSON/Kotlin/JS-style line is never reinterpreted as this.
    private val UNQUOTED_ASSIGNMENT_LINE = Regex(
        """^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*(\S{6,})\s*$"""
    )

    private fun extractAssignments(line: String): List<Pair<String, String>> {
        val quoted = ASSIGNMENT_LINE.findAll(line).map { it.groupValues[1] to it.groupValues[3] }.toList()
        if (quoted.isNotEmpty()) return quoted
        val unquoted = UNQUOTED_ASSIGNMENT_LINE.find(line) ?: return emptyList()
        return listOf(unquoted.groupValues[1] to unquoted.groupValues[2])
    }

    fun scan(root: File): List<ScanHit> {
        val hits = mutableListOf<ScanHit>()
        root.walkTopDown()
            .onEnter { dir -> dir.name !in SKIP_DIRS }
            .filter { it.isFile && it.extension.lowercase() in SCAN_EXTENSIONS }
            .forEach { file -> hits += scanFile(file, root) }
        return hits
    }

    private fun scanFile(file: File, root: File): List<ScanHit> {
        val relativePath = file.relativeTo(root).path.replace('\\', '/')
        val lines = try {
            file.readLines()
        } catch (e: Exception) {
            // Unreadable despite a text extension (binary content, odd
            // encoding, permissions) -- skip it, never crash the whole scan
            // over one file.
            return emptyList()
        }

        val hits = mutableListOf<ScanHit>()
        lines.forEachIndexed { index, line ->
            val lineNumber = index + 1
            var matchedOnLine = false

            for ((key, value) in extractAssignments(line)) {
                val finding = SecretDetector.scanLiteral(value, key) ?: continue
                val column = line.indexOf(value).let { if (it >= 0) it + 1 else 1 }
                hits += ScanHit(relativePath, lineNumber, column, finding.kind, finding.description)
                matchedOnLine = true
            }

            // Format-signature secrets (AWS/GitHub/Slack/JWT/PEM/Stripe) can
            // appear outside a clean `key = "value"` assignment (e.g. inside
            // a shell command or a YAML flow value) -- scanLiteral on the
            // raw line still catches every fixed-format signature via
            // find()/containsMatchIn() (substring search, not a full match).
            // It can't catch GENERIC_HIGH_ENTROPY this way (that check needs
            // an isolated value + variable-name hint), which is exactly why
            // the assignment pass above exists. Skip if that pass already
            // found something on this line, to avoid double-reporting.
            if (!matchedOnLine) {
                SecretDetector.scanLiteral(line, null)?.let { finding ->
                    hits += ScanHit(relativePath, lineNumber, 1, finding.kind, finding.description)
                }
            }
        }
        return hits
    }
}
