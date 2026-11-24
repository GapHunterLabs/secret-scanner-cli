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
    //
    // The key is capped at 128 characters and matched possessively (`*+`
    // style, here `{0,127}+`). Without the cap, a long run of key characters
    // with no `:`/`=` after it (a hex blob, a long identifier in minified
    // code) made every start position scan to the end of the run and fail:
    // quadratic time, measured at about 20 s for a single 20,000-character
    // line, so hours for a 1 MB line. The possessive form changes nothing
    // for a real match: the character after the key has to be a quote,
    // whitespace, `:` or `=`, none of which is a key character, so giving
    // back key characters could never let the rest of the pattern match.
    internal val ASSIGNMENT_LINE = Regex(
        """["']?([A-Za-z_][A-Za-z0-9_.\-]{0,127}+)["']?\s*[:=]\s*(["'])([^"'\n]{6,})\2"""
    )

    // .env/.properties/shell-export style: `KEY=value` or `key: value`, one
    // assignment filling the whole line (anchored ^...$). The value is read
    // the way .env files write it (CredentialHeuristic.unquote): one pair of
    // quotes stripped, or a trailing ` # comment` cut off. The old form
    // (`\S{6,}` up to the end of the line) missed `API_TOKEN=... # prod`
    // entirely. Tried only when the quoted pattern finds nothing on a line,
    // so a quoted JSON/Kotlin/JS-style line is never reinterpreted as this.
    private val UNQUOTED_ASSIGNMENT_LINE = Regex(
        """^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=](.*)$"""
    )

    private const val MIN_VALUE_LENGTH = 6

    private fun extractAssignments(line: String): List<Pair<String, String>> {
        // Both assignment patterns need a `=` or a `:`. Without either there is
        // nothing to extract, and the quoted pattern (up to 128 key characters
        // tried from every position) cost about 4 s per megabyte on a long line
        // of identifier characters, a minified bundle or a base64 blob, and
        // twice that late in a long run. Signatures still check the whole line.
        if (line.indexOf('=') < 0 && line.indexOf(':') < 0) return emptyList()
        // The quoted pattern also needs a quote. Its known remaining cost is a
        // long line that has quotes, `=`/`:` AND a long run of key characters:
        // still linear (each position tries at most 128 key characters), about
        // 4 s per megabyte of such a line.
        val hasQuote = line.indexOf('"') >= 0 || line.indexOf('\'') >= 0
        val quoted = if (!hasQuote) emptyList() else ASSIGNMENT_LINE.findAll(line).map { it.groupValues[1] to it.groupValues[3] }.toList()
        if (quoted.isNotEmpty()) return quoted
        val unquoted = UNQUOTED_ASSIGNMENT_LINE.find(line) ?: return emptyList()
        val value = CredentialHeuristic.unquote(unquoted.groupValues[2]).first
        if (value.length < MIN_VALUE_LENGTH) return emptyList()
        return listOf(unquoted.groupValues[1] to value)
    }

    fun scan(root: File): List<ScanHit> {
        // A single file given on the command line is scanned whatever its
        // extension (the user asked for that file), and reported by its own
        // name: relativeTo(itself) would be the empty string, which made an
        // empty location in the text output and an empty SARIF uri.
        if (root.isFile) return scanFile(root, root.name)

        val hits = mutableListOf<ScanHit>()
        // Real paths of the directories already entered. A directory link
        // (a symlink, or a junction on Windows) that points back up the tree
        // made the walk descend again and again until the OS refused the
        // path: measured on Windows, one secret behind a junction loop was
        // reported 32 times. Entering each real directory once ends that.
        val visited = HashSet<String>()
        root.walkTopDown()
            // The root itself is never skipped by name: scanning `build/` or
            // `vendor/` on purpose used to report "no findings" without
            // reading a single file, because the root matched SKIP_DIRS.
            .onEnter { dir -> (dir == root || dir.name !in SKIP_DIRS) && visited.add(realPathOf(dir)) }
            .filter { it.isFile && it.extension.lowercase() in SCAN_EXTENSIONS }
            .forEach { file -> hits += scanFile(file, file.relativeTo(root).path.replace('\\', '/')) }
        return hits
    }

    private fun realPathOf(dir: File): String =
        try {
            dir.toPath().toRealPath().toString()
        } catch (e: Exception) {
            dir.absoluteFile.normalize().path
        }

    private fun scanFile(file: File, relativePath: String): List<ScanHit> {
        val hits = mutableListOf<ScanHit>()
        // Templates (`.env.example`, `*.sample`) and lockfiles hold placeholders
        // and hashes by design: only the exact formats are checked there.
        val heuristic = !CredentialHeuristic.isTemplateOrGeneratedFile(file.name)
        try {
            // Streamed line by line instead of readLines(): a 50 MB file no
            // longer has to sit in memory as one list of strings.
            file.useLines { lines -> lines.forEachIndexed { index, line -> scanLine(line, index + 1, relativePath, heuristic, hits) } }
        } catch (e: Exception) {
            // Unreadable despite a text extension (binary content, odd
            // encoding, permissions) -- skip it, never crash the whole scan
            // over one file. Known gap: the skip is silent.
        }
        return hits
    }

    private fun scanLine(line: String, lineNumber: Int, relativePath: String, heuristic: Boolean, hits: MutableList<ScanHit>) {
        var matchedOnLine = false

        for ((key, value) in extractAssignments(line)) {
            val finding = SecretDetector.scanLiteral(value, key, heuristic) ?: continue
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
            SecretDetector.scanSignatures(line)?.let { finding ->
                hits += ScanHit(relativePath, lineNumber, 1, finding.kind, finding.description)
            }
        }
    }
}
