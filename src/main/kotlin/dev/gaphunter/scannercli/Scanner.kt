package dev.gaphunter.scannercli

import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.nio.charset.Charset
import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest

/**
 * One finding. [file] is the path as the report shows it, `/`-separated. The
 * secret itself is never kept: only what the masked view needs ([secretHead],
 * at most 64 characters, shown only with `--reveal`; [secretTail], 4) and its
 * SHA-256 for the SARIF fingerprint.
 */
data class ScanHit(
    val file: String,
    val line: Int,
    val column: Int,
    val kind: String,
    val description: String,
    val severity: Severity = Severity.HIGH,
    val endColumn: Int = column,
    val secretLength: Int = 0,
    val secretHead: String = "",
    val secretTail: String = "",
    val secretSha256: String = "",
    val testPath: Boolean = false,
)

/** What a scan read, left out and why. Filled by [Scanner.scanAll]; the renderers print it. */
class ScanStats {
    var filesScanned = 0
    var bytesScanned = 0L
    var excluded = 0
    var durationMs = 0L
    val tooLarge = mutableListOf<String>()
    val binary = mutableListOf<String>()
    val unreadable = mutableListOf<String>()
    val externalLinks = mutableListOf<String>()
    val decodedAsUtf16 = mutableListOf<String>()

    val skipped: Int get() = tooLarge.size + binary.size + unreadable.size + externalLinks.size
}

data class ScanOptions(
    val followExternalLinks: Boolean = false,
    /** Files larger than this are skipped and listed; 0 = no limit. */
    val maxFileBytes: Long = DEFAULT_MAX_FILE_BYTES,
    val ignore: IgnoreRules = IgnoreRules.NONE,
    val disabledRules: Set<String> = emptySet(),
    /** Real paths never read (the `--out` report itself). */
    val skipRealPaths: Set<String> = emptySet(),
) {
    companion object {
        const val DEFAULT_MAX_FILE_MB = 25L
        const val DEFAULT_MAX_FILE_BYTES = DEFAULT_MAX_FILE_MB * 1024 * 1024
    }
}

object Scanner {

    // Directories never worth descending into: VCS metadata, build output,
    // dependency caches. Keeps a scan of a whole repo fast and avoids
    // reporting findings buried in third-party/generated code nobody owns.
    private val SKIP_DIRS = setOf(
        ".git", ".gradle", ".idea", "node_modules", "build", "dist",
        "target", "out", "vendor", ".venv", "venv", "__pycache__",
    )

    // Extensions worth reading as text. A file with one of these that turns out
    // to be binary is caught by the content sniff in [readText] and skipped.
    private val SCAN_EXTENSIONS = setOf(
        "kt", "kts", "java", "py", "js", "jsx", "ts", "tsx", "go", "rb",
        "php", "cs", "cpp", "c", "h", "hpp", "rs", "swift", "sh", "bash",
        "yml", "yaml", "json", "properties", "env", "xml", "toml", "ini",
        "cfg", "conf", "gradle",
    )

    // Coarse assignment-line heuristic: `key = "value"` / `key: "value"` /
    // `"key": "value"`. Group 1 = key, group 2 = the quote character actually used,
    // group 3 = value. The key is capped at 128 characters and matched possessively,
    // which keeps a long run of key characters with no `:`/`=` after it linear.
    internal val ASSIGNMENT_LINE = Regex(
        """["']?([A-Za-z_][A-Za-z0-9_.\-]{0,127}+)["']?\s*[:=]\s*(["'])([^"'\n]{6,})\2"""
    )

    // .env/.properties/shell-export style: `KEY=value` or `key: value`, one
    // assignment filling the whole line. Tried only when the quoted pattern finds nothing.
    private val UNQUOTED_ASSIGNMENT_LINE = Regex(
        """^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=](.*)$"""
    )

    private const val MIN_VALUE_LENGTH = 6

    /** Path segments and file names that mark test code, fixtures or examples. Only a tag: severity does not change. */
    private val TEST_SEGMENTS = setOf(
        "test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures", "testdata", "test-data",
        "example", "examples", "sample", "samples", "demo", "demos", "mock", "mocks", "__mocks__",
    )
    // Case matters on purpose: `AppTest.kt` is a test, `contest.py` is not.
    private val TEST_FILE = Regex("""(^test_.*\.py$|_test\.\w+$|[a-z0-9](Test|Tests|Spec)\.\w+$|\.(spec|test)\.\w+$)""")

    internal fun isTestPath(path: String): Boolean {
        val parts = path.split('/')
        if (parts.dropLast(1).any { it.lowercase() in TEST_SEGMENTS }) return true
        return TEST_FILE.containsMatchIn(parts.last())
    }

    /** One assignment on a line: the key, the value and the value's offset in the line. */
    private data class Assignment(val key: String, val value: String, val at: Int)

    private fun extractAssignments(line: String): List<Assignment> {
        // Both patterns need a `=` or a `:`; the quoted one also needs a quote.
        if (line.indexOf('=') < 0 && line.indexOf(':') < 0) return emptyList()
        val hasQuote = line.indexOf('"') >= 0 || line.indexOf('\'') >= 0
        val quoted = if (!hasQuote) emptyList() else ASSIGNMENT_LINE.findAll(line).map {
            Assignment(it.groupValues[1], it.groupValues[3], it.groups[3]!!.range.first)
        }.toList()
        if (quoted.isNotEmpty()) return quoted
        val unquoted = UNQUOTED_ASSIGNMENT_LINE.find(line) ?: return emptyList()
        val (value, offset) = CredentialHeuristic.unquote(unquoted.groupValues[2])
        if (value.length < MIN_VALUE_LENGTH) return emptyList()
        return listOf(Assignment(unquoted.groupValues[1], value, unquoted.groups[2]!!.range.first + offset))
    }

    /**
     * Scans one [root] (a directory or a file), reporting paths relative to it.
     * Kept for callers of 0.2.0; [scanAll] is what the command line uses.
     */
    fun scan(root: File, followExternalLinks: Boolean = false, onSkippedLink: (String) -> Unit = {}): List<ScanHit> {
        val stats = ScanStats()
        val hits = scanAll(listOf(root to ""), ScanOptions(followExternalLinks = followExternalLinks, maxFileBytes = 0), stats)
        stats.externalLinks.forEach(onSkippedLink)
        return hits
    }

    /**
     * Scans every root. Each root comes with the prefix its paths get in the
     * report (see [displayPrefix]). A file reached twice (two roots that
     * overlap, a link inside the tree) is read once. A directory or file link
     * whose real path leads outside its root is not followed unless
     * [ScanOptions.followExternalLinks]; it is listed in [ScanStats.externalLinks]
     * by its path inside the tree, never by its target.
     */
    fun scanAll(roots: List<Pair<File, String>>, options: ScanOptions, stats: ScanStats): List<ScanHit> {
        val started = System.nanoTime()
        val hits = mutableListOf<ScanHit>()
        val readFiles = HashSet<String>()
        for ((root, prefix) in roots) {
            if (root.isFile) {
                // A file named on the command line is scanned whatever its extension or the
                // exclusions (the user asked for that file), and reported by its own name.
                val display = prefix + root.name
                if (readFiles.add(realPathOf(root)) && realPathOf(root) !in options.skipRealPaths) {
                    hits += scanFile(root, display, options, stats)
                }
                continue
            }
            // Resolving a real path is a system call per file (slow on Windows), so it is done only
            // where a file could be met twice or could be the --out report: several roots, a symlinked
            // file, or a file with the report's name. One root without links never repeats a file
            // (each real directory is entered once).
            val skipNames = options.skipRealPaths.map { File(it).name }.toSet()
            walk(root, prefix, options, stats) { file, display ->
                val check = roots.size > 1 || file.name in skipNames || Files.isSymbolicLink(file.toPath())
                val real = if (check) realPathOf(file) else null
                if (real == null || (real !in options.skipRealPaths && readFiles.add(real))) hits += scanFile(file, display, options, stats)
            }
        }
        stats.durationMs = (System.nanoTime() - started) / 1_000_000
        return hits
    }

    /** Every file a scan of [root] would read, without reading it: used by the scan and by `--dry-run`. */
    internal fun walk(root: File, prefix: String, options: ScanOptions, stats: ScanStats, onFile: (File, String) -> Unit) {
        // Real paths of the directories already entered: a link pointing back up the tree is entered once.
        val visited = HashSet<String>()
        val rootReal = realPathOf(root)
        fun relative(f: File) = f.relativeTo(root).path.replace(File.separatorChar, '/')
        fun leavesTheRoot(f: File): Boolean = !options.followExternalLinks && !isWithin(realPathOf(f), rootReal)
        root.walkTopDown()
            .onEnter { dir ->
                if (dir == root) return@onEnter visited.add(realPathOf(dir))
                // The root itself is never skipped by name: scanning `build/` on purpose reads it.
                if (dir.name in SKIP_DIRS) return@onEnter false
                val display = prefix + relative(dir)
                if (options.ignore.matches(display, isDirectory = true)) {
                    stats.excluded++
                    return@onEnter false
                }
                if (leavesTheRoot(dir)) {
                    stats.externalLinks += display
                    return@onEnter false
                }
                visited.add(realPathOf(dir))
            }
            .filter { it.isFile && it.extension.lowercase() in SCAN_EXTENSIONS }
            .forEach { file ->
                val display = prefix + relative(file)
                when {
                    options.ignore.matches(display, isDirectory = false) -> stats.excluded++
                    // Only a symlinked file can lead elsewhere (a junction is always a directory).
                    Files.isSymbolicLink(file.toPath()) && leavesTheRoot(file) -> stats.externalLinks += display
                    else -> onFile(file, display)
                }
            }
    }

    /** True when [path] is [root] or inside it, compared by path segments (so `/repo2` is not inside `/repo`). */
    internal fun isWithin(path: String, root: String): Boolean {
        val p = Paths.get(path)
        val r = Paths.get(root)
        return p == r || p.startsWith(r)
    }

    internal fun realPathOf(f: File): String =
        try {
            f.toPath().toRealPath().toString()
        } catch (e: Exception) {
            f.absoluteFile.normalize().path
        }

    private const val SNIFF_BYTES = 8192

    /** How a file is decoded, decided from its first bytes. */
    private enum class Decoding(val charset: Charset?, val skip: Int) {
        UTF8(Charsets.UTF_8, 0), UTF8_BOM(Charsets.UTF_8, 3),
        UTF16LE_BOM(Charsets.UTF_16LE, 2), UTF16BE_BOM(Charsets.UTF_16BE, 2),
        UTF16LE(Charsets.UTF_16LE, 0), UTF16BE(Charsets.UTF_16BE, 0),
        BINARY(null, 0),
    }

    /**
     * Decides how to read a file from its first [SNIFF_BYTES]:
     *  - a byte-order mark picks UTF-8 or UTF-16, and the mark itself is not part
     *    of line 1 (in 0.2.0 a UTF-8 BOM hid `API_TOKEN=...` on the first line of a `.env`);
     *  - NUL bytes in every other position, and nowhere else, are UTF-16 without a mark;
     *  - any other NUL byte means binary content behind a text extension: skipped, listed.
     * Everything else is read as UTF-8; an invalid byte (a Latin-1 or Windows-1252 file)
     * becomes one replacement character, so columns stay one per byte, as in those encodings.
     */
    private fun sniff(head: ByteArray, n: Int): Decoding {
        fun b(i: Int) = head[i].toInt() and 0xFF
        if (n >= 3 && b(0) == 0xEF && b(1) == 0xBB && b(2) == 0xBF) return Decoding.UTF8_BOM
        if (n >= 2 && b(0) == 0xFF && b(1) == 0xFE) return Decoding.UTF16LE_BOM
        if (n >= 2 && b(0) == 0xFE && b(1) == 0xFF) return Decoding.UTF16BE_BOM
        var evenNul = 0
        var oddNul = 0
        for (i in 0 until n) if (head[i].toInt() == 0) { if (i % 2 == 0) evenNul++ else oddNul++ }
        if (evenNul + oddNul == 0) return Decoding.UTF8
        val half = n / 2
        if (n >= 4 && evenNul == 0 && oddNul >= half * 0.9) return Decoding.UTF16LE
        if (n >= 4 && oddNul == 0 && evenNul >= half * 0.9) return Decoding.UTF16BE
        return Decoding.BINARY
    }

    private fun scanFile(file: File, display: String, options: ScanOptions, stats: ScanStats): List<ScanHit> {
        val size = file.length()
        if (options.maxFileBytes > 0 && size > options.maxFileBytes) {
            stats.tooLarge += display
            return emptyList()
        }
        val hits = mutableListOf<ScanHit>()
        val heuristic = !CredentialHeuristic.isTemplateOrGeneratedFile(file.name)
        val testPath = isTestPath(display)
        try {
            BufferedInputStream(file.inputStream(), 64 * 1024).use { input ->
                input.mark(SNIFF_BYTES)
                val head = ByteArray(SNIFF_BYTES)
                var n = 0
                while (n < SNIFF_BYTES) {
                    val r = input.read(head, n, SNIFF_BYTES - n)
                    if (r < 0) break
                    n += r
                }
                input.reset()
                val decoding = sniff(head, n)
                if (decoding == Decoding.BINARY) {
                    stats.binary += display
                    return emptyList()
                }
                if (decoding == Decoding.UTF16LE || decoding == Decoding.UTF16BE) stats.decodedAsUtf16 += display
                input.skip(decoding.skip.toLong())
                // Streamed line by line: a large file never sits in memory as one list of strings.
                BufferedReader(InputStreamReader(input, decoding.charset!!)).useLines { lines ->
                    lines.forEachIndexed { index, line -> scanLine(line, index + 1, display, heuristic, testPath, options, hits) }
                }
            }
            stats.filesScanned++
            stats.bytesScanned += size
        } catch (e: Exception) {
            // Unreadable despite a text extension (permissions, a file locked by another
            // process on Windows): skipped and listed, never the end of the whole scan.
            stats.unreadable += display
            return emptyList()
        }
        return hits
    }

    private fun hitOf(finding: SecretFinding, file: String, line: Int, offset: Int, testPath: Boolean): ScanHit {
        val v = finding.value
        return ScanHit(
            file = file, line = line, column = offset + finding.start + 1, kind = finding.kind,
            description = finding.description, severity = finding.severity,
            endColumn = offset + finding.end + 1, secretLength = v.length,
            secretHead = v.take(64), secretTail = v.takeLast(4), secretSha256 = sha256Hex(v), testPath = testPath,
        )
    }

    private fun scanLine(
        line: String, lineNumber: Int, display: String, heuristic: Boolean, testPath: Boolean,
        options: ScanOptions, hits: MutableList<ScanHit>,
    ) {
        var matchedOnLine = false
        for (a in extractAssignments(line)) {
            val finding = SecretDetector.scanLiteral(a.value, a.key, heuristic, options.disabledRules) ?: continue
            hits += hitOf(finding, display, lineNumber, a.at, testPath)
            matchedOnLine = true
        }
        // Exact formats can appear outside a clean `key = "value"` (inside a shell command,
        // a URL, a comment): searched on the whole line, at the column where they start.
        // Skipped when the assignment pass already reported this line.
        if (!matchedOnLine) {
            SecretDetector.scanSignatures(line, options.disabledRules)?.let { hits += hitOf(it, display, lineNumber, 0, testPath) }
        }
    }

    internal fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}
