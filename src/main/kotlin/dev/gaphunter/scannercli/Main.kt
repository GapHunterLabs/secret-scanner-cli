package dev.gaphunter.scannercli

import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.security.MessageDigest
import kotlin.system.exitProcess

internal const val VERSION = "0.3.0"

private val FORMATS = listOf("text", "sarif", "json")

private data class Args(
    val paths: List<File>,
    val format: String,
    val outFile: File?,
    val failOn: String?,
    val noFail: Boolean,
    val bannerFlag: Boolean,
    val noBannerFlag: Boolean,
    val followExternalLinks: Boolean,
    val quiet: Boolean,
    val verbose: Boolean,
    val configFile: File?,
    val noConfig: Boolean,
    val excludes: List<String>,
    val maxFileSizeMb: Long?,
    val maxFindings: Int?,
    val reveal: Int?,
    val dryRun: Boolean,
    val expectSha256: String?,
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
 * [workingDir] is where `.secret-scanner.json` and `.scannerignore` are looked
 * for and what report paths are relative to; the tests pass a temporary one.
 */
internal fun cliMain(
    rawArgs: Array<String>, out: PrintStream, err: PrintStream, isConsole: Boolean,
    workingDir: File = File("").absoluteFile,
): Int {
    val io = Io(out, err, isConsole)
    return try {
        execute(rawArgs, io, workingDir)
    } catch (e: CliExit) {
        e.code
    }
}

private fun execute(rawArgs: Array<String>, io: Io, workingDir: File): Int {
    val args = parseArgs(rawArgs, io) ?: return 0
    fun inWd(f: File) = if (f.isAbsolute) f else File(workingDir, f.path)

    // ---- everything below is checked before a single file is read ----
    args.expectSha256?.let { expected ->
        val actual = selfSha256() ?: pathError(io, "--expect-sha256: this run is not from a jar, so there is no artifact to check")
        if (!actual.equals(expected, ignoreCase = true)) {
            pathError(io, "--expect-sha256: the running jar is $actual, expected $expected; refusing to scan with an unexpected artifact")
        }
    }
    for (p in args.paths) if (!inWd(p).exists()) pathError(io, "path not found: ${consoleSafe(p.path)}")
    args.outFile?.let { o -> outFileProblem(inWd(o))?.let { pathError(io, it) } }

    val config = loadConfig(args, io, workingDir)
    val ignoreFile = File(workingDir, ".scannerignore")
    val ignore = try {
        var rules = IgnoreRules.NONE
        if (!args.noConfig && ignoreFile.isFile) rules = rules.plus(IgnoreRules.parse(ignoreFile.readLines(), ".scannerignore"))
        config.exclude.forEachIndexed { n, p -> rules = rules.plus(IgnoreRules.single(p, "${config.source}: exclude[$n]")) }
        args.excludes.forEach { p -> rules = rules.plus(IgnoreRules.single(p, "--exclude")) }
        rules
    } catch (e: IgnoreRules.Invalid) {
        pathError(io, e.message ?: "invalid exclusion pattern")
    } catch (e: java.io.IOException) {
        pathError(io, "cannot read .scannerignore: ${e.message}")
    }

    // The command line wins over the configuration file: --no-fail or --fail-on is the explicit, local choice.
    val failOn = when {
        args.noFail -> "none"
        args.failOn != null -> args.failOn
        else -> config.failOn ?: "all"
    }
    val maxMb = args.maxFileSizeMb ?: config.maxFileSizeMb ?: ScanOptions.DEFAULT_MAX_FILE_MB
    val maxFindings = args.maxFindings ?: config.maxFindings
    val outReal = args.outFile?.let { Scanner.realPathOf(inWd(it)) }
    val options = ScanOptions(
        followExternalLinks = args.followExternalLinks || config.followExternalLinks == true,
        maxFileBytes = maxMb * 1024 * 1024,
        ignore = ignore,
        disabledRules = config.disableRules,
        skipRealPaths = setOfNotNull(outReal),
    )
    val roots = args.paths.map { p -> inWd(p) to displayPrefix(p, inWd(p), workingDir, args.paths.size) }

    if (args.dryRun) {
        dryRun(args, io, roots, options, config, ignoreFile, failOn, maxMb, maxFindings)
        return 0
    }

    val machineReadable = args.format != "text" || args.outFile != null
    if (!args.quiet && Banner.shouldShow(args.bannerFlag, args.noBannerFlag, io.isConsole, machineReadable)) {
        io.out.println(Banner.TEXT)
        io.out.println()
    }

    val stats = ScanStats()
    val hits = Scanner.scanAll(roots, options, stats)
    val label = args.paths.joinToString(", ") { it.path }
    val view = View(
        reveal = args.reveal, maxFindings = maxFindings,
        stats = if (args.quiet && args.format == "text") null else stats,
        toolSha256 = if (args.format == "text") null else selfSha256(),
    )
    val output = when (args.format) {
        "sarif" -> renderSarif(hits, "", view)
        "json" -> renderJson(hits, view)
        else -> renderText(hits, label, view)
    }

    if (args.outFile != null) {
        try {
            inWd(args.outFile).writeText(output)
        } catch (e: java.io.IOException) {
            pathError(io, "cannot write --out file ${consoleSafe(args.outFile.path)}: ${e.message}")
        }
    } else {
        io.out.println(output)
    }

    if (!args.quiet) {
        printNotices(io, stats, args.verbose)
        // For SARIF, JSON or --out the numbers are inside the report; a short line on stderr keeps the CI log readable.
        if (args.format != "text" || args.outFile != null) {
            io.err.println("secret-scanner-cli: ${hits.size} finding(s) in ${consoleSafe(label)}")
            summaryLines(hits, stats).forEach { io.err.println(consoleSafe(it)) }
        }
    }

    val threshold = when (failOn) {
        "none" -> null
        "high" -> Severity.HIGH
        else -> Severity.MEDIUM  // "medium" and "all": every finding counts
    }
    return if (threshold != null && hits.any { it.severity >= threshold }) 1 else 0
}

/**
 * The prefix a root's files get in the report: relative to [workingDir] when the
 * root is inside it (`src/Config.kt` when scanning `src`, which Code Scanning
 * resolves against the repository root); otherwise relative to the root, plus the
 * root's own name when several roots are scanned, so two `.env` files from two
 * different folders are never reported as the same path.
 */
private fun displayPrefix(given: File, root: File, workingDir: File, rootCount: Int): String {
    val prefix = sarifUriPrefix(root, workingDir)
    if (prefix.isNotEmpty()) return prefix
    val dir = if (root.isFile) root.absoluteFile.parentFile else root.absoluteFile
    val insideWd = dir != null && Scanner.isWithin(dir.normalize().path, workingDir.absoluteFile.normalize().path)
    if (insideWd || rootCount == 1) return ""
    return if (root.isFile) "" else root.absoluteFile.normalize().name + "/"
}

private fun loadConfig(args: Args, io: Io, workingDir: File): Config {
    if (args.noConfig) return Config()
    val file = args.configFile?.let { if (it.isAbsolute) it else File(workingDir, it.path) } ?: File(workingDir, Config.FILE_NAME)
    if (!file.isFile) {
        if (args.configFile != null) pathError(io, "--config file not found: ${consoleSafe(args.configFile.path)}")
        return Config()
    }
    return try {
        Config.load(file).copy(source = args.configFile?.path ?: Config.FILE_NAME)
    } catch (e: Config.Invalid) {
        pathError(io, consoleSafe(e.message ?: "invalid configuration"))
    }
}

private const val NOTICE_LIMIT = 5

/** Skipped links and files, one block per reason: the first five, then a count, unless --verbose lists them all. */
private fun printNotices(io: Io, stats: ScanStats, verbose: Boolean) {
    fun block(items: List<String>, what: String, hint: String) {
        if (items.isEmpty()) return
        val listed = if (verbose) items else items.take(NOTICE_LIMIT)
        val more = items.size - listed.size
        val tail = if (more > 0) " and $more more (--verbose lists them all)" else ""
        io.err.println("secret-scanner-cli: skipped ${items.size} $what: ${listed.joinToString(", ") { consoleSafe(it) }}$tail$hint")
    }
    block(stats.externalLinks, "link(s) that lead outside the scanned folder", " (--follow-external-links scans them)")
    block(stats.tooLarge, "file(s) over the size limit", " (--max-file-size raises it)")
    block(stats.binary, "binary file(s) with a text extension", "")
    block(stats.unreadable, "unreadable file(s)", "")
    if (verbose) block(stats.decodedAsUtf16, "file(s) read as UTF-16 without a byte-order mark", "")
}

private fun dryRun(
    args: Args, io: Io, roots: List<Pair<File, String>>, options: ScanOptions, config: Config, ignoreFile: File,
    failOn: String, maxMb: Long, maxFindings: Int?,
) {
    val stats = ScanStats()
    var files = 0
    var tooLarge = 0
    for ((root, prefix) in roots) {
        if (root.isFile) { files++; continue }
        Scanner.walk(root, prefix, options, stats) { f, _ ->
            if (options.maxFileBytes > 0 && f.length() > options.maxFileBytes) tooLarge++ else files++
        }
    }
    val disabled = config.disableRules
    io.out.println("secret-scanner-cli $VERSION: dry run, no file content was read")
    io.out.println("paths: ${args.paths.joinToString(", ") { consoleSafe(it.path) }}")
    io.out.println("format: ${args.format}; fail on: $failOn; max file size: ${if (maxMb == 0L) "no limit" else "$maxMb MB"}; " +
        "max findings: ${maxFindings ?: "all"}${args.outFile?.let { "; report to ${consoleSafe(it.path)}" } ?: ""}")
    io.out.println("configuration: ${config.source ?: "none"}; ignore file: ${if (!args.noConfig && ignoreFile.isFile) ".scannerignore" else "none"}; " +
        "exclusion patterns: ${options.ignore.size}")
    io.out.println("rules: ${SecretDetector.KINDS.size - disabled.size} enabled" + (if (disabled.isEmpty()) "" else ", disabled: ${disabled.sorted().joinToString()}"))
    io.out.println("files that would be read: $files; over the size limit: $tooLarge; excluded: ${stats.excluded}; " +
        "links outside the folder: ${stats.externalLinks.size}")
}

private fun parseArgs(rawArgs: Array<String>, io: Io): Args? {
    val paths = mutableListOf<File>()
    val single = HashMap<String, String>()
    val switches = HashSet<String>()
    val excludes = mutableListOf<String>()

    fun value(i: Int, flag: String): String {
        val v = rawArgs.getOrNull(i) ?: usageError(io, "$flag needs a value")
        // `--out --no-fail` used to write a file literally named "--no-fail" and drop the flag the user meant.
        if (v.startsWith("--")) usageError(io, "$flag needs a value, got the flag '$v'")
        return v
    }

    fun once(flag: String, v: String) {
        if (single.put(flag, v) != null) usageError(io, "$flag was given twice")
    }

    var i = 0
    while (i < rawArgs.size) {
        when (val arg = rawArgs[i]) {
            "--format", "--out", "--fail-on", "--config", "--max-file-size", "--max-findings", "--reveal", "--expect-sha256" ->
                once(arg, value(++i, arg))
            "--exclude" -> excludes += value(++i, arg)
            "--no-fail", "--banner", "--no-banner", "--follow-external-links", "--quiet", "--verbose", "--no-config", "--dry-run" -> {
                if (!switches.add(arg)) usageError(io, "$arg was given twice")
            }
            "--version" -> { io.out.println("secret-scanner-cli $VERSION"); return null }
            "--self-sha256" -> {
                val sha = selfSha256() ?: pathError(io, "--self-sha256: this run is not from a jar")
                io.out.println("$sha  secret-scanner-cli-$VERSION.jar")
                return null
            }
            "-h", "--help" -> {
                if (Banner.shouldShow("--banner" in switches, "--no-banner" in switches, io.isConsole, machineReadable = false)) {
                    io.out.println(Banner.TEXT)
                    io.out.println()
                }
                printHelp(io.out)
                return null
            }
            else -> {
                if (arg.startsWith("-") && arg != "-") usageError(io, "unknown flag '$arg'")
                if (arg.isEmpty()) usageError(io, "an empty path was given")
                paths += File(arg)
            }
        }
        i++
    }

    fun conflict(a: String, b: String) {
        val has = { f: String -> f in switches || f in single }
        if (has(a) && has(b)) usageError(io, "$a and $b cannot be used together")
    }
    conflict("--banner", "--no-banner")
    conflict("--quiet", "--verbose")
    conflict("--no-fail", "--fail-on")
    conflict("--config", "--no-config")

    val format = single["--format"] ?: "text"
    if (format !in FORMATS) usageError(io, "unknown --format '$format' (expected ${FORMATS.joinToString("|")})")
    val failOn = single["--fail-on"]?.also {
        if (it !in Config.FAIL_ON_VALUES) usageError(io, "unknown --fail-on '$it' (expected ${Config.FAIL_ON_VALUES.joinToString("|")})")
    }
    fun number(flag: String, min: Long, max: Long): Long? = single[flag]?.let { v ->
        val n = v.toLongOrNull() ?: usageError(io, "$flag needs a whole number, got '$v'")
        if (n < min || n > max) usageError(io, "$flag must be between $min and $max, got $n")
        n
    }
    val maxFileSize = number("--max-file-size", 0, 1_000_000)
    val maxFindings = number("--max-findings", 1, Int.MAX_VALUE.toLong())?.toInt()
    val reveal = number("--reveal", 1, Mask.MAX_REVEAL.toLong())?.toInt()
    val expect = single["--expect-sha256"]?.also {
        if (!Regex("[0-9a-fA-F]{64}").matches(it)) usageError(io, "--expect-sha256 needs a 64-character hex SHA-256, got '${consoleSafe(it)}'")
    }
    if ("--dry-run" in switches && "--reveal" in single) usageError(io, "--reveal has nothing to show in a --dry-run")
    if (paths.isEmpty()) paths += File(".")

    return Args(
        paths = paths, format = format, outFile = single["--out"]?.let { File(it) }, failOn = failOn,
        noFail = "--no-fail" in switches, bannerFlag = "--banner" in switches, noBannerFlag = "--no-banner" in switches,
        followExternalLinks = "--follow-external-links" in switches, quiet = "--quiet" in switches, verbose = "--verbose" in switches,
        configFile = single["--config"]?.let { File(it) }, noConfig = "--no-config" in switches, excludes = excludes,
        maxFileSizeMb = maxFileSize, maxFindings = maxFindings, reveal = reveal, dryRun = "--dry-run" in switches,
        expectSha256 = expect,
    )
}

private val WINDOWS_RESERVED = Regex("""(?i)^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$""")
private val WINDOWS_INVALID = Regex("""[<>:"|?*\u0000-\u001f]""")

/**
 * Why [out] can't be written, or null when it can. Checked before the scan, so a
 * bad --out never costs a whole scan and never surfaces as exit 1, the code that
 * means "findings". On Windows a reserved device name (`con.sarif`, `nul.json`)
 * used to send the report to the console device, exit 1 and no file.
 */
internal fun outFileProblem(out: File, isWindows: Boolean = System.getProperty("os.name").lowercase().startsWith("windows")): String? {
    val name = out.name
    if (out.isDirectory) return "--out points to a directory, not a file: ${consoleSafe(out.path)}"
    if (isWindows) {
        if (WINDOWS_RESERVED.matches(name)) return "--out uses '${consoleSafe(name)}', a reserved device name on Windows"
        if (WINDOWS_INVALID.containsMatchIn(name)) return "--out file name '${consoleSafe(name)}' has a character Windows does not allow (<>:\"|?*)"
    }
    val parent = out.absoluteFile.parentFile
    if (parent != null && !parent.isDirectory) return "--out directory does not exist: ${consoleSafe(parent.path)}"
    if (out.exists()) {
        if (!Files.isWritable(out.toPath())) return "--out file is not writable: ${consoleSafe(out.path)}"
        return null
    }
    // A probe file proves the directory accepts a new file (permissions, a read-only mount), then goes away.
    return try {
        val probe = File.createTempFile(".secret-scanner-probe", ".tmp", parent)
        probe.delete()
        null
    } catch (e: Exception) {
        "--out directory is not writable: ${consoleSafe(parent?.path ?: out.path)} (${e.message})"
    }
}

/** SHA-256 of the jar this code runs from, or null when it runs from classes (tests, an IDE). */
internal fun selfSha256(): String? {
    val location = try {
        File(Scanner::class.java.protectionDomain.codeSource.location.toURI())
    } catch (e: Exception) {
        return null
    }
    if (!location.isFile || !location.name.endsWith(".jar")) return null
    val digest = MessageDigest.getInstance("SHA-256")
    location.inputStream().use { input ->
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            digest.update(buf, 0, n)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
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

        Usage: secret-scanner-cli [path...] [options]

          path...             Directories and/or files to scan (default: current directory)
          --format <fmt>      Output format: text (default), sarif or json
          --out <file>        Write the report to a file instead of stdout
          --fail-on <level>   Exit 1 only for findings at this severity or above:
                              all (default), medium, high, or none
          --no-fail           Always exit 0 (same as --fail-on none)
          --quiet             Only findings and errors: no banner, summary or notices
          --verbose           List every skipped file and link, and the run's numbers
          --config <file>     Read this JSON configuration instead of ./.secret-scanner.json
          --no-config         Ignore ./.secret-scanner.json and ./.scannerignore
          --exclude <glob>    Leave out matching paths (repeatable; gitignore-style)
          --max-file-size <MB>
                              Skip larger files (default 25, 0 = no limit)
          --max-findings <N>  List at most N findings (the exit code still counts all)
          --reveal <N>        Show the first N characters of each secret (1-64);
                              by default only a masked view like abcd...wxyz
          --dry-run           Check flags, configuration and paths, count the files
                              that would be read, and exit without reading them
          --follow-external-links
                              Also scan through links (symlinks, junctions) that lead
                              outside the scanned folder; not followed by default
          --self-sha256       Print the SHA-256 of this jar and exit
          --expect-sha256 <hex>
                              Refuse to scan (exit 2) unless this jar has that SHA-256
          --banner            Always print the startup banner
          --no-banner         Never print the startup banner
          --version           Print version and exit
          -h, --help          Print this help and exit

        Severity: exact credential formats are high; a high-entropy value assigned
        to a credential name, a bcrypt hash and a Google API key are medium.

        Exit codes: 0 = no findings at the --fail-on level, 1 = findings at that level,
        2 = usage, configuration or path error (always before any file is read).
        """.trimIndent()
    )
}
