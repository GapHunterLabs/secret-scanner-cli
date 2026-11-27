package dev.gaphunter.scannercli

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.io.path.createTempDirectory

/**
 * The 0.3.0 command line, in-process with a temporary working directory:
 * formats, --fail-on, --quiet/--verbose, configuration, exclusions, several
 * paths, --max-findings, --reveal, --dry-run, self-verification, --out checks,
 * SARIF fingerprints, notices, console safety, and the GitHub Action itself.
 */
class CliFeaturesTest {

    private lateinit var wd: File

    @Before
    fun setUp() {
        wd = createTempDirectory(prefix = "cli-030-").toFile().canonicalFile
    }

    @After
    fun tearDown() {
        wd.deleteRecursively()
    }

    private fun cli(vararg args: String): CliResult {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = PrintStream(out, true, "UTF-8").use { o -> PrintStream(err, true, "UTF-8").use { e -> cliMain(arrayOf(*args), o, e, false, wd) } }
        return CliResult(code, out.toString("UTF-8"), err.toString("UTF-8"))
    }

    private fun write(path: String, text: String): File = File(wd, path).apply { parentFile.mkdirs(); writeText(text) }

    @Suppress("UNCHECKED_CAST")
    private fun json(text: String) = StrictJson(text).parse() as Map<String, Any?>

    // ---- formats (feature 1) and empty scans (point 14) ----

    @Test
    fun jsonIsValidAndCarriesSummaryFindingsAndNoSecret() {
        write("src/a.env", "API_TOKEN=${Fake.GENERIC}\nGH=${Fake.GITHUB}\n")
        val r = cli("src", "--format", "json")
        assertEquals(1, r.exitCode)
        val root = json(r.stdout)
        @Suppress("UNCHECKED_CAST") val findings = root["findings"] as List<Map<String, Any?>>
        assertEquals(listOf("src/a.env", "src/a.env"), findings.map { it["file"] })
        assertEquals(listOf("medium", "high"), findings.map { it["severity"] })
        @Suppress("UNCHECKED_CAST") val summary = root["summary"] as Map<String, Any?>
        assertEquals(2.0, summary["findings"])
        assertEquals(1.0, summary["filesScanned"])
        assertFalse(r.stdout.contains(Fake.GENERIC))
        assertFalse(r.stdout.contains(Fake.GITHUB))
        assertTrue(findings.all { (it["fingerprint"] as String).length == 32 })
    }

    @Test
    fun anEmptyOrCleanFolderExitsZeroWithValidOutputInEveryFormatAndNoWarnings() {
        File(wd, "empty").mkdirs()
        write("clean/app.yaml", "name: service\n")
        for (dir in listOf("empty", "clean")) {
            for (format in listOf("text", "sarif", "json")) {
                val r = cli(dir, "--format", format)
                assertEquals("$dir $format", 0, r.exitCode)
                when (format) {
                    "sarif" -> assertTrue(sarifResults(r.stdout).isEmpty())
                    "json" -> assertEquals(0.0, (json(r.stdout)["summary"] as Map<*, *>)["findings"])
                    else -> assertTrue(r.stdout.startsWith("secret-scanner-cli: no findings in $dir"))
                }
                assertFalse("$dir $format warns: ${r.stderr}", r.stderr.contains("skipped") || r.stderr.contains("error"))
            }
            assertEquals("", cli(dir, "--quiet", "--format", "sarif").stderr)
        }
    }

    // ---- --fail-on (feature 2) ----

    @Test
    fun failOnDecidesTheExitCodeBySeverity() {
        write("m/a.env", "API_TOKEN=${Fake.GENERIC}\n")             // medium only
        write("h/a.env", "GH=${Fake.GITHUB}\n")                      // high
        assertEquals(1, cli("m").exitCode)
        assertEquals(1, cli("m", "--fail-on", "all").exitCode)
        assertEquals(1, cli("m", "--fail-on", "medium").exitCode)
        assertEquals(0, cli("m", "--fail-on", "high").exitCode)
        assertEquals(0, cli("m", "--fail-on", "none").exitCode)
        assertEquals(1, cli("h", "--fail-on", "high").exitCode)
        assertEquals(0, cli("h", "--no-fail").exitCode)
        assertEquals("the report is the same whatever --fail-on says", cli("m", "--format", "sarif").stdout, cli("m", "--format", "sarif", "--fail-on", "high").stdout)
    }

    // ---- --quiet / --verbose and the summary (features 3 and 6, point 8) ----

    @Test
    fun theTextSummaryCountsFilesSkipsAndRulesAndQuietDropsIt() {
        write("s/a.env", "GH=${Fake.GITHUB}\nAPI_TOKEN=${Fake.GENERIC}\n")
        write("s/big.json", "x".repeat(1024 * 1024 + 10))
        File(wd, "s/bin.json").writeBytes(byteArrayOf(1, 0, 2, 0, 3, 7, 0))
        val r = cli("s", "--max-file-size", "1")
        assertTrue(r.stdout, r.stdout.contains("secret-scanner-cli: 2 finding(s) in s"))
        assertTrue(r.stdout, r.stdout.contains("scanned 1 file(s)"))
        assertTrue(r.stdout, r.stdout.contains("skipped 2 (1 too large, 1 binary)"))
        assertTrue(r.stdout, r.stdout.contains("by rule: GENERIC_HIGH_ENTROPY 1, GITHUB_TOKEN 1"))
        assertTrue(r.stdout, r.stdout.contains("by severity: 1 high, 1 medium"))
        assertTrue(r.stderr, r.stderr.contains("skipped 1 file(s) over the size limit: s/big.json"))
        val q = cli("s", "--max-file-size", "1", "--quiet")
        assertFalse(q.stdout.contains("scanned "))
        assertEquals("", q.stderr)
        assertEquals(1, q.exitCode)
    }

    @Test
    fun manySkippedFilesAreConsolidatedUnlessVerbose() {
        for (n in 1..12) write("t/big$n.json", "y".repeat(1024 * 1024 + 1))
        val r = cli("t", "--max-file-size", "1")
        val line = r.stderr.lines().single { it.contains("over the size limit") }
        assertTrue(line, line.startsWith("secret-scanner-cli: skipped 12 file(s) over the size limit: "))
        assertTrue(line, line.contains(" and 7 more (--verbose lists them all)"))
        assertEquals(1, r.stderr.lines().count { it.contains("over the size limit") })
        val v = cli("t", "--max-file-size", "1", "--verbose")
        val all = v.stderr.lines().single { it.contains("over the size limit") }
        assertEquals(12, Regex("big\\d+\\.json").findAll(all).count())
    }

    // ---- configuration (feature 4) and exclusions (feature 5) ----

    @Test
    fun theConfigurationFileExcludesDisablesAndSetsDefaultsAndTheCommandLineWins() {
        write("p/fixtures/a.env", "GH=${Fake.GITHUB}\n")
        write("p/src/b.env", "API_TOKEN=${Fake.GENERIC}\n")
        write("p/src/c.yaml", "key: \"AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q\"\n")
        write(".secret-scanner.json", """{"exclude": ["fixtures/"], "disableRules": ["GOOGLE_API_KEY"], "failOn": "high"}""")
        val r = cli("p", "--format", "json")
        @Suppress("UNCHECKED_CAST") val findings = json(r.stdout)["findings"] as List<Map<String, Any?>>
        assertEquals(listOf("p/src/b.env"), findings.map { it["file"] })
        assertEquals("failOn high: only a medium finding left", 0, r.exitCode)
        assertEquals("--fail-on on the command line wins", 1, cli("p", "--fail-on", "all").exitCode)
        assertEquals("--no-config ignores the file", 3, (json(cli("p", "--format", "json", "--no-config").stdout)["findings"] as List<*>).size)
    }

    @Test
    fun aBadConfigurationIsExitTwoBeforeAnythingIsReadAndNamesTheProblem() {
        write("p/a.env", "GH=${Fake.GITHUB}\n")
        val cases = mapOf(
            """{"exclud": []}""" to "unknown key(s) exclud",
            """{"exclude": "fixtures"}""" to "'exclude' must be an array of strings",
            """{"disableRules": ["NOPE"]}""" to "unknown rule id(s) in 'disableRules': NOPE",
            """{"failOn": "critical"}""" to "'failOn' must be one of",
            """{"maxFileSizeMb": -1}""" to "'maxFileSizeMb' must be a whole number of at least 0",
            """{"maxFindings": 1.5}""" to "'maxFindings' must be a whole number of at least 1",
            """{"followExternalLinks": "yes"}""" to "'followExternalLinks' must be true or false",
            """{"exclude": [],}""" to "is not valid JSON",
            """[]""" to "must hold a JSON object",
            """{"a": 1, "a": 2}""" to "duplicate key",
            "[".repeat(100) to "is not valid JSON",
            """{"exclude": ["!keep.env"]}""" to "negated patterns",
        )
        for ((content, message) in cases) {
            write(".secret-scanner.json", content)
            val r = cli("p")
            assertEquals(content, 2, r.exitCode)
            assertEquals(content, "", r.stdout)
            assertTrue("$content -> ${r.stderr}", r.stderr.contains(message))
        }
        File(wd, ".secret-scanner.json").delete()
        val missing = cli("p", "--config", "nope.json")
        assertEquals(2, missing.exitCode)
        assertTrue(missing.stderr.contains("--config file not found: nope.json"))
    }

    @Test
    fun scannerignoreAndExcludeFollowTheDocumentedPatternRules() {
        write("r/tests/a.env", "GH=${Fake.GITHUB}\n")
        write("r/src/tests.env", "GH=${Fake.GITHUB}\n")         // a file named like the directory pattern: kept
        write("r/docs/api.json", "\"gh\": \"${Fake.GITHUB}\"\n")
        write("r/deep/x/y/z.snap.json", "\"gh\": \"${Fake.GITHUB}\"\n")
        write("r/keep.env", "GH=${Fake.GITHUB}\n")
        write(".scannerignore", "# comment\n\ntests/\n/r/docs/api.json\n**/*.snap.json\n")
        val files = (json(cli("r", "--format", "json").stdout)["findings"] as List<*>).map { (it as Map<*, *>)["file"] }.toSet()
        assertEquals(setOf("r/src/tests.env", "r/keep.env"), files)
        val withExclude = (json(cli("r", "--format", "json", "--exclude", "keep.env").stdout)["findings"] as List<*>).size
        assertEquals(1, withExclude)
        val r = cli("r", "--exclude", "!x")
        assertEquals(2, r.exitCode)
        assertTrue(r.stderr.contains("--exclude: negated patterns"))
    }

    @Test
    fun ignorePatternUnits() {
        val rules = IgnoreRules.parse(listOf("build/", "*.log", "/top.env", "a/**/b.env", "q?.env", "  ", "# x"), "t")
        assertEquals(5, rules.size)
        assertTrue(rules.matches("x/build/y.env", false))
        assertFalse(rules.matches("x/build", false))      // a file named build is not the directory
        assertTrue(rules.matches("x/build", true))
        assertTrue(rules.matches("deep/app.log", false))
        assertTrue(rules.matches("top.env", false))
        assertFalse(rules.matches("sub/top.env", false))   // anchored
        assertTrue(rules.matches("a/b.env", false))
        assertTrue(rules.matches("a/x/y/b.env", false))
        assertTrue(rules.matches("q1.env", false))
        assertFalse(rules.matches("q12.env", false))
        assertFalse(IgnoreRules.NONE.matches("anything", false))
    }

    // ---- several paths (feature 9), `..` (point 9) and SARIF paths (point 3) ----

    @Test
    fun severalPathsAreScannedTogetherAndAFileReachedTwiceIsReadOnce() {
        write("a/x.env", "GH=${Fake.GITHUB}\n")
        write("b/y.env", "API_TOKEN=${Fake.GENERIC}\n")
        val r = cli("a", "b", "a/x.env", "b/../a", "--format", "sarif")
        assertEquals(1, r.exitCode)
        assertEquals(listOf("a/x.env", "b/y.env"), sarifUris(r.stdout).sorted())
    }

    @Test
    fun sarifPathsStayCleanWithDotSlashBackslashesDotDotAndASingleFile() {
        write("p3/sub/c.env", "GH=${Fake.GITHUB}\n")
        val variants = mutableListOf("./p3", "p3/sub/c.env", "p3/../p3/sub", "./p3/sub/../sub")
        if (File.separatorChar == '\\') variants += "p3\\sub"
        for (v in variants) assertEquals(v, listOf("p3/sub/c.env"), sarifUris(cli(v, "--format", "sarif").stdout))
    }

    @Test
    fun twoRootsOutsideTheWorkingDirectoryAreToldApartByName() {
        val outside = createTempDirectory(prefix = "outside-").toFile()
        try {
            File(outside, "one").mkdirs(); File(outside, "two").mkdirs()
            File(outside, "one/.env").writeText("GH=${Fake.GITHUB}\n")
            File(outside, "two/.env").writeText("GH=${Fake.GITHUB}\n")
            val r = cli(File(outside, "one").path, File(outside, "two").path, "--format", "sarif")
            assertEquals(listOf("one/.env", "two/.env"), sarifUris(r.stdout).sorted())
            assertFalse(r.stdout.contains(outside.path.replace('\\', '/')))
        } finally {
            outside.deleteRecursively()
        }
    }

    // ---- --max-findings (feature 13) and masking (feature 8) ----

    @Test
    fun maxFindingsShortensTheListButNotTheCountOrTheExitCode() {
        write("m/a.env", (1..30).joinToString("\n") { "GH$it=ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R" + (it % 10) } + "\n")
        val r = cli("m", "--max-findings", "5")
        assertEquals(1, r.exitCode)
        assertEquals(5, r.stdout.lines().count { it.contains("[GITHUB_TOKEN]") })
        assertTrue(r.stdout.contains("25 more finding(s) not shown (--max-findings 5)"))
        assertTrue(r.stdout.contains("30 finding(s) in m"))
        val s = cli("m", "--max-findings", "5", "--format", "sarif")
        assertEquals(5, sarifResults(s.stdout).size)
        assertTrue(s.stdout.contains("\"findings\": 30"))
    }

    @Test
    fun theMaskShowsFourAndFourByDefaultAndRevealIsExplicitAndCapped() {
        write("k/a.env", "GH=${Fake.GITHUB}\n")
        val t = cli("k").stdout
        assertTrue(t, t.contains("(" + Fake.GITHUB.take(4) + "..." + Fake.GITHUB.takeLast(4) + ")"))
        assertFalse(t.contains(Fake.GITHUB.take(5)))
        val r = cli("k", "--reveal", "10").stdout
        assertTrue(r.contains("(" + Fake.GITHUB.take(10) + "...)"))
        assertFalse(r.contains(Fake.GITHUB.take(11)))
        val hit = ScanHit("f", 1, 1, "K", "d", secretLength = 10, secretHead = "abcdefghij", secretTail = "ghij")
        assertEquals("ab...", Mask.masked(hit))
        assertEquals("abcdefghij", Mask.masked(hit, reveal = 64))
        assertEquals("...", Mask.masked(hit.copy(secretLength = 6, secretHead = "abcdef")))
        assertEquals("", Mask.masked(hit.copy(secretLength = 0)))
    }

    // ---- --dry-run (feature 14) ----

    @Test
    fun dryRunValidatesCountsAndReadsNothing() {
        write("d/a.env", "GH=${Fake.GITHUB}\n")
        write("d/b.env", "x=1\n")
        write("d/tests/c.env", "x=1\n")
        val r = cli("d", "--dry-run", "--exclude", "tests/")
        assertEquals(0, r.exitCode)
        assertTrue(r.stdout, r.stdout.startsWith("secret-scanner-cli $VERSION: dry run, no file content was read"))
        assertTrue(r.stdout, r.stdout.contains("files that would be read: 2"))
        assertTrue(r.stdout, r.stdout.contains("excluded: 1"))
        assertFalse(r.stdout.contains("GITHUB_TOKEN"))
        write(".secret-scanner.json", "{\"bad\": 1}")
        assertEquals("a dry run still rejects a bad configuration", 2, cli("d", "--dry-run").exitCode)
    }

    // ---- self-verification (feature 10) ----

    @Test
    fun selfVerificationNeedsAJarAndAWellFormedHash() {
        // The tests run from class directories, not from the jar: both flags must say so and exit 2, never pass silently.
        assertNull(selfSha256())
        assertEquals(2, cli("--self-sha256").exitCode)
        val r = cli(".", "--expect-sha256", "a".repeat(64))
        assertEquals(2, r.exitCode)
        assertTrue(r.stderr.contains("not from a jar"))
        assertEquals(2, cli(".", "--expect-sha256", "g".repeat(64)).exitCode)
    }

    // ---- --out (point 4) ----

    @Test
    fun outProblemsAreFoundBeforeTheScanWithTheCause() {
        assertTrue(outFileProblem(File(wd, "con.sarif"), isWindows = true)!!.contains("reserved device name"))
        assertTrue(outFileProblem(File(wd, "NUL"), isWindows = true)!!.contains("reserved device name"))
        assertTrue(outFileProblem(File(wd, "lpt1.json"), isWindows = true)!!.contains("reserved device name"))
        assertTrue(outFileProblem(File(wd, "a?b.sarif"), isWindows = true)!!.contains("character Windows does not allow"))
        assertNull(outFileProblem(File(wd, "console.sarif"), isWindows = true))
        assertNull(outFileProblem(File(wd, "con.sarif"), isWindows = false))
        assertTrue(outFileProblem(wd)!!.contains("points to a directory"))
        assertTrue(outFileProblem(File(wd, "missing/r.sarif"))!!.contains("does not exist"))
        assertNull(outFileProblem(File(wd, "r.sarif")))
        assertFalse("the probe leaves nothing behind", wd.listFiles()!!.any { it.name.startsWith(".secret-scanner-probe") })
        write("o/a.env", "GH=${Fake.GITHUB}\n")
        val r = cli("o", "--out", "missing/r.sarif")
        assertEquals(2, r.exitCode)
        assertEquals("", r.stdout)
    }

    @Test
    fun aReadOnlyDirectoryIsCaughtByTheProbe() {
        val ro = File(wd, "ro").apply { mkdirs() }
        assumeTrue("POSIX permissions only", ro.setWritable(false) && !java.nio.file.Files.isWritable(ro.toPath()))
        try {
            assertTrue(outFileProblem(File(ro, "r.sarif"))!!.contains("not writable"))
        } finally {
            ro.setWritable(true)
        }
    }

    // ---- flags (point 5) ----

    @Test
    fun everyNewUsageErrorIsExitTwoWithNothingOnStdout() {
        for (args in listOf(
            listOf("--format", "json", "--format", "json"), listOf("--quiet", "--verbose"), listOf("--fail-on", "high", "--no-fail"),
            listOf("--max-findings", "x"), listOf("--max-findings", "-3"), listOf("--max-file-size", "1000001"), listOf("--reveal"),
            listOf("--config"), listOf("--exclude", "--quiet"), listOf("--no-config", "--config", "a.json"), listOf("--verbose", "--verbose"),
        )) {
            val r = cli(*args.toTypedArray())
            assertEquals("$args", 2, r.exitCode)
            assertEquals("$args", "", r.stdout)
        }
    }

    // ---- SARIF metadata and fingerprints (feature 11) ----

    @Test
    fun sarifHasRuleMetadataLevelsColumnsAndFingerprintsThatSurviveALineMove() {
        write("f/a.env", "GH=${Fake.GITHUB}\nAPI_TOKEN=${Fake.GENERIC}\nGH2=${Fake.GITHUB}\n")
        val first = cli("f", "--format", "sarif").stdout
        @Suppress("UNCHECKED_CAST") val run = ((json(first)["runs"] as List<*>)[0] as Map<String, Any?>)
        assertEquals("utf16CodeUnits", run["columnKind"])
        val results = sarifResults(first)
        assertEquals(listOf("error", "warning", "error"), results.map { it["level"] })
        @Suppress("UNCHECKED_CAST")
        val fps = results.map { ((it["partialFingerprints"] as Map<String, Any?>)["secretScanner/v1"]) as String }
        assertEquals("two occurrences of one secret are two alerts", 3, fps.toSet().size)
        assertTrue(first.contains("\"security-severity\": \"8.0\""))
        assertTrue(first.contains("\"security-severity\": \"5.0\""))
        assertTrue(first.contains("\"endColumn\""))
        assertFalse("no timing inside the SARIF report", first.contains("durationMs"))
        write("f/a.env", "\n\n# moved\nGH=${Fake.GITHUB}\nAPI_TOKEN=${Fake.GENERIC}\nGH2=${Fake.GITHUB}\n")
        @Suppress("UNCHECKED_CAST")
        val moved = sarifResults(cli("f", "--format", "sarif").stdout).map { ((it["partialFingerprints"] as Map<String, Any?>)["secretScanner/v1"]) as String }
        assertEquals(fps, moved)
        write("f/a.env", "GH=${Fake.GITHUB}\nAPI_TOKEN=${Fake.GENERIC.reversed()}\nGH2=${Fake.GITHUB}\n")
        @Suppress("UNCHECKED_CAST")
        val changed = sarifResults(cli("f", "--format", "sarif").stdout).map { ((it["partialFingerprints"] as Map<String, Any?>)["secretScanner/v1"]) as String }
        assertNotEquals(fps[1], changed[1])
    }

    // ---- console safety (point 12) ----

    @Test
    fun controlAndBidiCharactersNeverReachTheConsoleRaw() {
        assertEquals("a\\u001b[31mb", consoleSafe("a\u001b[31mb"))
        assertEquals("x\\u202ey", consoleSafe("x\u202Ey"))
        assertEquals("tab\\u0009", consoleSafe("tab\t"))
        assertEquals("plain/path-é.env", consoleSafe("plain/path-é.env"))
        val hit = ScanHit("evil\u001b[2J\u009b.env", 1, 1, "K", "desc\u0007")
        val text = renderText(listOf(hit), "root\u001b]0;title\u0007")
        assertFalse(text.any { it == '\u001b' || it == '\u0007' || it == '\u009b' })
        assertTrue(text.contains("evil\\u001b[2J\\u009b.env"))
    }

    @Test
    fun aFileNameWithAnEscapeSequenceIsPrintedEscapedOnPosix() {
        val name = "evil\u001b[31m.env"
        val f = File(wd, "e/$name")
        f.parentFile.mkdirs()
        assumeTrue("the file system accepts ESC in a name", runCatching { f.writeText("GH=${Fake.GITHUB}\n"); f.exists() }.getOrDefault(false))
        val r = cli("e")
        assertFalse(r.stdout.contains('\u001b'))
        assertTrue(sarifUris(cli("e", "--format", "sarif").stdout).single().contains("%1B"))
    }

    // ---- the GitHub Action and the CI workflow (point 13) ----

    @Test
    fun theActionNeverExpandsAnExpressionInsideAShellScriptAndPinsEveryThirdPartyAction() {
        val project = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "action.yml").isFile }
        for (yml in listOf(File(project, "action.yml"), File(project, ".github/workflows/ci.yml"))) {
            val lines = yml.readLines()
            var inRun = false
            var runIndent = 0
            for ((n, line) in lines.withIndex()) {
                val indent = line.length - line.trimStart().length
                if (inRun && line.isNotBlank() && indent <= runIndent) inRun = false
                if (inRun) assertFalse("${yml.name}:${n + 1} expands an expression inside a script: $line", line.contains("\${{"))
                if (line.trimStart().startsWith("run:")) {
                    inRun = true
                    runIndent = indent
                    assertFalse("${yml.name}:${n + 1}", line.substringAfter("run:").contains("\${{"))
                }
                val uses = Regex("""^\s*-?\s*uses:\s*(\S+)""").find(line)?.groupValues?.get(1)
                if (uses != null && !uses.startsWith("./")) {
                    assertTrue("${yml.name}:${n + 1} pins '$uses' by a full commit SHA", Regex("""@[0-9a-f]{40}$""").containsMatchIn(uses))
                }
            }
        }
        val ci = File(project, ".github/workflows/ci.yml").readText()
        assertTrue("the CI workflow declares least-privilege permissions", Regex("""(?m)^permissions:\s*\n\s+contents: read""").containsMatchIn(ci))
        val action = File(project, "action.yml").readText()
        assertTrue("file names in the log cannot run workflow commands", action.contains("::stop-commands::"))
    }
}
