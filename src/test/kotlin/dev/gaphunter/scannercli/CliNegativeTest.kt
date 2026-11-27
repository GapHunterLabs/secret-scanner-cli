package dev.gaphunter.scannercli

import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.io.path.createTempDirectory

/**
 * Exit codes, stream routing and argument errors, through [cliMain] in-process
 * (fast), plus one test that starts a real child JVM to prove main() turns
 * those codes into the process exit status.
 */
class CliNegativeTest {

    companion object {
        private lateinit var base: File
        private lateinit var clean: File
        private lateinit var dirty: File

        @BeforeClass
        @JvmStatic
        fun setUp() {
            base = createTempDirectory(prefix = "cli-negative-").toFile()
            clean = File(base, "clean").apply { mkdirs() }
            File(clean, "app.yaml").writeText("name: my-service\n")
            dirty = File(base, "dirty").apply { mkdirs() }
            Fake.BY_KIND.entries.forEachIndexed { n, (_, lineAndSecret) -> File(dirty, "f$n.yaml").writeText(lineAndSecret.first + "\n") }
        }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            base.deleteRecursively()
        }
    }

    private fun cli(vararg args: String, console: Boolean = false): CliResult {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = PrintStream(out, true, "UTF-8").use { o -> PrintStream(err, true, "UTF-8").use { e -> cliMain(arrayOf(*args), o, e, console) } }
        return CliResult(code, out.toString("UTF-8"), err.toString("UTF-8"))
    }

    @Test
    fun everyFormatTimesEveryExitCode() {
        for (format in listOf("text", "sarif")) {
            val ok = cli(clean.path, "--format", format)
            assertEquals("$format clean", 0, ok.exitCode)
            val found = cli(dirty.path, "--format", format)
            assertEquals("$format findings", 1, found.exitCode)
            val noFail = cli(dirty.path, "--format", format, "--no-fail")
            assertEquals("$format findings --no-fail", 0, noFail.exitCode)
            assertEquals("--no-fail changes the exit code only", findingsOnly(found.stdout), findingsOnly(noFail.stdout))
            val missing = cli(File(base, "nope").path, "--format", format)
            assertEquals("$format missing path", 2, missing.exitCode)
            assertTrue(missing.stderr.contains("path not found"))
            assertEquals("", missing.stdout)
            val bad = cli(dirty.path, "--format", format, "--bogus")
            assertEquals("$format usage error", 2, bad.exitCode)
            if (format == "sarif") {
                assertEquals(0, sarifResults(ok.stdout).size)
                assertEquals(Fake.BY_KIND.size, sarifResults(found.stdout).size)
            } else {
                assertTrue(ok.stdout.contains("no findings"))
                assertTrue(found.stdout.contains("${Fake.BY_KIND.size} finding(s)"))
            }
            for ((_, lineAndSecret) in Fake.BY_KIND) {
                if (lineAndSecret.second.startsWith("-----BEGIN")) continue
                assertFalse("$format leaks a full secret", found.stdout.contains(lineAndSecret.second))
            }
        }
    }

    @Test
    fun usageErrorsExitTwoAndKeepStdoutEmpty() {
        val cases = listOf(
            listOf("--bogus"),
            listOf("-x"),
            listOf("--format"),
            listOf("--format", "xml"),
            listOf("--format", "text", "--format", "sarif"),
            listOf("--quiet", "--verbose"),
            listOf("--no-fail", "--fail-on", "high"),
            listOf("--fail-on", "critical"),
            listOf("--max-file-size", "-1"),
            listOf("--max-file-size", "ten"),
            listOf("--max-findings", "0"),
            listOf("--reveal", "65"),
            listOf("--reveal", "0"),
            listOf("--expect-sha256", "abc"),
            listOf("--config", "x.json", "--no-config"),
            listOf("--dry-run", "--reveal", "4"),
            listOf("--no-fail", "--no-fail"),
            listOf("--exclude"),
            listOf(""),
            listOf("--format", ""),
            listOf("--format", "SARIF"),
            listOf("--out"),
            listOf("--out", "--no-fail"),
            listOf("--banner", "--no-banner"),
        )
        for (args in cases) {
            val r = cli(*args.toTypedArray())
            assertEquals("$args", 2, r.exitCode)
            assertEquals("$args must not write help to stdout", "", r.stdout)
            assertTrue("$args names the problem on stderr", r.stderr.startsWith("secret-scanner-cli: "))
            assertTrue("$args prints usage on stderr", r.stderr.contains("Usage:"))
        }
    }

    @Test
    fun aSingleDashOutValueIsStillAFileName() {
        // Neighbour of the `--out --flag` check: only a `--` prefix is refused, `-report.txt` is a legal name.
        val out = File(base, "-report.txt")
        val r = cli(clean.path, "--out", out.path)
        assertEquals(0, r.exitCode)
        assertTrue(out.readText().contains("no findings"))
        out.delete()
    }

    @Test
    fun outToAMissingDirectoryOrADirectoryIsAPathErrorWithoutAStackTrace() {
        val cases = mapOf(File(base, "missing/dir/out.txt") to "--out directory does not exist", base to "--out points to a directory")
        for ((out, message) in cases) {
            val r = cli(dirty.path, "--out", out.path, "--no-fail")
            assertEquals("$out", 2, r.exitCode)
            assertFalse("$out: stack trace", r.stderr.contains("Exception"))
            // The pre-scan check's own message, not the write-time fallback: the run fails before scanning.
            assertTrue(r.stderr, r.stderr.contains(message))
            assertEquals("", r.stdout)
        }
    }

    @Test
    fun outToAReadOnlyFileIsAPathError() {
        val ro = File(base, "readonly.txt").apply { writeText("old") }
        assertTrue(ro.setWritable(false))
        try {
            val r = cli(clean.path, "--out", ro.path)
            assertEquals(2, r.exitCode)
            assertTrue(r.stderr, r.stderr.contains("--out file is not writable"))
            assertEquals("old", ro.readText())
        } finally {
            ro.setWritable(true)
            ro.delete()
        }
    }

    @Test
    fun outInsideTheScannedTreeIsNotPickedUpByTheNextScan() {
        val tree = File(base, "self").apply { mkdirs() }
        File(tree, "a.yaml").writeText(Fake.BY_KIND.values.joinToString("\n") { it.first } + "\n")
        for ((format, name) in listOf("text" to "report.json", "sarif" to "report.yaml", "json" to "report.yml")) {
            val out = File(tree, name)
            assertEquals(0, cli(tree.path, "--format", format, "--out", out.path, "--no-fail").exitCode)
            val first = out.readText()
            assertEquals(0, cli(tree.path, "--format", format, "--out", out.path, "--no-fail").exitCode)
            assertEquals("$format: the report must not produce findings of its own", findingsOnly(first), findingsOnly(out.readText()))
            out.delete()
        }
    }

    @Test
    fun aSingleFilePathWorksEndToEnd() {
        val r = cli(File(dirty, "f1.yaml").path, "--format", "sarif", "--no-fail")
        assertEquals(0, r.exitCode)
        assertEquals(listOf("f1.yaml"), sarifUris(r.stdout))
    }

    @Test
    fun versionAndHelpExitZeroOnStdout() {
        val v = cli("--version")
        assertEquals(0, v.exitCode)
        assertEquals("secret-scanner-cli 0.3.1", v.stdout.trim())
        val h = cli("--help")
        assertEquals(0, h.exitCode)
        assertTrue(h.stdout.contains("Usage:"))
        assertEquals("", h.stderr)
    }

    @Test
    fun bannerRulesHoldThroughTheRealEntryPoint() {
        val first = Banner.TEXT.trim().lines().first()
        assertFalse("piped text run", cli(clean.path).stdout.contains(first))
        assertTrue("console text run", cli(clean.path, console = true).stdout.contains(first))
        assertFalse("console sarif run", cli(clean.path, "--format", "sarif", console = true).stdout.contains(first))
        assertTrue("--banner when piped", cli(clean.path, "--banner").stdout.contains(first))
        assertFalse("--no-banner on a console", cli(clean.path, "--no-banner", console = true).stdout.contains(first))
        sarifResults(cli(clean.path, "--format", "sarif", console = true).stdout) // pure JSON on stdout
    }

    @Test
    fun theRealProcessExitStatusMatches() {
        // One child JVM per code: the only place exitProcess itself is exercised.
        assertEquals(1, runCli(dirty.path).exitCode)
        val usage = runCli("--format")
        assertEquals(2, usage.exitCode)
        assertEquals("", usage.stdout)
        assertEquals(0, runCli(clean.path, "--format", "sarif").exitCode)
    }

    /** The finding lines of a text report, without the summary (its timing differs between two runs). */
    private fun findingsOnly(stdout: String) =
        stdout.lines().filterNot { it.startsWith("secret-scanner-cli: scanned ") || it.trimStart().startsWith("\"durationMs\"") }.joinToString("\n")
}
