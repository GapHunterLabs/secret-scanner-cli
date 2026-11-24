package dev.gaphunter.scannercli

import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import java.io.File
import java.lang.management.ManagementFactory
import java.lang.management.MemoryType
import kotlin.io.path.createTempDirectory

/**
 * Heavy stress and ReDoS measurements. Skipped unless the build passes
 * `-Pstress` (see docs/TESTING.md), so the normal `./gradlew test` stays fast.
 * Each case prints one line with wall time and peak heap and appends it to
 * build/reports/stress/stress-results.txt. The budgets are deliberately loose
 * (they catch a quadratic or an out-of-memory regression, not a 20 % slowdown).
 */
class StressTest {

    companion object {
        private lateinit var base: File
        private val report = File("build/reports/stress/stress-results.txt")

        @BeforeClass
        @JvmStatic
        fun setUpClass() {
            if (System.getProperty("scanner.stress") != "true") return
            base = createTempDirectory(prefix = "scanner-stress-").toFile()
            report.parentFile.mkdirs()
            report.appendText("# run ${java.time.LocalDateTime.now()} maxHeap=${Runtime.getRuntime().maxMemory() / (1024 * 1024)} MB java=${System.getProperty("java.version")}\n")
        }

        @AfterClass
        @JvmStatic
        fun tearDownClass() {
            if (::base.isInitialized) base.deleteRecursively()
        }
    }

    @Before
    fun onlyWhenAskedFor() {
        assumeTrue("stress tests run only with -Pstress", System.getProperty("scanner.stress") == "true")
    }

    private fun <T> measure(name: String, budgetMs: Long, block: () -> T): T {
        System.gc()
        val pools = ManagementFactory.getMemoryPoolMXBeans().filter { it.type == MemoryType.HEAP }
        pools.forEach { it.resetPeakUsage() }
        val start = System.nanoTime()
        val result = block()
        val ms = (System.nanoTime() - start) / 1_000_000
        val peakMb = pools.sumOf { it.peakUsage.used } / (1024 * 1024)
        val line = "%-58s %8d ms  peak heap %5d MB  (budget %d ms)".format(name, ms, peakMb, budgetMs)
        println(line)
        report.appendText(line + "\n")
        assertTrue("$name took $ms ms, budget $budgetMs ms", ms <= budgetMs)
        return result
    }

    private fun dir(name: String) = File(base, name).apply { mkdirs() }

    @Test
    fun a50MegabyteFile() {
        val d = dir("big")
        val f = File(d, "big.yaml")
        var lines = 0
        f.bufferedWriter().use { w ->
            var written = 0L
            while (written < 50L * 1024 * 1024) {
                val line = "  some_key: \"ordinary value number $lines with words\"   # comment\n"
                w.write(line)
                written += line.length
                lines++
            }
            w.write("db.password=${Fake.GENERIC}\n")
        }
        val sizeMb = f.length() / (1024 * 1024)
        val hits = measure("50 MB file (${sizeMb} MB, ${lines / 1000}k lines)", 120_000) { Scanner.scan(d) }
        assertEquals(listOf("GENERIC_HIGH_ENTROPY"), hits.map { it.kind })
    }

    @Test
    fun aSingleLineOfFiveMegabytesWorstCaseForTheAssignmentRule() {
        val d = dir("longline")
        File(d, "min.js").writeText("a".repeat(5 * 1024 * 1024) + " token " + Fake.GITHUB + "\n")
        val hits = measure("single 5 MB line, one key-character run", 60_000) { Scanner.scan(d) }
        assertEquals(listOf("GITHUB_TOKEN"), hits.map { it.kind })
    }

    @Test
    fun aSingleLineOfFiveMegabytesOfJwtLookalikes() {
        val d = dir("jwtline")
        File(d, "x.json").writeText("-eyJ".repeat(5 * 1024 * 1024 / 4) + "\n")
        val hits = measure("single 5 MB line of -eyJ (JWT adversarial)", 60_000) { Scanner.scan(d) }
        assertTrue(hits.isEmpty())
    }

    @Test
    fun reDosEveryPatternAtOneMegabyte() {
        val n = 1024 * 1024
        val adversarial = linkedMapOf(
            "assignment: a*n" to "a".repeat(n),
            "assignment: a.*n" to "a.".repeat(n / 2),
            "assignment: k=\"*n" to "k=\"".repeat(n / 3),
            "unquoted: k= x x x" to "k=" + "x ".repeat(n / 2),
            "aws: AKIA*n" to "AKIA".repeat(n / 4),
            "github: ghp_ a*n _" to "ghp_" + "a".repeat(n) + "_",
            "github: -ghp_*n" to "-ghp_".repeat(n / 5),
            "slack: xoxb- then -*n" to "xoxb-" + "-".repeat(n),
            "slack: ' xoxb-'*n" to " xoxb-".repeat(n / 6),
            "jwt: -eyJ*n" to "-eyJ".repeat(n / 4),
            "jwt: .eyJaaaaa*n" to ".eyJaaaaa".repeat(n / 9),
            "jwt: eyJa.*n" to " eyJa.".repeat(n / 6),
            "pem: -*n" to "-".repeat(n),
            "pem: -----BEGIN *n" to "-----BEGIN ".repeat(n / 11),
            "stripe: ' sk_live_'*n" to " sk_live_".repeat(n / 9),
            "name+entropy: password=<1 MB value>" to "password=" + "Xk9mQ2pL8v".repeat(n / 10),
            "placeholder: your_ a*n" to "your_" + "a".repeat(n),
            "placeholder: <*n" to "<".repeat(n),
            "placeholder: \${*n" to "\${".repeat(n / 2),
        )
        val d = dir("redos")
        for ((name, line) in adversarial) {
            val f = File(d, "case.yaml")
            f.writeText(line + "\n")
            measure("ReDoS 1 MB, $name", 10_000) { Scanner.scan(d) }
            measure("ReDoS 1 MB detector only, $name", 10_000) { SecretDetector.scanLiteral(line, "password") }
        }
    }

    @Test
    fun tenThousandSmallFiles() {
        val d = dir("many")
        for (i in 0 until 10_000) {
            val sub = File(d, "pkg${i / 100}").apply { mkdirs() }
            File(sub, "F$i.kt").writeText("package x\nval name = \"value $i\"\n" + if (i % 1000 == 0) "val gh = \"${Fake.GITHUB}\"\n" else "")
        }
        val hits = measure("10,000 small files in 100 directories", 120_000) { Scanner.scan(d) }
        assertEquals(10, hits.size)
    }

    @Test
    fun deeplyNestedDirectories() {
        val d = dir("deep")
        var cur = d
        repeat(300) { cur = File(cur, "d").apply { mkdirs() } }
        File(cur, "Deep.kt").writeText("val gh = \"${Fake.GITHUB}\"\n")
        val hits = measure("300 nested directories (path ${cur.path.length} chars)", 60_000) { Scanner.scan(d) }
        assertEquals(1, hits.size)
        assertTrue(hits[0].file.count { it == '/' } == 300)
    }

    @Test
    fun aHundredThousandFindingsRenderedAsTextAndSarif() {
        val d = dir("manyhits")
        File(d, "hits.yaml").bufferedWriter().use { w -> repeat(100_000) { w.write("t$it: \"${Fake.GITHUB}\"\n") } }
        val hits = measure("100,000 findings: scan", 60_000) { Scanner.scan(d) }
        assertEquals(100_000, hits.size)
        val text = measure("100,000 findings: render text", 60_000) { renderText(hits, d) }
        val sarif = measure("100,000 findings: render SARIF (${hits.size} results)", 60_000) { renderSarif(hits) }
        measure("100,000 findings: parse SARIF back (${sarif.length / (1024 * 1024)} MB)", 60_000) { sarifResults(sarif) }
        assertTrue(text.endsWith("100000 finding(s) in ${d.path}"))
    }
}
