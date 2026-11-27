package dev.gaphunter.scannercli

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import kotlin.io.path.createTempDirectory

/** The 0.3.0 formats and placeholders, and how files are read: encodings, columns, binary content and size limits. */
class FormatsAndReadingTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "formats-").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    // ---- fake values, built at runtime so no complete token is committed ----

    private val alnum = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXyZ"
    private val hex = "0123456789abcdef"

    private fun mixed(n: Int, alphabet: String) = (0 until n).map { alphabet[(it * 7 + 3) % alphabet.length] }.joinToString("")

    /** kind -> (a value of the shortest accepted length, the same value one character shorter). */
    private val shortest: Map<String, Pair<String, String>> by lazy {
        fun pair(prefix: String, body: String, suffix: String = "") = (prefix + body + suffix) to (prefix + body.dropLast(1) + suffix)
        mapOf(
            "ATLASSIAN_API_TOKEN" to pair("ATATT3", mixed(186, alnum + "_-=")),
            "DOPPLER_TOKEN" to pair("dp.pt.", mixed(43, alnum)),
            "AGE_SECRET_KEY" to pair("AGE-SECRET-KEY-1", mixed(58, "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L")),
            "LINEAR_API_KEY" to pair("lin_api_", mixed(40, alnum)),
            "POSTMAN_API_KEY" to pair("PMAK-" + mixed(24, hex) + "-", mixed(34, hex)),
            "GRAFANA_SERVICE_ACCOUNT_TOKEN" to pair("glsa_" + mixed(32, alnum) + "_", mixed(8, hex)),
            "SQUARE_ACCESS_TOKEN" to pair("sq0atp-", mixed(22, alnum)),
            "AZURE_STORAGE_KEY" to pair("AccountKey=", mixed(86, alnum + "+/"), "=="),
            "BCRYPT_HASH" to pair("$" + "2b$12$", mixed(53, "./" + alnum)),
        )
    }

    private fun kind(v: String) = SecretDetector.scanLiteral(v)?.kind

    @Test
    fun everyNewFormatMatchesAtItsShortestAndNotOneCharacterLess() {
        assertEquals(9, shortest.size)
        for ((k, p) in shortest) {
            assertEquals("$k shortest", k, kind(p.first))
            assertEquals("$k inside a line", k, SecretDetector.scanSignatures("x = '${p.first}' # note")?.kind)
            assertTrue("$k one shorter", kind(p.second) != k)
        }
    }

    @Test
    fun headersOfPrivateKeyFilesAreReportedWhateverTheirType() {
        for (h in listOf("PGP PRIVATE KEY BLOCK", "PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "EC PRIVATE KEY")) {
            assertEquals(h, "PRIVATE_KEY", kind("-----BEGIN $h-----"))
        }
        assertEquals("PUTTY_PRIVATE_KEY", kind("PuTTY-User-Key-File-" + "3: ssh-ed25519"))
        assertEquals("PUTTY_PRIVATE_KEY", kind("PuTTY-User-Key-File-" + "2: ssh-rsa"))
        assertNull(kind("PuTTY-User-Key-File-" + "4: ssh-rsa"))
        assertNull(kind("-----BEGIN " + "PGP PUBLIC KEY BLOCK-----"))
    }

    @Test
    fun severityIsHighForExactFormatsAndMediumForTheGuessesAndTheHashes() {
        assertEquals(Severity.HIGH, SecretDetector.scanLiteral(Fake.GITHUB)!!.severity)
        assertEquals(Severity.MEDIUM, SecretDetector.scanLiteral(shortest.getValue("BCRYPT_HASH").first)!!.severity)
        assertEquals(Severity.MEDIUM, SecretDetector.scanLiteral(Fake.GENERIC, "api_key")!!.severity)
        assertEquals(Severity.MEDIUM, SecretDetector.RULES.getValue("GOOGLE_API_KEY").second)
        assertEquals(SecretDetector.KINDS.toSet(), SecretDetector.RULES.keys)
    }

    @Test
    fun disabledRulesAreNotReported() {
        assertNull(SecretDetector.scanLiteral(Fake.GITHUB, disabled = setOf("GITHUB_TOKEN")))
        assertNull(SecretDetector.scanLiteral(Fake.GENERIC, "api_key", disabled = setOf(SecretDetector.GENERIC_KIND)))
        assertEquals("AWS_ACCESS_KEY", SecretDetector.scanLiteral(Fake.AWS, disabled = setOf("GITHUB_TOKEN"))?.kind)
    }

    // ---- placeholders and URLs (point 15) ----

    @Test
    fun placeholdersAndEmptyUrlParametersAreNotReportedButRealTokensInUrlsAre() {
        File(root, "a.env").writeText(
            listOf(
                "API_URL=https://example.com/path?token=", "API_KEY=<YOUR_API_KEY>", "DB_PASSWORD=changeme", "SECRET_KEY=REPLACE_ME",
                "SECRET=replace-me", "AWS_KEY=AKIA" + "IOSFODNN7EXAMPLE", "OPENAI=sk-proj-" + "X".repeat(48), "TOKEN=ghp_" + "*".repeat(36),
                "CALLBACK=https://example.com/cb?token=${Fake.GITHUB}",
            ).joinToString("\n") + "\n",
        )
        val hits = Scanner.scan(root)
        assertEquals(listOf(9 to "GITHUB_TOKEN"), hits.map { it.line to it.kind })
    }

    // ---- encodings (point 10) ----

    @Test
    fun aUtf8ByteOrderMarkNoLongerHidesTheFirstLine() {
        File(root, "a.env").writeBytes(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + "API_TOKEN=${Fake.GENERIC}\n".toByteArray())
        File(root, "b.yaml").writeBytes(byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + "gh: \"${Fake.GITHUB}\"\n".toByteArray())
        val hits = Scanner.scan(root).sortedBy { it.file }
        assertEquals(listOf("a.env" to 11, "b.yaml" to 6), hits.map { it.file to it.column })
    }

    @Test
    fun utf16WithAByteOrderMarkIsReadInBothByteOrders() {
        File(root, "le.json").writeBytes(byteArrayOf(0xFF.toByte(), 0xFE.toByte()) + "{\"token\": \"${Fake.GITHUB}\"}".toByteArray(Charsets.UTF_16LE))
        File(root, "be.json").writeBytes(byteArrayOf(0xFE.toByte(), 0xFF.toByte()) + "{\"token\": \"${Fake.GITHUB}\"}".toByteArray(Charsets.UTF_16BE))
        assertEquals(listOf(1 to 12, 1 to 12), Scanner.scan(root).map { it.line to it.column })
    }

    @Test
    fun latin1AndWindows1252KeepOneColumnPerByte() {
        // "configuración" in Latin-1: one byte per letter, so the token starts where a Latin-1 editor shows it.
        val line = "desc = 'configuración' ; gh = '${Fake.GITHUB}'\n"
        File(root, "a.kt").writeBytes(line.toByteArray(Charsets.ISO_8859_1))
        File(root, "b.kt").writeBytes(line.toByteArray(Charset1252))
        val expected = line.indexOf(Fake.GITHUB) + 1
        assertEquals(listOf(expected, expected), Scanner.scan(root).map { it.column })
    }

    @Test
    fun aTruncatedUtf8FileIsStillReadUpToTheCut() {
        val bytes = "gh = \"${Fake.GITHUB}\"\nname = \"café\"".toByteArray()
        File(root, "a.kt").writeBytes(bytes.copyOf(bytes.size - 2))  // cut inside the two-byte é and its closing quote
        assertEquals(listOf("GITHUB_TOKEN"), Scanner.scan(root).map { it.kind })
    }

    // ---- columns (point 11) ----

    @Test
    fun aSignatureInTheMiddleOfALineGetsItsRealColumnNotColumnOne() {
        val line = "\tcurl -H 'x: y' ${Fake.GITHUB} --fail"
        File(root, "a.sh").writeText("$line\n")
        val hit = Scanner.scan(root).single()
        assertEquals(line.indexOf(Fake.GITHUB) + 1, hit.column)
        assertEquals(hit.column + Fake.GITHUB.length, hit.endColumn)
    }

    @Test
    fun columnsCountUtf16UnitsSoEmojiAndTabsBeforeASecretAreExact() {
        val line = "# 🔑\té日 x = \"${Fake.GITHUB}\""
        File(root, "a.py").writeText("$line\n")
        val hit = Scanner.scan(root).single()
        assertEquals(line.indexOf(Fake.GITHUB) + 1, hit.column)
    }

    @Test
    fun aValueThatAlsoAppearsEarlierOnTheLineGetsTheColumnOfTheAssignment() {
        val v = Fake.GENERIC
        val line = "# old $v was rotated; api_token: \"$v\""
        File(root, "a.yaml").writeText("$line\n")
        val hits = Scanner.scan(root)
        assertEquals(listOf(line.lastIndexOf(v) + 1), hits.map { it.column })
    }

    @Test
    fun aVeryLongLineKeepsItsColumns() {
        val pad = "a".repeat(200_000)
        File(root, "a.js").writeText("var s = '$pad'; var k = '${Fake.GITHUB}';\n")
        val hit = Scanner.scan(root).single()
        assertEquals("var s = '$pad'; var k = '".length + 1, hit.column)
    }

    // ---- binary content and size limits (points 6 and 7) ----

    @Test
    fun aFileOverTheSizeLimitIsSkippedAndListedAndZeroMeansNoLimit() {
        val big = File(root, "dump.json")
        big.writeText("x".repeat(2 * 1024 * 1024) + "\n\"token\": \"${Fake.GITHUB}\"\n")
        val stats = ScanStats()
        assertTrue(Scanner.scanAll(listOf(root to ""), ScanOptions(maxFileBytes = 1024 * 1024), stats).isEmpty())
        assertEquals(listOf("dump.json"), stats.tooLarge)
        val noLimit = ScanStats()
        assertEquals(1, Scanner.scanAll(listOf(root to ""), ScanOptions(maxFileBytes = 0), noLimit).size)
        assertTrue(noLimit.tooLarge.isEmpty())
        // exactly at the limit is read
        val exact = ScanStats()
        assertEquals(1, Scanner.scanAll(listOf(root to ""), ScanOptions(maxFileBytes = big.length()), exact).size)
    }

    @Test
    fun theDefaultLimitIs25Megabytes() {
        assertEquals(25L * 1024 * 1024, ScanOptions().maxFileBytes)
    }

    @Test
    fun aNulAfterTheFirst8KbDoesNotMakeATextFileBinary() {
        File(root, "a.json").writeBytes(("\"gh\": \"${Fake.GITHUB}\"\n" + "y".repeat(9000)).toByteArray() + byteArrayOf(0) + "\n".toByteArray())
        val stats = ScanStats()
        assertEquals(1, Scanner.scanAll(listOf(root to ""), ScanOptions(), stats).size)
        assertTrue(stats.binary.isEmpty())
    }

    @Test
    fun anEmptyFileAndAOneByteFileAreReadWithoutNoise() {
        File(root, "empty.env").writeBytes(ByteArray(0))
        File(root, "one.env").writeBytes(byteArrayOf('x'.code.toByte()))
        val stats = ScanStats()
        assertTrue(Scanner.scanAll(listOf(root to ""), ScanOptions(), stats).isEmpty())
        assertEquals(2, stats.filesScanned)
        assertEquals(0, stats.skipped)
    }

    // ---- test and example paths (feature 12) ----

    @Test
    fun testAndExamplePathsAreTaggedNotDowngraded() {
        for (p in listOf("tests/a.kt", "src/test/kotlin/A.kt", "x/__tests__/a.ts", "fixtures/.env", "examples/app.yaml", "AppTest.kt",
            "app_test.go", "test_app.py", "app.spec.ts", "app.test.js", "docs/samples/a.json")) assertTrue(p, Scanner.isTestPath(p))
        for (p in listOf("src/main/App.kt", "latest/a.kt", "contest.py", "testing.env", "attestation/a.kt", "test", "src/Tester.kt")) {
            assertFalse(p, Scanner.isTestPath(p))
        }
        File(root, "tests").mkdirs()
        File(root, "tests/a.env").writeText("K=${Fake.GITHUB}\n")
        val hit = Scanner.scan(root).single()
        assertTrue(hit.testPath)
        assertEquals(Severity.HIGH, hit.severity)
        assertTrue(renderText(listOf(hit), "x").contains("[test-or-example]"))
    }

    private companion object {
        val Charset1252: java.nio.charset.Charset = java.nio.charset.Charset.forName("windows-1252")
    }
}
