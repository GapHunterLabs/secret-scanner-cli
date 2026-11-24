package dev.gaphunter.scannercli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/** SARIF and text output under hostile file names and every detector kind. */
class SarifNegativeTest {

    private fun hit(file: String, kind: String = "GITHUB_TOKEN", description: String = "d") = ScanHit(file, 3, 7, kind, description)

    @Test
    fun emptyResultsIsValidJson() {
        val results = sarifResults(renderSarif(emptyList()))
        assertTrue(results.isEmpty())
    }

    @Test
    fun everyRuleKindProducesValidJsonWithItsRuleDescription() {
        val kinds = Fake.BY_KIND.keys.toList()
        val sarif = renderSarif(kinds.map { hit("a.kt", it) })
        assertEquals(kinds, sarifResults(sarif).map { it["ruleId"] })
        for (k in kinds) assertFalse("$k has no rule description of its own", sarif.contains("\"text\": \"$k\""))
    }

    @Test
    fun everyControlCharacterInAFileNameIsEscaped() {
        for (code in 0 until 0x20) {
            val name = "dir/a" + code.toChar() + "b.kt"
            try {
                sarifResults(renderSarif(listOf(hit(name))))
            } catch (e: IllegalArgumentException) {
                fail("U+%04X in a file name broke the SARIF JSON: ${e.message}".format(code))
            }
        }
    }

    @Test
    fun controlCharactersInADescriptionAreEscaped() {
        val sarif = renderSarif(listOf(hit("a.kt", description = "tab\there, cr\rthere, nul\u0000, quote\" backslash\\ ls\u2028")))
        sarifResults(sarif) // throws if invalid
        assertTrue(sarif.contains("tab\\there"))
        assertTrue(sarif.contains("cr\\rthere"))
        assertTrue(sarif.contains("\\u0000"))
        assertTrue(sarif.contains("\\u2028"))
    }

    @Test
    fun fileNamesBecomeValidUriReferences() {
        val cases = mapOf(
            "src/My Config.kt" to "src/My%20Config.kt",
            "a#b.kt" to "a%23b.kt",
            "100%.kt" to "100%25.kt",
            "q?.kt" to "q%3F.kt",
            "c:x.kt" to "c%3Ax.kt",
            "caf\u00e9/\u65e5\u672c.kt" to "caf%C3%A9/%E6%97%A5%E6%9C%AC.kt",
            "plain/path-1_2.~kt" to "plain/path-1_2.~kt",
            "tab\tname.kt" to "tab%09name.kt",
        )
        for ((file, uri) in cases) assertEquals(file, uri, sarifUri(file))
        val uris = sarifUris(renderSarif(cases.keys.map { hit(it) }))
        assertEquals(cases.values.toList(), uris)
        val uriRef = Regex("""^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$""")
        for (u in uris) assertTrue(u, uriRef.matches(u))
    }

    @Test
    fun theSarifSchemaUrlIsTheOasisOne() {
        assertTrue(renderSarif(emptyList()).contains("\"\$schema\": \"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json\""))
    }

    @Test
    fun textOutputKeepsTheRawPathForHumans() {
        // Only SARIF needs URI encoding; the text output stays readable.
        assertTrue(renderText(listOf(hit("src/My Config.kt")), File(".")).contains("src/My Config.kt:3:7"))
    }

    @Test
    fun outFileProblemCatchesTheCommonMistakesBeforeTheScan() {
        val tmp = kotlin.io.path.createTempDirectory("outfile").toFile()
        try {
            assertEquals(null, outFileProblem(File(tmp, "report.sarif")))
            assertTrue(outFileProblem(tmp)!!.contains("directory, not a file"))
            assertTrue(outFileProblem(File(tmp, "missing/x.sarif"))!!.contains("does not exist"))
            // A bare file name resolves against the working directory, which exists.
            assertEquals(null, outFileProblem(File("relative-report.sarif")))
        } finally {
            tmp.deleteRecursively()
        }
    }
}
