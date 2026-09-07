package dev.gaphunter.scannercli

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class OutputFormatTest {

    private val sampleHit = ScanHit(
        file = "src/Config.kt",
        line = 12,
        column = 5,
        kind = "AWS_ACCESS_KEY",
        description = "Looks like an AWS access key ID (AKIAIOSF...)",
    )

    @Test
    fun textOutputIsEmptyForNoFindings() {
        val text = renderText(emptyList(), File("."))
        assertTrue(text.contains("no findings"))
    }

    @Test
    fun textOutputListsFileLineAndKind() {
        val text = renderText(listOf(sampleHit), File("."))
        assertTrue(text.contains("src/Config.kt:12:5"))
        assertTrue(text.contains("[AWS_ACCESS_KEY]"))
        assertTrue(text.contains("1 finding(s)"))
    }

    @Test
    fun sarifOutputIsWellFormedAroundTheOneResult() {
        val sarif = renderSarif(listOf(sampleHit))
        assertTrue(sarif.contains("\"version\": \"2.1.0\""))
        assertTrue(sarif.contains("\"ruleId\": \"AWS_ACCESS_KEY\""))
        assertTrue(sarif.contains("\"uri\": \"src/Config.kt\""))
        assertTrue(sarif.contains("\"startLine\": 12"))
        assertTrue(sarif.contains("\"startColumn\": 5"))
    }

    @Test
    fun sarifEscapesQuotesInMessages() {
        val hit = sampleHit.copy(description = "value has a \"quoted\" part")
        val sarif = renderSarif(listOf(hit))
        assertTrue(sarif.contains("\\\"quoted\\\""))
    }
}
