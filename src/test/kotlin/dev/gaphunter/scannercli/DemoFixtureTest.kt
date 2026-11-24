package dev.gaphunter.scannercli

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.io.path.createTempDirectory

/**
 * End to end on a small demo project (src/test/resources/demo-fixture). The
 * fixture holds `{{NAME}}` markers instead of secret-shaped values; they are
 * filled here with the runtime-built fakes from [Fake], so the committed files
 * never contain a complete token.
 */
class DemoFixtureTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "demo-fixture-").toFile()
        materializeDemoFixture(root)
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun theDemoProjectReportsExactlyTheExpectedFindings() {
        val hits = Scanner.scan(root).sortedWith(compareBy({ it.file }, { it.line })).map { "${it.file}:${it.line}:${it.kind}" }
        assertEquals(
            listOf(
                ".env:1:AWS_ACCESS_KEY",
                ".env:2:STRIPE_KEY",
                ".env:3:GENERIC_HIGH_ENTROPY",
                "deploy.yaml:3:JWT",
                "deploy.yaml:4:SLACK_TOKEN",
                "deploy.yaml:6:PRIVATE_KEY",
                "src/Config.kt:3:GITHUB_TOKEN",
            ),
            hits,
        )
    }

    @Test
    fun theDemoProjectThroughTheCliInBothFormats() {
        for (format in listOf("text", "sarif")) {
            val out = ByteArrayOutputStream()
            val code = PrintStream(out, true, "UTF-8").use { cliMain(arrayOf(root.path, "--format", format), it, it, false) }
            assertEquals(1, code)
            val text = out.toString("UTF-8")
            if (format == "sarif") assertEquals(7, sarifResults(text).size)
            for (secret in listOf(Fake.AWS, Fake.STRIPE, Fake.GENERIC, Fake.JWT, Fake.SLACK, Fake.GITHUB)) {
                assertFalse("$format output carries a full secret", text.contains(secret))
            }
        }
    }
}

/** Copies the demo fixture into [target] and fills its markers. Shared with the jar end-to-end check in docs/TESTING.md. */
internal fun materializeDemoFixture(target: File) {
    val values = mapOf(
        "{{AWS}}" to Fake.AWS, "{{STRIPE}}" to Fake.STRIPE, "{{JWT}}" to Fake.JWT,
        "{{SLACK}}" to Fake.SLACK, "{{PEM_HEADER}}" to Fake.PEM, "{{GITHUB}}" to Fake.GITHUB,
    )
    val source = File(DemoFixtureTest::class.java.getResource("/demo-fixture")!!.toURI())
    source.walkTopDown().filter { it.isFile }.forEach { f ->
        val dest = File(target, f.relativeTo(source).path)
        dest.parentFile.mkdirs()
        var text = f.readText()
        for ((marker, value) in values) text = text.replace(marker, value)
        dest.writeText(text)
    }
}
