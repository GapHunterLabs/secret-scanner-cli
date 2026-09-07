package dev.gaphunter.scannercli

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import kotlin.io.path.createTempDirectory

class ScannerTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "scanner-cli-test-").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    private fun write(relativePath: String, content: String): File {
        val file = File(root, relativePath)
        file.parentFile.mkdirs()
        file.writeText(content)
        return file
    }

    @Test
    fun detectsAwsKeyInEnvFile() {
        write(".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        val hits = Scanner.scan(root)
        assertEquals(1, hits.size)
        assertEquals("AWS_ACCESS_KEY", hits[0].kind)
        assertEquals(".env", hits[0].file)
        assertEquals(1, hits[0].line)
    }

    @Test
    fun detectsGithubTokenInKotlinAssignment() {
        val token = "ghp_" + "a".repeat(36)
        write("src/Config.kt", "val githubToken = \"$token\"\n")
        val hits = Scanner.scan(root)
        assertEquals(1, hits.size)
        assertEquals("GITHUB_TOKEN", hits[0].kind)
        assertEquals(1, hits[0].line)
    }

    @Test
    fun detectsGenericHighEntropySecretByVariableName() {
        // High-entropy, not a dictionary word, long enough, credential-like
        // variable name -- exactly the GENERIC_HIGH_ENTROPY case, same
        // heuristic as api-security-companion's SecretDetectorTest.
        write("config.properties", "db.password=Xk9mQ2pL8vRnZ4wT7Ba3\n")
        val hits = Scanner.scan(root)
        assertEquals(1, hits.size)
        assertEquals("GENERIC_HIGH_ENTROPY", hits[0].kind)
    }

    @Test
    fun doesNotFlagObviousPlaceholder() {
        write("config.properties", "db.password=changeme\napi.token=your_token_here\n")
        val hits = Scanner.scan(root)
        assertTrue("expected no findings for placeholder values, got: $hits", hits.isEmpty())
    }

    @Test
    fun doesNotFlagLowEntropyOrShortValues() {
        write("app.yaml", "name: my-service\nenvironment: production\n")
        val hits = Scanner.scan(root)
        assertTrue("expected no findings for plain config values, got: $hits", hits.isEmpty())
    }

    @Test
    fun skipsIgnoredDirectories() {
        write("node_modules/some-lib/secret.js", "const token = \"ghp_" + "b".repeat(36) + "\";\n")
        write("build/generated/secret.kt", "val token = \"ghp_" + "c".repeat(36) + "\"\n")
        val hits = Scanner.scan(root)
        assertTrue("expected node_modules/build to be skipped, got: $hits", hits.isEmpty())
    }

    @Test
    fun skipsNonScannableExtensions() {
        write("logo.png", "AKIAIOSFODNN7EXAMPLE") // not a real PNG, just proving extension-based skip
        val hits = Scanner.scan(root)
        assertTrue("expected .png to be skipped regardless of content, got: $hits", hits.isEmpty())
    }

    @Test
    fun detectsStripeKeyEmbeddedOutsideAssignment() {
        // Not a clean `key = "value"` line -- a raw value inside a shell
        // command -- still caught via the whole-line fallback pass.
        val fakeStripeKey = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        write("deploy.sh", "curl -H \"Authorization: Bearer $fakeStripeKey\" https://api.example.com\n")
        val hits = Scanner.scan(root)
        assertEquals(1, hits.size)
        assertEquals("STRIPE_KEY", hits[0].kind)
    }

    @Test
    fun reportsCorrectLineNumberForMultilineFile() {
        val token = "ghp_" + "d".repeat(36)
        write("src/Multi.kt", "// line 1\n// line 2\nval t = \"$token\"\n// line 4\n")
        val hits = Scanner.scan(root)
        assertEquals(1, hits.size)
        assertEquals(3, hits[0].line)
    }
}
