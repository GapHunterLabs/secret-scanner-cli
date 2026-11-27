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

/**
 * The 16 signatures and the strict credential heuristic ported from
 * api-security-companion, and the SARIF uri base. Every fake token is built at
 * run time from pieces, so no complete token shape is committed.
 */
class PortedRulesTest {

    private fun kind(value: String, hint: String? = null, heuristic: Boolean = true) =
        SecretDetector.scanLiteral(value, hint, heuristic)?.kind

    /** kind -> (the shortest value it detects, the same value one body character short). */
    private val boundaries: Map<String, Pair<String, String>> = linkedMapOf(
        "OPENAI_API_KEY" to ("sk-" + "proj-" + "A".repeat(40) to "sk-" + "proj-" + "A".repeat(39)),
        "ANTHROPIC_API_KEY" to ("sk-" + "ant-api03-" + "a".repeat(80) to "sk-" + "ant-api03-" + "a".repeat(79)),
        "HUGGINGFACE_TOKEN" to ("hf" + "_" + "a".repeat(34) to "hf" + "_" + "a".repeat(33)),
        "GROQ_API_KEY" to ("gsk" + "_" + "a".repeat(52) to "gsk" + "_" + "a".repeat(51)),
        "PERPLEXITY_API_KEY" to ("pplx" + "-" + "a".repeat(48) to "pplx" + "-" + "a".repeat(47)),
        "GOOGLE_API_KEY" to ("AI" + "za" + "a".repeat(35) to "AI" + "za" + "a".repeat(34)),
        "GITHUB_FINE_GRAINED_TOKEN" to ("github_" + "pat_" + "a".repeat(82) to "github_" + "pat_" + "a".repeat(81)),
        "GITLAB_TOKEN" to ("glpat" + "-" + "a".repeat(20) to "glpat" + "-" + "a".repeat(19)),
        "NPM_TOKEN" to ("npm" + "_" + "a".repeat(36) to "npm" + "_" + "a".repeat(35)),
        "PYPI_TOKEN" to ("pypi-" + "AgEIcHlwaS5vcmc" + "a".repeat(50) to "pypi-" + "AgEIcHlwaS5vcmc" + "a".repeat(49)),
        "SENDGRID_API_KEY" to ("SG" + "." + "a".repeat(66) to "SG" + "." + "a".repeat(65)),
        "SHOPIFY_TOKEN" to ("shpat" + "_" + "a".repeat(32) to "shpat" + "_" + "a".repeat(31)),
        "DIGITALOCEAN_TOKEN" to ("dop_" + "v1_" + "a".repeat(64) to "dop_" + "v1_" + "a".repeat(63)),
        "DATABRICKS_TOKEN" to ("da" + "pi" + "a".repeat(32) to "da" + "pi" + "a".repeat(31)),
        "VAULT_TOKEN" to ("hvs" + "." + "a".repeat(90) to "hvs" + "." + "a".repeat(89)),
        "SLACK_WEBHOOK" to ("https://hooks.slack" + ".com/services/" + "A".repeat(43) to "https://hooks.slack" + ".com/services/" + "A".repeat(42)),
    )

    @Test
    fun theBuildAlwaysTellsTheTestsWhetherStressIsOn() {
        // `./gradlew test -Pstress` used to skip every stress test while staying green: the build never passed
        // the property on. Set to "true" or "false" on every run, never missing.
        val value = System.getProperty("scanner.stress")
        assertTrue("scanner.stress is '$value'", value == "true" || value == "false")
    }

    @Test
    fun allSixteenPortedSignaturesAreThere() {
        assertEquals(16, boundaries.size)
        // 22 formats through 0.2.0, ten more in 0.3.0, plus the name + entropy rule.
        assertEquals(32 + 1, SecretDetector.KINDS.size)
        assertTrue(SecretDetector.KINDS.containsAll(boundaries.keys))
    }

    @Test
    fun eachPortedSignatureDetectsItsShortestFormAndNotOneCharacterLess() {
        for ((k, pair) in boundaries) {
            assertEquals(k, k, kind(pair.first))
            assertEquals("$k inside a line", k, kind("token: \"" + pair.first + "\" # prod"))
            assertNull("$k one character short", kind(pair.second))
        }
    }

    @Test
    fun portedSignaturesNeedTheirExactPrefixAndBody() {
        assertNull(kind("SK-" + "proj-" + "A".repeat(40)))                  // prefix is case-sensitive
        assertEquals("OPENAI_API_KEY", kind("sk-" + "a".repeat(20) + "T3Blbk" + "FJ" + "b".repeat(20)))
        assertNull(kind("hf" + "_" + "a".repeat(33) + "1"))                   // Hugging Face bodies are letters only
        assertNull(kind("shpat" + "_" + "g".repeat(32)))                     // Shopify bodies are hex
        assertNull(kind("dop_" + "v1_" + "A".repeat(64)))                    // DigitalOcean: lowercase hex
        assertNull(kind("AI" + "za" + "a".repeat(36)))                        // Google: exactly 35, not 36
        assertNull(kind("glpat" + "-" + "a".repeat(21)))                      // GitLab: exactly 20
        assertNull(kind("SG" + "." + "a".repeat(67)))                         // SendGrid: exactly 66
        assertNull(kind("https://hooks.slack" + ".com/other/" + "A".repeat(43)))
        assertNull(kind("hvs" + "." + "a".repeat(89)))
    }

    @Test
    fun descriptionsNeverCarryMoreThanAShortPrefix() {
        for ((k, pair) in boundaries) {
            val description = SecretDetector.scanLiteral(pair.first)!!.description
            assertFalse("$k description leaks the body", description.contains(pair.first.take(12)))
        }
    }

    @Test(timeout = 10_000)
    fun adversarialRunsForEveryPortedPrefixStayLinear() {
        val prefixes = listOf("sk-proj-", "sk-", "sk-ant-api03-", "hf_", "api_org_", "gsk_", "pplx-", "AIza", "github_pat_", "glpat-",
            "npm_", "pypi-AgEIcHlwaS5vcmc", "SG.", "shpat_", "dop_v1_", "dapi", "hvs.", "hooks.slack.com/services/")
        for (p in prefixes) {
            // the prefix repeated, and the prefix followed by one long body that never ends the way the rule wants.
            // Only the time is checked: some repeated prefixes ARE a valid shape (`AIzaAIza...` is a Google key).
            SecretDetector.scanSignatures(p.repeat(200_000 / p.length))
            SecretDetector.scanSignatures(p + "a".repeat(200_000) + "_")
            SecretDetector.scanSignatures(p + "-".repeat(200_000))
        }
    }

    // ---- strict heuristic ------------------------------------------------------------------------------------

    @Test
    fun theLastWordOfTheKeyHasToBeTheCredentialNoun() {
        for (k in listOf("api_token", "client_secret", "DB_PASSWORD", "apiKey", "githubToken", "signing_key", "passphrase", "auth",
            "Authorization", "aws.credentials", "PRIVATE-KEY")) {
            assertEquals(k, "GENERIC_HIGH_ENTROPY", kind(Fake.GENERIC, k))
        }
        for (k in listOf("token_url", "secretName", "passwordPolicy", "token_endpoint", "secret_ref", "keyboard", "tokenizer", "author")) {
            assertNull(k, kind(Fake.GENERIC, k))
        }
    }

    @Test
    fun referencesAreNotSecrets() {
        for (v in listOf("\${PROD_TOKEN_123}", "\$PROD_TOKEN", "%PROD_TOKEN%", "{{ secrets.PROD_TOKEN }}", "<prod-token-here>",
            "env:PROD_TOKEN", "  \${A1b2C3d4E5f6}  ")) {
            assertNull(v, kind(v, "api_token"))
        }
    }

    @Test
    fun pathsUrlsSentencesAndSlugsAreNotSecrets() {
        for (v in listOf("/etc/secrets/Prod9Key", "./certs/Key9Prod.pem", "~/.ssh/id_Rsa9", "C:\\keys\\Prod9.key",
            "https://vault.example.com/v1/Key9", "two Words9 here", "authorization-code-grant", "GITHUB_TOKEN_NAME",
            "abcdefghijklmnop", "ABCDEFGHIJKLMNOP", "1234567890123456")) {
            assertNull(v, kind(v, "client_secret"))
        }
        // credentials inside a URL are a secret
        assertEquals("GENERIC_HIGH_ENTROPY", kind("postgres://app:Xk9mQ2pL8v@db:5432/app", "database_password"))
    }

    @Test
    fun theSlugLoopAgreesWithThePluginRegexOnEveryShortString() {
        val lower = Regex("""[a-z]+([_.-][a-z]+)+""")
        val upper = Regex("""[A-Z]+([_.-][A-Z]+)+""")
        val alphabet = listOf('a', 'b', 'Z', '_', '.', '-', '1')
        var checked = 0
        fun walk(prefix: String) {
            if (prefix.isNotEmpty()) {
                assertEquals("'$prefix'", lower.matches(prefix) || upper.matches(prefix), CredentialHeuristic.isSlug(prefix))
                checked++
            }
            if (prefix.length < 6) for (c in alphabet) walk(prefix + c)
        }
        walk("")
        assertTrue(checked > 100_000)
    }

    @Test(timeout = 10_000)
    fun aMegabyteDottedValueDoesNotOverflowTheStack() {
        // The plugin's `[a-z]+([_.-][a-z]+)+` recursed once per word: StackOverflowError at this size.
        assertTrue(CredentialHeuristic.isSlug("a." .repeat(500_000) + "a"))
        assertNull(kind("a.".repeat(500_000) + "Z9", "password"))
    }

    @Test
    fun authSchemesAndCommandLineFlagsAreUnwrapped() {
        assertEquals("GENERIC_HIGH_ENTROPY", kind("Bearer " + Fake.GENERIC, "Authorization"))
        assertNull(kind("Bearer \${TOKEN}", "Authorization"))
        // A reference behind an auth scheme or a flag is still a reference: only the unwrapped value shows it.
        // (Mutation found this was unchecked: `${...}` is also a placeholder, so these use `%VAR%`.)
        assertNull(kind("Bearer %PROD_API_TOKEN_2024%", "Authorization"))
        assertNull(kind("--api-key=%API_KEY_2024%", "args"))
        assertEquals("GENERIC_HIGH_ENTROPY", kind("Bearer PROD_API_TOKEN_2024%x", "Authorization"))
        assertEquals("GENERIC_HIGH_ENTROPY", kind("--api-key=" + Fake.GENERIC, "args"))
        assertNull(kind("--output=" + Fake.GENERIC, "args"))
    }

    @Test
    fun theHeuristicCanBeTurnedOffButSignaturesStay() {
        assertNull(kind(Fake.GENERIC, "api_token", heuristic = false))
        assertEquals("GITHUB_TOKEN", kind(Fake.GITHUB, "api_token", heuristic = false))
    }

    @Test
    fun templateAndGeneratedFilesAreRecognized() {
        for (n in listOf(".env.example", "config.sample", "app.template", "settings.dist", "a.tpl", "b.tmpl", "config.example.yml",
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "PACKAGE-LOCK.JSON")) {
            assertTrue(n, CredentialHeuristic.isTemplateOrGeneratedFile(n))
        }
        for (n in listOf(".env", "config.yml", "examples.kt", "sampler.py", "distance.go", "lock.json")) {
            assertFalse(n, CredentialHeuristic.isTemplateOrGeneratedFile(n))
        }
    }

    // ---- through the scanner --------------------------------------------------------------------------------

    private lateinit var root: File

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "ported-").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    private fun write(name: String, text: String) = File(root, name).also { it.parentFile.mkdirs(); it.writeText(text) }

    @Test
    fun dotEnvValuesWithACommentOrQuotesAreRead() {
        write(".env", "API_TOKEN=${Fake.GENERIC} # prod\nDB_PASSWORD='${Fake.GENERIC}'\nexport SIGNING_KEY=\"${Fake.GENERIC}\"\nNAME=service # ok\n")
        val hits = Scanner.scan(root)
        assertEquals(listOf(1, 2, 3), hits.map { it.line })
        assertEquals(listOf(11, 14, 21), hits.map { it.column })
    }

    @Test
    fun aTemplateFileKeepsItsSignaturesButNotTheHeuristic() {
        write("app.sample.yml", "api_token: \"${Fake.GENERIC}\"\nother: \"${Fake.GITHUB}\"\n")
        assertEquals(listOf("GITHUB_TOKEN"), Scanner.scan(root).map { it.kind })
    }

    @Test
    fun aSentenceOrSlugAssignedToACredentialKeyIsNotReported() {
        write("a.yml", "token: refresh-token-grant\npassword: please set this in the vault\nsecret: \${SECRET}\n")
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun aPortedSignatureIsFoundAnywhereOnALine() {
        write("ci.sh", "curl -H \"x-api-key: " + "gsk" + "_" + "a".repeat(52) + "\" https://api\n")
        assertEquals(listOf("GROQ_API_KEY"), Scanner.scan(root).map { it.kind })
    }

    // ---- SARIF uri base ---------------------------------------------------------------------------------------

    @Test
    fun sarifUrisAreRelativeToTheWorkingDirectoryWhenTheRootIsInsideIt() {
        val src = File(root, "src").also { it.mkdirs() }
        val file = write("src/deep/A.kt", "x")
        assertEquals("", sarifUriPrefix(root, root))
        assertEquals("src/", sarifUriPrefix(src, root))
        assertEquals("src/deep/", sarifUriPrefix(file, root))
        assertEquals("src/", sarifUriPrefix(File(root, "src/../src"), root))
        // outside the working directory: relative to the root, never an absolute path
        assertEquals("", sarifUriPrefix(root, src))
        assertEquals("", sarifUriPrefix(createTempDirectory(prefix = "elsewhere-").toFile().also { it.deleteOnExit() }, root))
        val sarif = renderSarif(listOf(ScanHit("deep/A.kt", 1, 1, "GITHUB_TOKEN", "d")), "src/")
        assertEquals(listOf("src/deep/A.kt"), sarifUris(sarif))
    }

    @Test
    fun everyKindHasARuleDescriptionOfItsOwn() {
        val sarif = renderSarif(SecretDetector.KINDS.map { ScanHit("a.kt", 1, 1, it, "d") })
        for (k in SecretDetector.KINDS) assertFalse("$k has no rule description", sarif.contains("\"text\": \"$k\""))
    }
}
