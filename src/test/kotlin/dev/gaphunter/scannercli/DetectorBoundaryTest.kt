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
 * Boundary and negative cases for every detector: the shortest value that
 * matches, one character shorter (must not match), a wrong prefix, the value
 * inside a comment, an already-masked value, and the guarantee that no output
 * format ever carries a complete secret.
 */
class DetectorBoundaryTest {

    private fun kind(value: String, hint: String? = null) = SecretDetector.scanLiteral(value, hint)?.kind

    // ---- AWS: AKIA/ASIA + exactly 16 of [0-9A-Z] ----

    @Test
    fun awsShortestMatchesAndOneShorterDoesNot() {
        assertEquals("AWS_ACCESS_KEY", kind("AKIA" + "A".repeat(16)))
        assertEquals("AWS_ACCESS_KEY", kind("ASIA" + "7".repeat(16)))
        assertNull(kind("AKIA" + "A".repeat(15)))
        // 17 is one too many: the trailing \b can't sit inside the run.
        assertNull(kind("AKIA" + "A".repeat(17)))
    }

    @Test
    fun awsWrongPrefixOrCaseDoesNotMatch() {
        assertNull(kind("AKIB" + "A".repeat(16)))
        assertNull(kind("akia" + "A".repeat(16)))
        assertNull(kind("AKIA" + "a".repeat(16)))
        assertNull(kind("XAKIA" + "A".repeat(16)))
    }

    // ---- GitHub: gh[pousr]_ + 36 or more of [A-Za-z0-9] ----

    @Test
    fun githubShortestMatchesAndOneShorterDoesNot() {
        for (p in listOf("ghp_", "gho_", "ghu_", "ghs_", "ghr_")) {
            assertEquals(p, "GITHUB_TOKEN", kind(p + "Z".repeat(36)))
            assertNull(p, kind(p + "Z".repeat(35)))
        }
        assertEquals("GITHUB_TOKEN", kind("ghp_" + "Z".repeat(200)))
    }

    @Test
    fun githubWrongPrefixDoesNotMatch() {
        assertNull(kind("ghx_" + "Z".repeat(36)))
        assertNull(kind("ghp-" + "Z".repeat(36)))
        assertNull(kind("GHP_" + "Z".repeat(36)))
        // Fine-grained github_pat_ tokens have their own rule since the port of the plugin's signatures.
        assertEquals("GITHUB_FINE_GRAINED_TOKEN", kind("github_pat_" + "Z".repeat(82)))
    }

    // ---- Slack: xox[baprs]- + 10 or more of [0-9A-Za-z-] ----

    @Test
    fun slackShortestMatchesAndOneShorterDoesNot() {
        for (p in listOf("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")) {
            assertEquals(p, "SLACK_TOKEN", kind(p + "1".repeat(10)))
            assertNull(p, kind(p + "1".repeat(9)))
        }
    }

    @Test
    fun slackWrongPrefixDoesNotMatch() {
        assertNull(kind("xoxz-" + "1".repeat(10)))
        assertNull(kind("xoxb_" + "1".repeat(10)))
    }

    // ---- JWT: eyJ + 5 . 5 . 5 base64url ----

    @Test
    fun jwtShortestMatchesAndOneShorterDoesNot() {
        assertEquals("JWT", kind("eyJ" + "aaaaa" + ".bbbbb" + ".ccccc"))
        assertNull(kind("eyJ" + "aaaa" + ".bbbbb" + ".ccccc"))
        assertNull(kind("eyJ" + "aaaaa" + ".bbbb" + ".ccccc"))
        assertNull(kind("eyJ" + "aaaaa" + ".bbbbb" + ".cccc"))
        assertNull(kind("eyJ" + "aaaaa" + ".bbbbb"))
    }

    @Test
    fun jwtWrongPrefixDoesNotMatch() {
        assertNull(kind("eyK" + "aaaaa.bbbbb.ccccc"))
        assertNull(kind("EYJ" + "aaaaa.bbbbb.ccccc"))
    }

    @Test
    fun jwtStartBoundary() {
        // Unchanged by the ReDoS fix: start of string, after space, quote, '=', ':' or '.'.
        for (before in listOf("", " ", "\"", "=", ":", ".", "/", "Bearer ")) {
            assertEquals("prefix '$before'", "JWT", kind(before + Fake.JWT))
        }
        // Still not a start inside a word (also true before the fix: \b).
        assertNull(kind("x" + Fake.JWT))
        assertNull(kind("_" + Fake.JWT))
        // The one behaviour change of the fix, pinned on purpose: glued to '-' it is no longer reported.
        assertNull(kind("x-" + Fake.JWT))
    }

    // ---- PEM header ----

    @Test
    fun pemEveryAcceptedHeaderMatches() {
        for (t in listOf("", "RSA ", "EC ", "OPENSSH ", "DSA ", "ENCRYPTED ")) {
            assertEquals(t, "PRIVATE_KEY", kind("-----BEGIN " + t + "PRIVATE KEY-----"))
        }
    }

    @Test
    fun pemNearMissesDoNotMatch() {
        assertNull(kind("----BEGIN " + "PRIVATE KEY-----"))
        assertNull(kind("-----BEGIN " + "PUBLIC KEY-----"))
        assertNull(kind("-----BEGIN " + "CERTIFICATE-----"))
        assertNull(kind("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"))
        assertNull(kind("-----BEGIN " + "rsa PRIVATE KEY-----"))
    }

    // ---- Stripe: [sr]k_(live|test)_ + 20 or more ----

    @Test
    fun stripeShortestMatchesAndOneShorterDoesNot() {
        for (p in listOf("sk_live_", "sk_test_", "rk_live_", "rk_test_")) {
            assertEquals(p, "STRIPE_KEY", kind(p + "Q".repeat(20)))
            assertNull(p, kind(p + "Q".repeat(19)))
        }
    }

    @Test
    fun stripeWrongPrefixDoesNotMatch() {
        assertNull(kind("pk_live_" + "Q".repeat(20))) // publishable key: public by design
        assertNull(kind("sk_prod_" + "Q".repeat(20)))
        assertNull(kind("SK_LIVE_" + "Q".repeat(20)))
    }

    // ---- GENERIC_HIGH_ENTROPY: secret-like name, length >= 12, not a placeholder, >= 3.3 bits/char ----

    @Test
    fun genericLengthBoundary() {
        // 12 distinct characters: log2(12) = 3.58 bits/char, over the 3.3 threshold.
        assertEquals("GENERIC_HIGH_ENTROPY", kind("aB3dE5gH7jK9", "apiKey"))
        assertNull(kind("aB3dE5gH7jK", "apiKey"))
    }

    @Test
    fun genericEntropyBoundary() {
        // 12 characters, 11 distinct (one repeated): about 3.42 bits/char, above 3.3.
        // 12 characters, 10 distinct (two repeated): about 3.25 bits/char, below.
        // Mixed case on purpose: the strict heuristic wants two character classes,
        // so an all-lowercase value would be refused before the entropy is read.
        val above = "aBcdefghijka"
        val below = "aBcdefghijaB"
        assertTrue(SecretDetector.shannonEntropyBitsPerChar(above) >= 3.3)
        assertTrue(SecretDetector.shannonEntropyBitsPerChar(below) < 3.3)
        assertEquals("GENERIC_HIGH_ENTROPY", kind(above, "secret"))
        assertNull(kind(below, "secret"))
    }

    @Test
    fun genericNeedsASecretLikeName() {
        for (name in listOf("apiKey", "api_key", "API-KEY", "secret", "clientSecret", "token", "password", "passwd", "pwd", "accessKey", "private_key")) {
            assertEquals(name, "GENERIC_HIGH_ENTROPY", kind(Fake.GENERIC, name))
        }
        for (name in listOf("name", "url", "host", "", "keyboard")) {
            assertNull(name, kind(Fake.GENERIC, name))
        }
        assertNull(kind(Fake.GENERIC, null))
    }

    @Test
    fun genericPlaceholdersAreIgnored() {
        for (v in listOf("changeme", "your_api_key_here", "<insert-token-here>", "\${API_TOKEN_FROM_ENV}", "xxxxxxxxxxxxxxxx", "placeholder")) {
            assertNull(v, kind(v, "api_key"))
        }
    }

    @Test
    fun knownGapPlaceholderWithMyPrefixIsStillFlagged() {
        // Documented gap, pinned so a fix shows up as a deliberate test change: `my_` is not a placeholder prefix.
        assertEquals("GENERIC_HIGH_ENTROPY", kind("my_api_key_12345", "api_key"))
    }

    // ---- masked values ----

    @Test
    fun valuesMaskedWithAsterisksAreNotReported() {
        assertNull(kind("*".repeat(24), "password"))
        assertNull(kind("ghp_" + "*".repeat(36)))
        assertNull(kind("AKIA" + "*".repeat(16)))
        assertNull(kind("sk_live_" + "*".repeat(24)))
    }

    @Test
    fun knownGapValuesMaskedWithXStillMatchTheFormatRules() {
        // Documented false positive, pinned: a redaction like ghp_XXXX... still has the token's exact shape.
        assertEquals("GITHUB_TOKEN", kind("ghp_" + "X".repeat(36)))
        assertEquals("STRIPE_KEY", kind("sk_live_" + "X".repeat(24)))
        assertEquals("AWS_ACCESS_KEY", kind("AKIA" + "X".repeat(16)))
    }

    // ---- through the file scanner: comments, CRLF, no full secret in any output ----

    private lateinit var root: File

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "boundary-test-").toFile()
    }

    @After
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun aSecretInsideACommentIsStillReported() {
        // Deliberate: a secret in a comment is still a leaked secret.
        File(root, "a.kt").writeText("// old token: ${Fake.GITHUB}\n/* key = \"${Fake.AWS}\" */\n# ${Fake.STRIPE}\n")
        val kinds = Scanner.scan(root).map { it.kind }
        assertEquals(listOf("GITHUB_TOKEN", "AWS_ACCESS_KEY", "STRIPE_KEY"), kinds)
    }

    @Test
    fun everyDetectorIsFoundByTheFileScanner() {
        Fake.BY_KIND.entries.forEachIndexed { n, (kind, lineAndSecret) ->
            File(root, "f$n.yaml").writeText(lineAndSecret.first + "\n")
        }
        val found = Scanner.scan(root).sortedBy { it.file }.map { it.kind }
        assertEquals(Fake.BY_KIND.keys.toList(), found)
    }

    @Test
    fun noOutputFormatEverContainsACompleteSecret() {
        Fake.BY_KIND.entries.forEachIndexed { n, (_, lineAndSecret) ->
            File(root, "f$n.yaml").writeText(lineAndSecret.first + "\n")
        }
        val hits = Scanner.scan(root)
        assertEquals(Fake.BY_KIND.size, hits.size)
        val text = renderText(hits, root)
        val sarif = renderSarif(hits)
        for ((kind, lineAndSecret) in Fake.BY_KIND) {
            val secret = lineAndSecret.second
            // PRIVATE_KEY's "secret" is only the header line; the key body is what matters and it is never read into output.
            if (kind == "PRIVATE_KEY") continue
            assertFalse("$kind: full secret in text output", text.contains(secret))
            assertFalse("$kind: full secret in SARIF output", sarif.contains(secret))
            // At most the first 11 characters (the Stripe prefix plus 3) ever appear.
            for (len in 12..secret.length) {
                val head = secret.take(len)
                assertFalse("$kind: $len leading characters in text output", text.contains(head))
                assertFalse("$kind: $len leading characters in SARIF output", sarif.contains(head))
            }
        }
    }

    @Test
    fun theTruncatedPrefixesAreExactlyWhatTheDescriptionsPromise() {
        assertEquals("Looks like an AWS access key ID (AKIAIOSF...)", SecretDetector.scanLiteral(Fake.AWS)!!.description)
        assertEquals(
            "Looks like a Stripe secret/restricted API key (sk_live_4eC...)",
            SecretDetector.scanLiteral(Fake.STRIPE)!!.description,
        )
        val generic = SecretDetector.scanLiteral(Fake.GENERIC, "db.password")!!.description
        assertFalse(generic.contains(Fake.GENERIC.take(4)))
    }

    @Test
    fun crlfAndLfGiveTheSameLinesAndColumns() {
        val body = listOf("// one", "val gh = \"${Fake.GITHUB}\"", "x = 1", "db.password=${Fake.GENERIC}")
        File(root, "lf.kt").writeText(body.joinToString("\n") + "\n")
        File(root, "crlf.kt").writeText(body.joinToString("\r\n") + "\r\n")
        File(root, "cr.kt").writeText(body.joinToString("\r") + "\r")
        val byFile = Scanner.scan(root).groupBy({ it.file }, { Triple(it.line, it.column, it.kind) })
        assertEquals(byFile["lf.kt"], byFile["crlf.kt"])
        assertEquals(byFile["lf.kt"], byFile["cr.kt"])
        assertEquals(listOf(Triple(2, 11, "GITHUB_TOKEN"), Triple(4, 13, "GENERIC_HIGH_ENTROPY")), byFile["lf.kt"])
    }

    @Test
    fun aCrlfLineEndingNeverLeaksIntoTheUnquotedValue() {
        // The unquoted rule takes the rest of the line; a stray \r must not become part of the value or key.
        File(root, ".env").writeText("API_TOKEN=${Fake.GENERIC}\r\n")
        val hits = Scanner.scan(root)
        assertEquals(1, hits.size)
        assertFalse(hits[0].description.contains("\r"))
    }
}
