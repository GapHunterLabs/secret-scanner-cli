package dev.gaphunter.scannercli

data class SecretFinding(val kind: String, val description: String)

/**
 * Pure text-based secret detection, kept in step by hand with
 * api-security-companion's `detect/SecretDetector.kt` (the two projects build
 * independently: one is an IntelliJ plugin, this one a standalone JVM app).
 *
 * Two parts, on purpose:
 *  - [SIGNATURES]: credential formats with a distinctive prefix and a
 *    fixed-shape body, so a match is a finding on its own.
 *  - The name + entropy heuristic ([CredentialHeuristic]) for "some secret
 *    assigned to a credential-named key", which no fixed format covers. It
 *    is the strict version the plugin uses for configuration files: the
 *    key's last word has to be the credential noun, and references, paths,
 *    URLs without credentials and slugs are not secrets.
 *
 * Where this copy differs from the plugin, deliberately:
 *  - JWT starts only where the previous character is not a base64url
 *    character (the plugin uses `\b`). With `\b`, a long run like
 *    `-eyJ-eyJ-eyJ...` with no `.` gave one start per `eyJ`, and each start
 *    scanned to the end of the run before failing: quadratic, measured at
 *    about 2.3 s for a 20,000-character line. Only difference in what
 *    matches: a JWT glued to a preceding `-` (`x-eyJ...`) is not reported.
 *
 * Bodies are only ever shown as a short prefix in a description, never in full.
 */
object SecretDetector {

    /**
     * [literals]: text every match must contain (one of them). Checked with a plain
     * `contains` before the regex runs: none of these regexes can skip ahead on its
     * own (each starts with `` or a lookbehind), so with 22 rules every line paid
     * 22 full regex passes, measured at 835 ms for a 1 MB line. The check only skips
     * a regex that could not match, so what is detected does not change.
     */
    private class Signature(val kind: String, val literals: List<String>, val regex: Regex, val describe: (String) -> String)

    const val GENERIC_KIND = "GENERIC_HIGH_ENTROPY"

    private val SIGNATURES: List<Signature> = listOf(
        Signature("AWS_ACCESS_KEY", listOf("AKIA", "ASIA"), Regex("""\b(AKIA|ASIA)[0-9A-Z]{16}\b""")) {
            "Looks like an AWS access key ID (${it.take(8)}...)"
        },
        Signature("GITHUB_TOKEN", listOf("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), Regex("""\bgh[pousr]_[A-Za-z0-9]{36,}\b""")) {
            "Looks like a GitHub personal access token"
        },
        Signature("SLACK_TOKEN", listOf("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"), Regex("""\bxox[baprs]-[0-9A-Za-z-]{10,}\b""")) {
            "Looks like a Slack API token"
        },
        Signature("JWT", listOf("eyJ"), Regex("""(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b""")) {
            "Looks like a JWT (base64url header.payload.signature)"
        },
        Signature("PRIVATE_KEY", listOf("-----BEGIN "), Regex("""-----BEGIN ((RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY-----""")) {
            "Contains a PEM private key block"
        },
        // Stripe secret/restricted API keys, live and test: a hardcoded test key
        // still leaks real account structure.
        Signature("STRIPE_KEY", listOf("k_live_", "k_test_"), Regex("""\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b""")) {
            "Looks like a Stripe secret/restricted API key (${it.take(11)}...)"
        },

        // --- AI services ---
        // sk-proj-/sk-svcacct-/sk-admin- keys, plus the older sk-...T3BlbkFJ...
        // shape ("T3BlbkFJ" is base64 for "OpenAI").
        Signature(
            "OPENAI_API_KEY", listOf("sk-"),
            Regex("""\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"""),
        ) { "Looks like an OpenAI API key (${it.take(8)}...)" },
        Signature("ANTHROPIC_API_KEY", listOf("sk-ant-"), Regex("""\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}""")) {
            "Looks like an Anthropic API key (${it.take(10)}...)"
        },
        // hf_ user tokens and api_org_ organization tokens: 34 letters, no digits.
        Signature("HUGGINGFACE_TOKEN", listOf("hf_", "api_org_"), Regex("""\b(?:hf|api_org)_[A-Za-z]{34}\b""")) {
            "Looks like a Hugging Face access token"
        },
        Signature("GROQ_API_KEY", listOf("gsk_"), Regex("""\bgsk_[A-Za-z0-9]{52}\b""")) { "Looks like a Groq API key" },
        Signature("PERPLEXITY_API_KEY", listOf("pplx-"), Regex("""\bpplx-[A-Za-z0-9]{48}\b""")) { "Looks like a Perplexity API key" },
        // Firebase web keys share this shape and are meant to be public
        // (restricted by referrer/app), so the message says to check.
        Signature("GOOGLE_API_KEY", listOf("AIza"), Regex("""\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])""")) {
            "Looks like a Google API key (${it.take(8)}...): fine if it's a restricted Firebase web key, a leak if not"
        },

        // --- developer platforms and cloud services ---
        Signature("GITHUB_FINE_GRAINED_TOKEN", listOf("github_pat_"), Regex("""\bgithub_pat_\w{82}\b""")) {
            "Looks like a GitHub fine-grained personal access token"
        },
        Signature("GITLAB_TOKEN", listOf("glpat-"), Regex("""\bglpat-[\w-]{20}(?![\w-])""")) { "Looks like a GitLab personal access token" },
        Signature("NPM_TOKEN", listOf("npm_"), Regex("""\bnpm_[A-Za-z0-9]{36}\b""")) { "Looks like an npm access token" },
        Signature("PYPI_TOKEN", listOf("pypi-AgEIcHlwaS5vcmc"), Regex("""\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}""")) { "Looks like a PyPI upload token" },
        Signature("SENDGRID_API_KEY", listOf("SG."), Regex("""\bSG\.[A-Za-z0-9=_.-]{66}(?![A-Za-z0-9=_.-])""")) { "Looks like a SendGrid API key" },
        Signature("SHOPIFY_TOKEN", listOf("shpat_", "shpca_", "shppa_", "shpss_"), Regex("""\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}\b""")) {
            "Looks like a Shopify access token"
        },
        Signature("DIGITALOCEAN_TOKEN", listOf("dop_v1_"), Regex("""\bdop_v1_[a-f0-9]{64}\b""")) {
            "Looks like a DigitalOcean personal access token"
        },
        Signature("DATABRICKS_TOKEN", listOf("dapi"), Regex("""\bdapi[a-f0-9]{32}(?:-\d)?\b""")) { "Looks like a Databricks access token" },
        Signature("VAULT_TOKEN", listOf("hvs."), Regex("""\bhvs\.[\w-]{90,120}""")) { "Looks like a HashiCorp Vault service token" },
        Signature(
            "SLACK_WEBHOOK", listOf("hooks.slack.com/"),
            Regex("""hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"""),
        ) { "Contains a Slack incoming-webhook URL (anyone with it can post to the channel)" },
    )

    /** Every rule id this detector can report, in a fixed order. */
    val KINDS: List<String> = SIGNATURES.map { it.kind } + GENERIC_KIND

    private const val MIN_ENTROPY_LENGTH = 12
    private const val MIN_ENTROPY_BITS_PER_CHAR = 3.3

    private val OBVIOUS_PLACEHOLDER = Regex(
        """^(|changeme|change[_-]?me|todo|fixme|xxx+|your[_-].*|placeholder|example|test|dummy|<.*>|\$\{.*})$""",
        RegexOption.IGNORE_CASE,
    )

    /** Only the exact-format signatures: no name hint, no entropy guess. */
    fun scanSignatures(value: String): SecretFinding? {
        for (signature in SIGNATURES) {
            if (signature.literals.none { value.contains(it) }) continue
            val match = signature.regex.find(value) ?: continue
            return SecretFinding(signature.kind, signature.describe(match.value))
        }
        return null
    }

    /**
     * Signatures first; then, when [heuristic] is on and a key is known, the
     * strict name + entropy check. [heuristic] is off in template and generated
     * files (`.example`, lockfiles), where values are placeholders or hashes by
     * design; exact formats are still reported there.
     */
    fun scanLiteral(value: String, variableNameHint: String? = null, heuristic: Boolean = true): SecretFinding? {
        scanSignatures(value)?.let { return it }
        if (!heuristic || variableNameHint == null) return null
        val name = CredentialHeuristic.credentialName(variableNameHint, value) ?: return null
        return SecretFinding(
            GENERIC_KIND,
            "Assigned to '$name' and looks like a real credential, not a placeholder or a reference",
        )
    }

    fun looksLikeARealSecret(value: String): Boolean {
        if (value.length < MIN_ENTROPY_LENGTH) return false
        if (OBVIOUS_PLACEHOLDER.matches(value.trim())) return false
        if (value.toSet().size <= 2) return false
        return shannonEntropyBitsPerChar(value) >= MIN_ENTROPY_BITS_PER_CHAR
    }

    fun shannonEntropyBitsPerChar(value: String): Double {
        if (value.isEmpty()) return 0.0
        val counts = value.groupingBy { it }.eachCount()
        val length = value.length.toDouble()
        return -counts.values.sumOf { count ->
            val p = count / length
            p * (Math.log(p) / Math.log(2.0))
        }
    }
}
