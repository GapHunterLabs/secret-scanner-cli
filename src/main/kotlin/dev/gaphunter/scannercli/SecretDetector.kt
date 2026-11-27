package dev.gaphunter.scannercli

/**
 * What a detector found. [start]/[end] are offsets of the secret inside the text
 * that was searched, [value] is the secret itself: renderers never print it,
 * they print a masked view (see [Mask]).
 */
data class SecretFinding(
    val kind: String,
    val description: String,
    val severity: Severity = Severity.HIGH,
    val start: Int = 0,
    val end: Int = 0,
    val value: String = "",
)

enum class Severity(val label: String, val sarifLevel: String, val securitySeverity: String) {
    MEDIUM("medium", "warning", "5.0"),
    HIGH("high", "error", "8.0");

    companion object {
        fun parse(label: String): Severity? = entries.firstOrNull { it.label == label }
    }
}

/**
 * Pure text-based secret detection, kept in step by hand with
 * api-security-companion's `detect/SecretDetector.kt` (the two projects build
 * independently: one is an IntelliJ plugin, this one a standalone JVM app).
 *
 * Two parts, on purpose:
 *  - [SIGNATURES]: credential formats with a distinctive prefix and a
 *    fixed-shape body, so a match is a finding on its own.
 *  - The name + entropy heuristic ([CredentialHeuristic]) for "some secret
 *    assigned to a credential-named key", which no fixed format covers.
 *
 * Where this copy differs from the plugin, deliberately:
 *  - JWT starts only where the previous character is not a base64url
 *    character (the plugin uses `\b`), which keeps a long `-eyJ-eyJ...` run
 *    linear. A JWT glued to a preceding `-` (`x-eyJ...`) is not reported.
 *  - Since 0.3.0: a body made only of redaction characters (`ghp_XXXX...`) and
 *    the AWS documentation example key are not reported, and ten more formats.
 *
 * Several shapes added in 0.3.0 are the ones in gitleaks' rule set (MIT, Zachary
 * Rice), read from its `config/gitleaks.toml` on 2026-11-27: Atlassian, Doppler,
 * age, Linear, Postman, Grafana service accounts, Square `sq0atp-`, and the
 * general PEM header. The others follow the format's own specification: PuTTY's
 * key file header, Azure Storage's 64-byte account key in a connection string,
 * and bcrypt's `$2a$NN$` + 53 characters.
 */
object SecretDetector {

    /**
     * [literals]: text every match must contain (one of them), checked with a plain
     * `contains` before the regex runs, so a line pays only for the rules that could match.
     */
    private class Signature(
        val kind: String,
        val literals: List<String>,
        val regex: Regex,
        val severity: Severity = Severity.HIGH,
        val description: String,
    )

    const val GENERIC_KIND = "GENERIC_HIGH_ENTROPY"

    private val SIGNATURES: List<Signature> = listOf(
        Signature("AWS_ACCESS_KEY", listOf("AKIA", "ASIA"), Regex("""\b(AKIA|ASIA)[0-9A-Z]{16}\b"""), description = "Looks like an AWS access key ID"),
        Signature("GITHUB_TOKEN", listOf("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), Regex("""\bgh[pousr]_[A-Za-z0-9]{36,}\b"""),
            description = "Looks like a GitHub personal access token"),
        Signature("SLACK_TOKEN", listOf("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"), Regex("""\bxox[baprs]-[0-9A-Za-z-]{10,}\b"""),
            description = "Looks like a Slack API token"),
        Signature("JWT", listOf("eyJ"), Regex("""(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"""),
            description = "Looks like a JWT (base64url header.payload.signature)"),
        // Any PEM or PGP private key header: RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8 and `PGP PRIVATE KEY BLOCK`.
        Signature("PRIVATE_KEY", listOf("-----BEGIN"), Regex("""-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"""),
            description = "Contains a private key block (PEM or PGP)"),
        Signature("STRIPE_KEY", listOf("k_live_", "k_test_"), Regex("""\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b"""),
            description = "Looks like a Stripe secret/restricted API key"),

        // --- AI services ---
        Signature(
            "OPENAI_API_KEY", listOf("sk-"),
            Regex("""\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"""),
            description = "Looks like an OpenAI API key",
        ),
        Signature("ANTHROPIC_API_KEY", listOf("sk-ant-"), Regex("""\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{80,}"""),
            description = "Looks like an Anthropic API key"),
        Signature("HUGGINGFACE_TOKEN", listOf("hf_", "api_org_"), Regex("""\b(?:hf|api_org)_[A-Za-z]{34}\b"""),
            description = "Looks like a Hugging Face access token"),
        Signature("GROQ_API_KEY", listOf("gsk_"), Regex("""\bgsk_[A-Za-z0-9]{52}\b"""), description = "Looks like a Groq API key"),
        Signature("PERPLEXITY_API_KEY", listOf("pplx-"), Regex("""\bpplx-[A-Za-z0-9]{48}\b"""), description = "Looks like a Perplexity API key"),
        // Firebase web keys share this shape and are meant to be public (restricted by referrer/app): medium.
        Signature("GOOGLE_API_KEY", listOf("AIza"), Regex("""\bAIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"""), Severity.MEDIUM,
            "Looks like a Google API key: fine if it's a restricted Firebase web key, a leak if not"),

        // --- developer platforms and cloud services ---
        Signature("GITHUB_FINE_GRAINED_TOKEN", listOf("github_pat_"), Regex("""\bgithub_pat_\w{82}\b"""),
            description = "Looks like a GitHub fine-grained personal access token"),
        Signature("GITLAB_TOKEN", listOf("glpat-"), Regex("""\bglpat-[\w-]{20}(?![\w-])"""), description = "Looks like a GitLab personal access token"),
        Signature("NPM_TOKEN", listOf("npm_"), Regex("""\bnpm_[A-Za-z0-9]{36}\b"""), description = "Looks like an npm access token"),
        Signature("PYPI_TOKEN", listOf("pypi-AgEIcHlwaS5vcmc"), Regex("""\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}"""), description = "Looks like a PyPI upload token"),
        Signature("SENDGRID_API_KEY", listOf("SG."), Regex("""\bSG\.[A-Za-z0-9=_.-]{66}(?![A-Za-z0-9=_.-])"""), description = "Looks like a SendGrid API key"),
        Signature("SHOPIFY_TOKEN", listOf("shpat_", "shpca_", "shppa_", "shpss_"), Regex("""\bshp(?:at|ca|pa|ss)_[A-Fa-f0-9]{32}\b"""),
            description = "Looks like a Shopify access token"),
        Signature("DIGITALOCEAN_TOKEN", listOf("dop_v1_"), Regex("""\bdop_v1_[a-f0-9]{64}\b"""), description = "Looks like a DigitalOcean personal access token"),
        Signature("DATABRICKS_TOKEN", listOf("dapi"), Regex("""\bdapi[a-f0-9]{32}(?:-\d)?\b"""), description = "Looks like a Databricks access token"),
        Signature("VAULT_TOKEN", listOf("hvs."), Regex("""\bhvs\.[\w-]{90,120}"""), description = "Looks like a HashiCorp Vault service token"),
        Signature(
            "SLACK_WEBHOOK", listOf("hooks.slack.com/"),
            Regex("""hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"""),
            description = "Contains a Slack incoming-webhook URL (anyone with it can post to the channel)",
        ),

        // --- added in 0.3.0 ---
        Signature("ATLASSIAN_API_TOKEN", listOf("ATATT3"), Regex("""\bATATT3[A-Za-z0-9_\-=]{186}(?![A-Za-z0-9_\-=])"""),
            description = "Looks like an Atlassian API token"),
        Signature("DOPPLER_TOKEN", listOf("dp.pt."), Regex("""\bdp\.pt\.[A-Za-z0-9]{43}(?![A-Za-z0-9])"""), description = "Looks like a Doppler personal token"),
        Signature("AGE_SECRET_KEY", listOf("AGE-SECRET-KEY-1"), Regex("""\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}(?![A-Z0-9])"""),
            description = "Contains an age encryption secret key"),
        Signature("LINEAR_API_KEY", listOf("lin_api_"), Regex("""\blin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9])"""), description = "Looks like a Linear API key"),
        Signature("POSTMAN_API_KEY", listOf("PMAK-"), Regex("""\bPMAK-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{34}(?![A-Fa-f0-9])"""),
            description = "Looks like a Postman API key"),
        Signature("GRAFANA_SERVICE_ACCOUNT_TOKEN", listOf("glsa_"), Regex("""\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?![A-Za-z0-9_])"""),
            description = "Looks like a Grafana service account token"),
        Signature("SQUARE_ACCESS_TOKEN", listOf("sq0atp-"), Regex("""\bsq0atp-[\w-]{22,60}(?![\w-])"""), description = "Looks like a Square access token"),
        Signature("PUTTY_PRIVATE_KEY", listOf("PuTTY-User-Key-File-"), Regex("""PuTTY-User-Key-File-[23]:[ \t]*[A-Za-z0-9@.-]+"""),
            description = "Contains a PuTTY private key file"),
        Signature("AZURE_STORAGE_KEY", listOf("AccountKey="), Regex("""AccountKey=[A-Za-z0-9+/]{86}=="""),
            description = "Contains an Azure Storage account key in a connection string"),
        Signature("BCRYPT_HASH", listOf("$2"), Regex("""\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}(?![./A-Za-z0-9])"""), Severity.MEDIUM,
            "Contains a bcrypt password hash (crackable offline if the password is weak)"),
    )

    /** Every rule id this detector can report, in a fixed order. */
    val KINDS: List<String> = SIGNATURES.map { it.kind } + GENERIC_KIND

    /** What each rule finds and how serious it is, for SARIF rule metadata and `--fail-on`. */
    val RULES: Map<String, Pair<String, Severity>> =
        SIGNATURES.associate { it.kind to (it.description to it.severity) } +
            (GENERIC_KIND to ("High-entropy value assigned to a credential-like variable name" to Severity.MEDIUM))

    private const val MIN_ENTROPY_LENGTH = 12
    private const val MIN_ENTROPY_BITS_PER_CHAR = 3.3

    private val OBVIOUS_PLACEHOLDER = Regex(
        """^(|changeme|change[_-]?me|replace[_-]?me|todo|fixme|xxx+|your[_-].*|placeholder|example|test|dummy|<.*>|\$\{.*})$""",
        RegexOption.IGNORE_CASE,
    )

    /** Characters people use to redact a token by hand (`ghp_XXXX...`, `sk-proj-****...`). */
    private const val REDACTION = "Xx*#.-_0"

    /** The body of [match] after the literal that triggered [signature] (`sk_live_` keeps `live_...` out of it). */
    private fun body(signature: Signature, match: String): String {
        for (lit in signature.literals) {
            val at = match.indexOf(lit)
            if (at >= 0) return match.substring(at + lit.length)
        }
        return match
    }

    /**
     * A redacted example, not a leak: at least 90 % of the body is redaction characters
     * (`sk-proj-` + 48 `X` qualifies; a real token never comes close), or it is AWS's own
     * documentation example key, which ends in `EXAMPLE` (`AKIAIOSFODNN7EXAMPLE`).
     */
    private fun isPlaceholder(signature: Signature, match: String): Boolean {
        if (signature.kind == "PRIVATE_KEY" || signature.kind == "PUTTY_PRIVATE_KEY") return false  // headers have no body
        if (signature.kind == "AWS_ACCESS_KEY" && match.endsWith("EXAMPLE")) return true
        val b = body(signature, match)
        if (b.length < 8) return false
        return b.count { it in REDACTION } >= b.length * 0.9
    }

    /** Only the exact-format signatures: no name hint, no entropy guess. The first non-placeholder match wins. */
    fun scanSignatures(value: String, disabled: Set<String> = emptySet()): SecretFinding? {
        for (signature in SIGNATURES) {
            if (signature.kind in disabled) continue
            if (signature.literals.none { value.contains(it) }) continue
            for (match in signature.regex.findAll(value)) {
                if (isPlaceholder(signature, match.value)) continue
                return SecretFinding(signature.kind, signature.description, signature.severity, match.range.first, match.range.last + 1, match.value)
            }
        }
        return null
    }

    /**
     * Signatures first; then, when [heuristic] is on and a key is known, the
     * strict name + entropy check. [heuristic] is off in template and generated
     * files (`.example`, lockfiles), where values are placeholders or hashes by
     * design; exact formats are still reported there.
     */
    fun scanLiteral(value: String, variableNameHint: String? = null, heuristic: Boolean = true, disabled: Set<String> = emptySet()): SecretFinding? {
        scanSignatures(value, disabled)?.let { return it }
        if (!heuristic || variableNameHint == null || GENERIC_KIND in disabled) return null
        val (name, core) = CredentialHeuristic.credential(variableNameHint, value) ?: return null
        val at = value.indexOf(core).coerceAtLeast(0)
        return SecretFinding(
            GENERIC_KIND,
            "Assigned to '$name' and looks like a real credential, not a placeholder or a reference",
            Severity.MEDIUM, at, at + core.length, core,
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
