package dev.gaphunter.scannercli

data class SecretFinding(val kind: String, val description: String)

/**
 * Ported verbatim from api-security-companion's
 * `detect/SecretDetector.kt` (dev.gaphunter.apisecuritycompanion.detect),
 * which was already pure text-based detection with zero PSI/IntelliJ
 * Platform dependency — that's exactly what makes it portable to a
 * plain CLI. This file is a manual copy, not a shared module: the two
 * plugins/projects build independently (one is an IntelliJ plugin, this
 * one is a standalone JVM app), so keeping them in sync is a deliberate
 * trade-off, not an oversight. If the detection rules change in one
 * place, mirror the change here (or vice versa) by hand.
 *
 * Combines known credential-format signatures (AWS/GitHub/Slack/JWT/PEM
 * private keys/Stripe) with a variable-name + Shannon-entropy heuristic
 * for the generic "some secret assigned to a suspiciously-named field"
 * case that no fixed format covers.
 */
object SecretDetector {

    private val AWS_ACCESS_KEY = Regex("""\b(AKIA|ASIA)[0-9A-Z]{16}\b""")
    private val GITHUB_TOKEN = Regex("""\bgh[pousr]_[A-Za-z0-9]{36,}\b""")
    private val SLACK_TOKEN = Regex("""\bxox[baprs]-[0-9A-Za-z-]{10,}\b""")
    private val JWT = Regex("""\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b""")
    private val PRIVATE_KEY_HEADER = Regex("""-----BEGIN ((RSA|EC|OPENSSH|DSA|ENCRYPTED) )?PRIVATE KEY-----""")
    private val STRIPE_KEY = Regex("""\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b""")

    private val SECRET_LIKE_NAME = Regex(
        """(api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|private[_-]?key)""",
        RegexOption.IGNORE_CASE,
    )

    private val OBVIOUS_PLACEHOLDER = Regex(
        """^(|changeme|change[_-]?me|todo|fixme|xxx+|your[_-].*|placeholder|example|test|dummy|<.*>|\$\{.*})$""",
        RegexOption.IGNORE_CASE,
    )

    private const val MIN_ENTROPY_LENGTH = 12
    private const val MIN_ENTROPY_BITS_PER_CHAR = 3.3

    fun scanLiteral(value: String, variableNameHint: String? = null): SecretFinding? {
        AWS_ACCESS_KEY.find(value)?.let {
            return SecretFinding("AWS_ACCESS_KEY", "Looks like an AWS access key ID (${it.value.take(8)}...)")
        }
        GITHUB_TOKEN.find(value)?.let {
            return SecretFinding("GITHUB_TOKEN", "Looks like a GitHub personal access token")
        }
        SLACK_TOKEN.find(value)?.let {
            return SecretFinding("SLACK_TOKEN", "Looks like a Slack API token")
        }
        JWT.find(value)?.let {
            return SecretFinding("JWT", "Looks like a JWT (base64url header.payload.signature)")
        }
        if (PRIVATE_KEY_HEADER.containsMatchIn(value)) {
            return SecretFinding("PRIVATE_KEY", "Contains a PEM private key block")
        }
        STRIPE_KEY.find(value)?.let {
            return SecretFinding("STRIPE_KEY", "Looks like a Stripe secret/restricted API key (${it.value.take(11)}...)")
        }
        if (variableNameHint != null && SECRET_LIKE_NAME.containsMatchIn(variableNameHint) && looksLikeARealSecret(value)) {
            return SecretFinding(
                "GENERIC_HIGH_ENTROPY",
                "Assigned to a variable named '$variableNameHint' and looks like a real credential, not a placeholder",
            )
        }
        return null
    }

    private fun looksLikeARealSecret(value: String): Boolean {
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
