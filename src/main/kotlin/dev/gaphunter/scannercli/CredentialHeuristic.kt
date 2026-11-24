package dev.gaphunter.scannercli

/**
 * The name + entropy check, in the strict form api-security-companion uses for
 * configuration files (`detect/ConfigSecretScanner.kt`), applied here to every
 * file: a CI gate pays for each false positive with a failed build, and the
 * loose form (any key that merely CONTAINS `token` or `secret`) reported
 * hundreds of findings on ordinary source trees.
 *
 * A value is reported only when all of these hold:
 *  - the key names a credential: its LAST word is the credential noun
 *    (`api_token`, `client_secret`, `DB_PASSWORD` yes; `token_url`,
 *    `secretName`, `passwordPolicy` no, those are settings ABOUT a secret);
 *  - the value is not a reference to something defined elsewhere
 *    (`${VAR}`, `$VAR`, `%VAR%`, `{{ var }}`, `<placeholder>`, `env:VAR`);
 *  - it is one token, not a sentence, a path or a URL without credentials,
 *    and not a slug like `authorization-code-grant`;
 *  - it mixes at least two character classes and passes the length and
 *    entropy check of [SecretDetector.looksLikeARealSecret].
 */
object CredentialHeuristic {

    private val REFERENCE = Regex("""^\s*(\$\{[^}]*}|\$[A-Za-z_][A-Za-z0-9_]*|%[^%]+%|\{\{.*}}|<[^>]*>|env:[A-Za-z_]\w*)\s*$""")

    private val CREDENTIAL_KEY = Regex(
        """(^|[_.\-\s])(api[_-]?key|access[_-]?key|private[_-]?key|secret[_-]?key|signing[_-]?key|encryption[_-]?key|""" +
            """secret|token|password|passwd|pwd|passphrase|credentials?|authorization|auth)$|[a-z0-9](ApiKey|AccessKey|""" +
            """PrivateKey|SecretKey|Secret|Token|Password|Passphrase|Credentials?|Authorization)$""",
        RegexOption.IGNORE_CASE,
    )

    private val AUTH_SCHEME_PREFIX = Regex("""^(Bearer|Basic|Token)\s+""", RegexOption.IGNORE_CASE)

    /** `--api-key=VALUE` / `-p=VALUE` command-line arguments, as CI and MCP configs pass them. */
    private val FLAG_ASSIGNMENT = Regex("""^--?([A-Za-z][A-Za-z0-9_.-]*)=(.+)$""", RegexOption.DOT_MATCHES_ALL)

    private val USERINFO_IN_URL = Regex("""://[^/@\s]+:[^/@\s]+@""")

    /**
     * `authorization-code-grant`, `GITHUB_TOKEN_NAME`: words of one letter case
     * joined by single `_`, `.` or `-`, at least two words. Letters only:
     * `acme_deploy_9f8e7d6c5b4a3210` is not a slug (a digit run is what a
     * generated key looks like). A loop, not the plugin's `[a-z]+([_.-][a-z]+)+`:
     * Java runs a repeated group recursively, one stack frame per word, and a
     * 1 MB value like `a.a.a...` overflowed the stack (found by the stress suite).
     */
    internal fun isSlug(value: String): Boolean {
        if (value.isEmpty()) return false
        val lower = value[0] in 'a'..'z'
        if (!lower && value[0] !in 'A'..'Z') return false
        var separators = 0
        var previousWasSeparator = false
        for (c in value) {
            when {
                c == '_' || c == '.' || c == '-' -> {
                    if (previousWasSeparator) return false
                    previousWasSeparator = true
                    separators++
                }
                (lower && c in 'a'..'z') || (!lower && c in 'A'..'Z') -> previousWasSeparator = false
                else -> return false
            }
        }
        return separators > 0 && !previousWasSeparator
    }

    private val GENERATED_FILE_NAMES = setOf(
        "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock", "pubspec.lock",
        "google-services.json",
    )

    private val TEMPLATE_MARKERS = listOf(".example", ".sample", ".template", ".dist", ".tpl", ".tmpl")

    /** Sample/template files and lock files hold placeholders or hashes by design. */
    fun isTemplateOrGeneratedFile(fileName: String): Boolean {
        val name = fileName.lowercase()
        if (name in GENERATED_FILE_NAMES) return true
        return TEMPLATE_MARKERS.any { name.endsWith(it) || name.contains("$it.") }
    }

    fun isReference(value: String): Boolean = REFERENCE.matches(value)

    /** True for a key that names a credential (its last word is the credential noun). */
    fun isCredentialKey(key: String): Boolean = CREDENTIAL_KEY.containsMatchIn(key.trim())

    /**
     * The credential's key when [value] assigned to [key] looks like a real
     * credential, else null. A `--flag=VALUE` value is judged by its own flag
     * name, and an auth scheme (`Bearer `) is not part of the secret.
     */
    fun credentialName(key: String, value: String): String? {
        if (value.isBlank() || isReference(value)) return null
        var name = key
        var core = value.trim()
        FLAG_ASSIGNMENT.matchEntire(core)?.let { match ->
            name = match.groupValues[1]
            core = match.groupValues[2]
        }
        core = core.replace(AUTH_SCHEME_PREFIX, "")
        if (!isCredentialKey(name)) return null
        if (isReference(core) || !looksLikeACredentialValue(core)) return null
        if (!SecretDetector.looksLikeARealSecret(core)) return null
        return name
    }

    /** A credential value is one token, not a sentence, path or URL, and mixes character classes. */
    private fun looksLikeACredentialValue(value: String): Boolean {
        if (value.any { it.isWhitespace() }) return false
        if (value.startsWith("/") || value.startsWith("./") || value.startsWith("~") || value.contains('\\')) return false
        if (value.contains("://") && !USERINFO_IN_URL.containsMatchIn(value)) return false
        if (isSlug(value)) return false
        val classes = listOf(
            value.any { it.isLowerCase() }, value.any { it.isUpperCase() },
            value.any { it.isDigit() }, value.any { !it.isLetterOrDigit() },
        ).count { it }
        return classes >= 2
    }

    /**
     * An unquoted value as `.env` files write it: one pair of quotes stripped,
     * or a trailing ` # comment` cut off. Returns the value and its offset in [rest].
     */
    fun unquote(rest: String): Pair<String, Int> {
        val trimmed = rest.trimStart()
        val lead = rest.length - trimmed.length
        if (trimmed.length >= 2 && (trimmed[0] == '"' || trimmed[0] == '\'')) {
            val close = trimmed.indexOf(trimmed[0], 1)
            if (close > 0) return trimmed.substring(1, close) to (lead + 1)
        }
        val commentAt = INLINE_COMMENT.find(trimmed)?.range?.first ?: trimmed.length
        return trimmed.substring(0, commentAt).trimEnd() to lead
    }

    private val INLINE_COMMENT = Regex("""\s#""")
}
