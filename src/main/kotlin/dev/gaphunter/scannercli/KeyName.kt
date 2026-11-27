package dev.gaphunter.scannercli

/**
 * Splits a configuration key into lower-case words the same way whatever its
 * naming convention (snake_case, kebab-case, dotted, camelCase, PascalCase,
 * UPPER_CASE), drops trailing environment or numbering suffixes, and says
 * whether what is left names a credential.
 *
 * Version 0.2.0 used two regexes that wanted the credential noun at the very
 * end of the key, so `API_KEY_1`, `DB_PASSWORD_PROD`, `AUTH_TOKEN_V2` and
 * `apiKeyProd` were never checked at all.
 */
internal object KeyName {

    /** Words that only say which copy of a credential this is. Removed from the end before the noun is checked. */
    private val ENVIRONMENT_SUFFIXES = setOf(
        "prod", "production", "dev", "development", "staging", "stage", "stg", "qa", "uat", "test", "testing",
        "local", "primary", "secondary", "backup", "old", "new", "live", "sandbox",
    )

    /** A credential noun on its own (also the glued forms `apikey`, `secretkey`...). */
    private val NOUNS = setOf(
        "secret", "token", "password", "passwd", "pwd", "passphrase", "credential", "credentials", "authorization", "auth",
        "apikey", "accesskey", "privatekey", "secretkey", "signingkey", "encryptionkey",
    )

    /** Qualifiers that make `key` a credential noun: `api_key`, `accessKey`. A bare `key` (`cache_key`) is not one. */
    private val KEY_QUALIFIERS = setOf("api", "access", "private", "secret", "signing", "encryption")

    /** Splits [key] into lower-case words: separators, camelCase humps, acronym ends and letter/digit changes. */
    fun words(key: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        fun flush() {
            if (cur.isNotEmpty()) out += cur.toString().lowercase()
            cur.setLength(0)
        }
        for ((i, c) in key.withIndex()) {
            if (!c.isLetterOrDigit()) {
                flush()
                continue
            }
            val prev = key.getOrNull(i - 1)
            val next = key.getOrNull(i + 1)
            val boundary = prev != null && prev.isLetterOrDigit() && (
                (prev.isLowerCase() && c.isUpperCase()) ||                                   // apiKey
                    (prev.isUpperCase() && c.isUpperCase() && next != null && next.isLowerCase()) || // APIKey -> API, Key
                    (prev.isDigit() != c.isDigit())                                             // key2, v2Token
                )
            if (boundary) flush()
            cur.append(c)
        }
        flush()
        return out
    }

    private fun isSuffix(word: String): Boolean =
        word in ENVIRONMENT_SUFFIXES || word.all { it.isDigit() } || (word.length >= 2 && word[0] == 'v' && word.drop(1).all { it.isDigit() })

    /** The words that name the credential: [words] without the trailing environment or numbering suffixes. */
    fun core(key: String): List<String> {
        val w = words(key).toMutableList()
        // `v2` splits into `v` and `2` at the letter/digit change: drop the digits, then a lone `v` before them.
        while (w.size > 1 && isSuffix(w.last())) {
            val removed = w.removeAt(w.size - 1)
            if (removed.all { it.isDigit() } && w.size > 1 && w.last() == "v") w.removeAt(w.size - 1)
        }
        return w
    }

    /** True for a key whose last word (after suffixes) is a credential noun. */
    fun isCredentialKey(key: String): Boolean {
        val w = core(key)
        val last = w.lastOrNull() ?: return false
        if (last in NOUNS) return true
        return last == "key" && w.size >= 2 && w[w.size - 2] in KEY_QUALIFIERS
    }
}
