package dev.gaphunter.scannercli

import java.io.File

/**
 * The optional project configuration, `.secret-scanner.json`:
 *
 * ```json
 * {
 *   "exclude": ["tests/fixtures/", "*.snap"],
 *   "disableRules": ["GOOGLE_API_KEY"],
 *   "failOn": "high",
 *   "maxFileSizeMb": 10,
 *   "maxFindings": 200,
 *   "followExternalLinks": false
 * }
 * ```
 *
 * Strict on purpose: an unknown key, a wrong type or an unknown rule id is an
 * error that names it (exit 2), not a setting that is silently ignored. JSON
 * only: YAML would need a parser dependency, and this tool ships as one jar
 * with no dependencies.
 */
data class Config(
    val exclude: List<String> = emptyList(),
    val disableRules: Set<String> = emptySet(),
    val failOn: String? = null,
    val maxFileSizeMb: Long? = null,
    val maxFindings: Int? = null,
    val followExternalLinks: Boolean? = null,
    val source: String? = null,
) {
    class Invalid(message: String) : IllegalArgumentException(message)

    companion object {
        const val FILE_NAME = ".secret-scanner.json"
        val FAIL_ON_VALUES = listOf("high", "medium", "all", "none")
        private val KEYS = setOf("exclude", "disableRules", "failOn", "maxFileSizeMb", "maxFindings", "followExternalLinks")

        fun load(file: File): Config {
            val text = try {
                file.readText(Charsets.UTF_8).removePrefix("\uFEFF")
            } catch (e: java.io.IOException) {
                throw Invalid("cannot read the configuration file $file: ${e.message}")
            }
            return parse(text, file.path)
        }

        fun parse(text: String, source: String): Config {
            val root = try {
                MiniJson(text).parse()
            } catch (e: IllegalArgumentException) {
                throw Invalid("$source is not valid JSON: ${e.message}")
            }
            if (root !is Map<*, *>) throw Invalid("$source must hold a JSON object")
            val unknown = root.keys.map { it.toString() }.filter { it !in KEYS }
            if (unknown.isNotEmpty()) throw Invalid("$source: unknown key(s) ${unknown.joinToString()} (known: ${KEYS.sorted().joinToString()})")

            fun strings(key: String): List<String>? {
                val v = root[key] ?: return null
                if (v !is List<*> || v.any { it !is String }) throw Invalid("$source: '$key' must be an array of strings")
                return v.map { it as String }
            }

            fun wholeNumber(key: String, min: Long): Long? {
                val v = root[key] ?: return null
                if (v !is Double || v != Math.floor(v) || v < min || v > Int.MAX_VALUE) {
                    throw Invalid("$source: '$key' must be a whole number of at least $min")
                }
                return v.toLong()
            }

            val disable = strings("disableRules").orEmpty().toSet()
            val unknownRules = disable - SecretDetector.KINDS.toSet()
            if (unknownRules.isNotEmpty()) throw Invalid("$source: unknown rule id(s) in 'disableRules': ${unknownRules.sorted().joinToString()}")
            val failOn = root["failOn"]?.let {
                if (it !is String || it !in FAIL_ON_VALUES) throw Invalid("$source: 'failOn' must be one of ${FAIL_ON_VALUES.joinToString()}")
                it
            }
            val follow = root["followExternalLinks"]?.let {
                it as? Boolean ?: throw Invalid("$source: 'followExternalLinks' must be true or false")
            }
            return Config(
                exclude = strings("exclude").orEmpty(),
                disableRules = disable,
                failOn = failOn,
                maxFileSizeMb = wholeNumber("maxFileSizeMb", 0),
                maxFindings = wholeNumber("maxFindings", 1)?.toInt(),
                followExternalLinks = follow,
                source = source,
            )
        }
    }
}

/**
 * Minimal strict JSON parser (RFC 8259) for the configuration file: rejects raw
 * control characters, bad escapes, trailing commas, duplicate keys and trailing
 * content. Returns Map/List/String/Double/Boolean/null. Nesting is capped so a
 * hostile file cannot overflow the stack.
 */
internal class MiniJson(private val s: String) {
    private var i = 0
    private var depth = 0

    fun parse(): Any? {
        val v = value()
        ws()
        if (i != s.length) fail("trailing content")
        return v
    }

    private fun fail(msg: String): Nothing = throw IllegalArgumentException("$msg at offset $i")

    private fun ws() {
        while (i < s.length && s[i] in " \t\r\n") i++
    }

    private fun value(): Any? {
        ws()
        if (i >= s.length) fail("unexpected end")
        return when (s[i]) {
            '{' -> nested { obj() }
            '[' -> nested { arr() }
            '"' -> str()
            't' -> lit("true", true)
            'f' -> lit("false", false)
            'n' -> lit("null", null)
            else -> num()
        }
    }

    private fun <T> nested(block: () -> T): T {
        if (++depth > 64) fail("nested too deeply")
        try {
            return block()
        } finally {
            depth--
        }
    }

    private fun lit(word: String, v: Any?): Any? {
        if (!s.startsWith(word, i)) fail("bad literal")
        i += word.length
        return v
    }

    private fun num(): Double {
        val m = NUMBER.matchAt(s, i) ?: fail("bad number")
        i += m.value.length
        return m.value.toDouble()
    }

    private fun str(): String {
        i++
        val sb = StringBuilder()
        while (true) {
            if (i >= s.length) fail("unterminated string")
            val c = s[i++]
            when {
                c == '"' -> return sb.toString()
                c == '\\' -> {
                    if (i >= s.length) fail("bad escape")
                    when (val e = s[i++]) {
                        '"', '\\', '/' -> sb.append(e)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            val hex = s.substring(i, minOf(i + 4, s.length))
                            if (!HEX4.matches(hex)) fail("bad \\u escape")
                            sb.append(hex.toInt(16).toChar())
                            i += 4
                        }
                        else -> fail("bad escape \\$e")
                    }
                }
                c < ' ' -> fail("raw control character in a string")
                else -> sb.append(c)
            }
        }
    }

    private fun obj(): Map<String, Any?> {
        i++
        val m = LinkedHashMap<String, Any?>()
        ws()
        if (s.getOrNull(i) == '}') { i++; return m }
        while (true) {
            ws()
            if (s.getOrNull(i) != '"') fail("expected a key")
            val k = str()
            if (k in m) fail("duplicate key '$k'")
            ws()
            if (s.getOrNull(i) != ':') fail("expected ':'")
            i++
            m[k] = value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> i++
                '}' -> { i++; return m }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun arr(): List<Any?> {
        i++
        val l = ArrayList<Any?>()
        ws()
        if (s.getOrNull(i) == ']') { i++; return l }
        while (true) {
            l += value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> i++
                ']' -> { i++; return l }
                else -> fail("expected ',' or ']'")
            }
        }
    }

    private companion object {
        val NUMBER = Regex("""-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?""")
        val HEX4 = Regex("[0-9a-fA-F]{4}")
    }
}
