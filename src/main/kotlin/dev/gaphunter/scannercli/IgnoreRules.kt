package dev.gaphunter.scannercli

/**
 * Exclusion patterns from `.scannerignore`, the configuration file's `exclude`
 * list and `--exclude`. A subset of gitignore, matched against the path as the
 * report shows it (`/`-separated):
 *
 *  - `*` any run of characters except `/`, `?` one character except `/`, `**` any depth;
 *  - a pattern with a `/` at the start or in the middle is anchored to the top
 *    (`/build`, `docs/api.md`); one without matches a name at any depth (`fixtures`);
 *  - a trailing `/` matches directories only (and everything inside them);
 *  - blank lines and `#` comments are ignored.
 *
 * Negation (`!pattern`) is rejected instead of being ignored: silently scanning
 * less, or more, than the file says is the worst outcome for a secret scanner.
 */
class IgnoreRules private constructor(private val patterns: List<Pattern>) {

    private class Pattern(val source: String, val origin: String, val regex: Regex, val dirOnly: Boolean)

    class Invalid(message: String) : IllegalArgumentException(message)

    val size: Int get() = patterns.size

    fun plus(other: IgnoreRules) = IgnoreRules(patterns + other.patterns)

    /** True when [path] (a file, or a directory when [isDirectory]) or any of its parent directories is excluded. */
    fun matches(path: String, isDirectory: Boolean): Boolean {
        if (patterns.isEmpty()) return false
        val parts = path.split('/').filter { it.isNotEmpty() && it != "." }
        for (end in parts.indices) {
            val candidate = parts.subList(0, end + 1).joinToString("/")
            val dir = end < parts.size - 1 || isDirectory
            if (patterns.any { (!it.dirOnly || dir) && it.regex.matches(candidate) }) return true
        }
        return false
    }

    companion object {
        val NONE = IgnoreRules(emptyList())

        /** Parses [lines]; [origin] names the source in error messages (`.scannerignore:3`). */
        fun parse(lines: List<String>, origin: String): IgnoreRules {
            val out = mutableListOf<Pattern>()
            lines.forEachIndexed { i, raw ->
                val line = raw.trimEnd().removePrefix("﻿")
                if (line.isBlank() || line.trimStart().startsWith("#")) return@forEachIndexed
                out += compile(line.trim(), "$origin:${i + 1}")
            }
            return IgnoreRules(out)
        }

        /** One pattern, as `--exclude` passes it. */
        fun single(raw: String, origin: String): IgnoreRules = IgnoreRules(listOf(compile(raw.trim(), origin)))

        private fun compile(raw: String, origin: String): Pattern {
            if (raw.startsWith("!")) throw Invalid("$origin: negated patterns ('$raw') are not supported; list only what to exclude")
            var p = raw.replace('\\', '/')
            val dirOnly = p.endsWith("/")
            p = p.trimEnd('/')
            if (p.isEmpty()) throw Invalid("$origin: the pattern '$raw' matches nothing")
            val anchored = p.startsWith("/") || p.contains('/')
            p = p.removePrefix("/")
            val body = globToRegex(p)
            val regex = Regex(if (anchored) body else "(?:.*/)?$body")
            return Pattern(raw, origin, regex, dirOnly)
        }

        private fun globToRegex(glob: String): String {
            val sb = StringBuilder()
            var i = 0
            while (i < glob.length) {
                val c = glob[i]
                when {
                    glob.startsWith("**/", i) -> { sb.append("(?:.*/)?"); i += 3; continue }
                    glob.startsWith("/**", i) && i + 3 == glob.length -> { sb.append("(?:/.*)?"); i += 3; continue }
                    glob.startsWith("**", i) -> { sb.append(".*"); i += 2; continue }
                    c == '*' -> sb.append("[^/]*")
                    c == '?' -> sb.append("[^/]")
                    else -> sb.append(Regex.escape(c.toString()))
                }
                i++
            }
            return sb.toString()
        }
    }
}
