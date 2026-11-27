package dev.gaphunter.scannercli

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * No Kotlin source in this repository carries a raw invisible character: a C0 or C1 control, a byte-order mark, a
 * bidirectional control or a line separator. Code that needs one writes its escape (`'\uFEFF'`). A raw one is
 * invisible in review and makes GitHub flag the file for bidirectional Unicode text.
 */
class SourceHygieneTest {

    private fun invisible(c: Char): Boolean {
        val o = c.code
        return (o < 0x20 && c != '\t' && c != '\n' && c != '\r') || o in 0x7f..0x9f || o in 0x200b..0x200f ||
            o in 0x202a..0x202e || o in 0x2066..0x2069 || o == 0xFEFF || o == 0x061C || o == 0x2028 || o == 0x2029
    }

    @Test
    fun noKotlinSourceHasARawInvisibleCharacter() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "src/main/kotlin").isDirectory }
        val found = File(root, "src").walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "kts") }
            .flatMap { f -> f.readLines().withIndex().filter { (_, l) -> l.any(::invisible) }.map { (n, _) -> "${f.relativeTo(root)}:${n + 1}" } }
            .toList()
        assertEquals("write these as escapes", emptyList<String>(), found)
    }
}
