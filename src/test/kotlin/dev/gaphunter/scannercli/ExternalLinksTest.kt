package dev.gaphunter.scannercli

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.io.path.createTempDirectory

/**
 * Since 0.2.0 a link (symlink or Windows junction) whose real path leads outside the scanned folder is not followed
 * unless --follow-external-links is given. Links are deleted before the folders in tearDown: a recursive delete that
 * walked into a junction would empty its target.
 */
class ExternalLinksTest {

    private lateinit var root: File
    private lateinit var outside: File
    private val links = mutableListOf<File>()

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "links-root-").toFile()
        outside = createTempDirectory(prefix = "links-outside-").toFile()
        File(outside, "Leak.kt").writeText("val gh = \"${Fake.GITHUB}\"\n")
    }

    @After
    fun tearDown() {
        links.forEach { Files.deleteIfExists(it.toPath()) }
        root.deleteRecursively()
        outside.deleteRecursively()
    }

    private fun write(name: String, text: String) = File(root, name).also { it.parentFile.mkdirs(); it.writeText(text) }

    private fun directoryLink(link: File, target: File): Boolean {
        link.parentFile.mkdirs()
        try {
            Files.createSymbolicLink(link.toPath(), target.toPath())
            links += link
            return true
        } catch (e: Exception) {
            // Windows without Developer Mode can't make symlinks; a junction needs no privilege.
        }
        if (!System.getProperty("os.name").startsWith("Windows")) return false
        val p = ProcessBuilder("cmd", "/c", "mklink", "/J", link.absolutePath, target.absolutePath).redirectErrorStream(true).start()
        p.inputStream.readBytes()
        val ok = p.waitFor() == 0 && link.isDirectory
        if (ok) links += link
        return ok
    }

    @Test
    fun aDirectoryLinkLeadingOutsideIsNotFollowedByDefault() {
        write("src/App.kt", "val ok = 1\n")
        assumeTrue("cannot create a directory link here", directoryLink(File(root, "src/vendored"), outside))
        val skipped = mutableListOf<String>()
        val hits = Scanner.scan(root) { skipped += it }
        assertTrue(hits.isEmpty())
        assertEquals(listOf("src/vendored"), skipped)
    }

    @Test
    fun followExternalLinksScansThroughIt() {
        assumeTrue(directoryLink(File(root, "vendored"), outside))
        val skipped = mutableListOf<String>()
        val hits = Scanner.scan(root, followExternalLinks = true) { skipped += it }
        assertEquals(listOf("vendored/Leak.kt"), hits.map { it.file })
        assertTrue(skipped.isEmpty())
    }

    @Test
    fun aLinkToAFolderInsideTheRootIsStillFollowedOnce() {
        write("real/Cfg.kt", "val gh = \"${Fake.GITHUB}\"\n")
        assumeTrue(directoryLink(File(root, "alias"), File(root, "real")))
        val skipped = mutableListOf<String>()
        val hits = Scanner.scan(root) { skipped += it }
        assertEquals(1, hits.size)
        assertTrue(skipped.isEmpty())
    }

    @Test
    fun aRootThatIsItselfALinkIsScanned() {
        val parent = createTempDirectory(prefix = "links-parent-").toFile()
        try {
            val linkedRoot = File(parent, "repo")
            assumeTrue(directoryLink(linkedRoot, outside))
            assertEquals(listOf("Leak.kt"), Scanner.scan(linkedRoot).map { it.file })
        } finally {
            links.forEach { Files.deleteIfExists(it.toPath()) }
            links.clear()
            parent.deleteRecursively()
        }
    }

    @Test
    fun aFileSymlinkLeadingOutsideIsNotRead() {
        val link = File(root, "leak.kt")
        try {
            Files.createSymbolicLink(link.toPath(), File(outside, "Leak.kt").toPath())
            links += link
        } catch (e: Exception) {
            assumeTrue("file symlinks need Developer Mode on Windows", false)
        }
        val skipped = mutableListOf<String>()
        assertTrue(Scanner.scan(root) { skipped += it }.isEmpty())
        assertEquals(listOf("leak.kt"), skipped)
        assertEquals(1, Scanner.scan(root, followExternalLinks = true).size)
    }

    @Test
    fun withinComparesWholePathSegments() {
        val base = File(root, "repo").absolutePath
        assertTrue(Scanner.isWithin(base, base))
        assertTrue(Scanner.isWithin(File(base, "a/b").absolutePath, base))
        assertFalse(Scanner.isWithin(base + "2", base))
        assertFalse(Scanner.isWithin(File(root, "other").absolutePath, base))
        assertFalse(Scanner.isWithin(root.absolutePath, base))
    }

    @Test
    fun theCliWarnsOnStderrAndKeepsTheSarifOnStdoutValid() {
        write("App.kt", "val ok = 1\n")
        assumeTrue(directoryLink(File(root, "ext"), outside))
        val (code, out, err) = run(root.path, "--format", "sarif", "--no-banner")
        assertEquals(0, code)
        assertTrue(sarifResults(out).isEmpty())
        assertTrue(err, err.contains("skipped 1 link(s) that lead outside the scanned folder: ext (--follow-external-links scans them)"))
        assertFalse("the warning never names the link's target", err.contains(outside.name))

        val (code2, out2, err2) = run(root.path, "--follow-external-links", "--no-banner")
        assertEquals(1, code2)
        assertTrue(out2.contains("ext/Leak.kt"))
        assertFalse(err2.contains("link(s) that lead outside"))
    }

    private fun run(vararg args: String): Triple<Int, String, String> {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = PrintStream(out, true, "UTF-8").use { o -> PrintStream(err, true, "UTF-8").use { e -> cliMain(arrayOf(*args), o, e, false) } }
        return Triple(code, out.toString("UTF-8"), err.toString("UTF-8"))
    }
}
