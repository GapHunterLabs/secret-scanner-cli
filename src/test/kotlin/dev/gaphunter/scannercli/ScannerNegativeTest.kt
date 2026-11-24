package dev.gaphunter.scannercli

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import kotlin.io.path.createTempDirectory

/** Inputs the scanner has to survive: odd roots, odd files, odd bytes, link loops and pathological lines. */
class ScannerNegativeTest {

    private lateinit var root: File

    @Before
    fun setUp() {
        root = createTempDirectory(prefix = "scanner-negative-").toFile()
    }

    private val links = mutableListOf<File>()

    @After
    fun tearDown() {
        // Links go first, so deleteRecursively never walks into a loop or out of the temp tree.
        links.forEach { Files.deleteIfExists(it.toPath()) }
        root.deleteRecursively()
    }

    private fun write(relativePath: String, content: String): File {
        val file = File(root, relativePath)
        file.parentFile.mkdirs()
        file.writeText(content)
        return file
    }

    @Test
    fun emptyDirectoryHasNoFindings() {
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun emptyFileHasNoFindings() {
        write("empty.kt", "")
        write("only-newlines.yaml", "\n\n\r\n")
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun aSingleFileRootIsScannedAndReportedByItsOwnName() {
        val f = write("sub/Config.kt", "val gh = \"${Fake.GITHUB}\"\n")
        val hits = Scanner.scan(f)
        assertEquals(1, hits.size)
        assertEquals("Config.kt", hits[0].file)
    }

    @Test
    fun aSingleFileRootIsScannedWhateverItsExtension() {
        // The user named the file; the extension filter is for directory walks.
        val f = write("notes.txt", "token ${Fake.GITHUB}\n")
        assertEquals(listOf("GITHUB_TOKEN"), Scanner.scan(f).map { it.kind })
    }

    @Test
    fun aRootWhoseNameIsASkippedDirectoryIsStillScanned() {
        for (name in listOf("build", "node_modules", "vendor", "dist", "target", "out", ".git")) {
            val dir = File(root, name).apply { mkdirs() }
            File(dir, "Secret.kt").writeText("val gh = \"${Fake.GITHUB}\"\n")
            assertEquals(name, 1, Scanner.scan(dir).size)
        }
    }

    @Test
    fun skippedDirectoriesBelowTheRootAreStillSkipped() {
        // Neighbour of the root fix: only the root itself is exempt, a nested build/ or node_modules/ is not.
        write("build/Secret.kt", "val gh = \"${Fake.GITHUB}\"\n")
        write("build/build/Inner.kt", "val gh = \"${Fake.GITHUB}\"\n")
        write("src/node_modules/x.js", "const t = \"${Fake.GITHUB}\"\n")
        assertEquals(listOf("Secret.kt"), Scanner.scan(File(root, "build")).map { it.file })
        assertTrue(Scanner.scan(File(root, "src")).isEmpty())
        // From the parent, build/ is a skipped child again.
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun binaryContentWithATextExtensionDoesNotCrashAndStillFindsTextSecrets() {
        val bytes = ByteArray(4096) { (it * 31 % 256).toByte() }
        File(root, "blob.json").writeBytes(bytes + "\nkey = \"${Fake.AWS}\"\n".toByteArray())
        assertEquals(listOf("AWS_ACCESS_KEY"), Scanner.scan(root).map { it.kind })
    }

    @Test
    fun binaryFilesByExtensionAreSkipped() {
        for (ext in listOf("png", "jar", "zip", "class", "exe")) write("x.$ext", "val gh = \"${Fake.GITHUB}\"\n")
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun nonUtf8BytesAreDecodedWithReplacementNotSkipped() {
        // Latin-1 e-acute (0xE9) and a lone 0xFF are malformed UTF-8; the secret after them must still be found.
        val f = File(root, "latin1.properties")
        f.writeBytes(byteArrayOf(0x63, 0x61, 0x66, 0xE9.toByte(), 0x3D, 0xFF.toByte(), 0x0A) + "api.token=${Fake.GENERIC}\n".toByteArray())
        val hits = Scanner.scan(root)
        assertEquals(listOf("GENERIC_HIGH_ENTROPY"), hits.map { it.kind })
        assertEquals(2, hits[0].line)
    }

    @Test
    fun utf16FileIsAKnownBlindSpot() {
        // Documented gap, pinned: a UTF-16 file (some Windows editors save .ps1/.json this way) is read as UTF-8,
        // so every other byte is NUL and no rule matches.
        File(root, "utf16.json").writeBytes("{\"token\": \"${Fake.GITHUB}\"}".toByteArray(Charsets.UTF_16LE))
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun aFileThatCannotBeReadIsSkippedWithoutStoppingTheScan() {
        // Windows enforces byte-range locks for other readers; elsewhere this lock is advisory, so the case is Windows-only.
        assumeTrue(System.getProperty("os.name").startsWith("Windows"))
        val locked = write("locked.kt", "val gh = \"${Fake.GITHUB}\"\n")
        write("open.kt", "val gh = \"${Fake.GITHUB}\"\n")
        RandomAccessFile(locked, "rw").use { raf ->
            raf.channel.lock().use {
                val hits = Scanner.scan(root)
                // Known gap: the locked file is skipped silently, no warning.
                assertEquals(listOf("open.kt"), hits.map { it.file })
            }
        }
    }

    @Test
    fun aDirectoryLinkLoopIsEnteredOnce() {
        write("a/Cfg.kt", "val gh = \"${Fake.GITHUB}\"\n")
        val link = File(root, "a/back")
        assumeTrue("cannot create a directory link on this machine", makeDirectoryLink(link, root))
        val hits = Scanner.scan(root)
        assertEquals(listOf("a/Cfg.kt"), hits.map { it.file })
    }

    @Test
    fun twoLinksToTheSameDirectoryScanItOnce() {
        write("real/Cfg.kt", "val gh = \"${Fake.GITHUB}\"\n")
        assumeTrue(makeDirectoryLink(File(root, "alias1"), File(root, "real")))
        assumeTrue(makeDirectoryLink(File(root, "alias2"), File(root, "real")))
        assertEquals(1, Scanner.scan(root).size)
    }

    // ---- ReDoS regressions: small enough for the normal suite, large enough that the old patterns took seconds ----

    @Test(timeout = 5_000)
    fun aLongRunOfKeyCharactersIsLinear() {
        // Before the fix: about 20 s for 20,000 characters (quadratic).
        write("blob.js", "a".repeat(40_000) + "\n" + "a.b-c_".repeat(8_000) + "\n")
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test(timeout = 5_000)
    fun aLongDotlessJwtLookalikeRunIsLinear() {
        // Before the fix: about 2.3 s for 20,000 characters, 9+ s for 40,000 (quadratic).
        assertEquals(null, SecretDetector.scanLiteral("-eyJ".repeat(20_000)))
        write("x.yaml", "-eyJ".repeat(20_000) + "\n")
        assertTrue(Scanner.scan(root).isEmpty())
    }

    @Test
    fun aKeyLongerThanTheCapStillReportsTheSecretUnderItsLastCharacters() {
        // Neighbour of the key-length cap: a 300-character key does not hide the value.
        val key = "x".repeat(290) + "_password"
        write("long.properties", "$key = \"${Fake.GENERIC}\"\n")
        val hits = Scanner.scan(root)
        assertEquals(listOf("GENERIC_HIGH_ENTROPY"), hits.map { it.kind })
        assertTrue(hits[0].description.contains("_password"))
    }

    @Test
    fun keysUpToTheCapMatchExactlyAsBefore() {
        for (len in listOf(1, 127, 128)) {
            val key = "k".repeat(len - 1) + "t"
            val m = Scanner.ASSIGNMENT_LINE.find("$key = \"value-123456\"")!!
            assertEquals("len $len", key, m.groupValues[1])
        }
        // 129: the match starts one character later, the key is the last 128.
        val key = "k".repeat(128) + "t"
        assertEquals(128, Scanner.ASSIGNMENT_LINE.find("$key = \"value-123456\"")!!.groupValues[1].length)
    }

    private fun makeDirectoryLink(link: File, target: File): Boolean {
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
}
