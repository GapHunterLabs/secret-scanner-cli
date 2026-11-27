package dev.gaphunter.scannercli

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import kotlin.io.path.createTempDirectory

/** Key names: every naming convention, environment and numbering suffixes, and what must stay unreported. */
class KeyNameTest {

    @Test
    fun wordsSplitTheSameWayInEveryConvention() {
        val expected = listOf("client", "secret")
        for (k in listOf("clientSecret", "ClientSecret", "client-secret", "client_secret", "CLIENT_SECRET", "client.secret", "client secret")) {
            assertEquals(k, expected, KeyName.words(k))
        }
        assertEquals(listOf("api", "key"), KeyName.words("APIKey"))
        assertEquals(listOf("o", "auth", "2", "token"), KeyName.words("OAuth2Token"))
        assertEquals(listOf("api", "key", "v", "2"), KeyName.words("apiKeyV2"))
        assertEquals(emptyList<String>(), KeyName.words(""))
        assertEquals(emptyList<String>(), KeyName.words("__--.."))
    }

    @Test
    fun environmentAndNumberingSuffixesAreDroppedBeforeTheNounIsChecked() {
        for (k in listOf(
            "API_KEY_1", "API_KEY_2", "DB_PASSWORD_PROD", "AUTH_TOKEN_V2", "apiKeyProd", "clientSecretStaging",
            "client-secret-dev", "SECRET_KEY_PRIMARY", "token.secondary", "DB_PASSWORD_PROD_2", "ApiKeyV10", "password1",
            "STRIPE_SECRET_KEY_LIVE", "TOKEN_QA", "PASSWORD_UAT_OLD",
        )) assertTrue(k, CredentialHeuristic.isCredentialKey(k))
    }

    @Test
    fun keysAboutACredentialStayUnreportedWithOrWithoutSuffixes() {
        for (k in listOf(
            "token_url", "TOKEN_URL_PROD", "secretName", "secretNameV2", "passwordPolicy", "password_policy_1",
            "cache_key", "CACHE_KEY_PROD", "KEY_1", "PROD", "V2", "1", "", "_", "monkey", "turkey", "keychain",
            "mytoken", "TOKENIZER", "authority", "author", "authorized_keys_path",
        )) assertFalse("'$k'", CredentialHeuristic.isCredentialKey(k))
    }

    @Test
    fun aBareSuffixIsNeverStrippedToNothing() {
        assertEquals(listOf("prod"), KeyName.core("PROD"))
        assertEquals(listOf("v"), KeyName.core("V2"))
        assertEquals(listOf("api", "key"), KeyName.core("API_KEY_V2_PROD"))
    }

    @Test
    fun theSuffixedKeysAreReportedThroughTheFileScannerAndPlaceholdersAreNot() {
        val root = createTempDirectory(prefix = "keyname-").toFile()
        try {
            val v = Fake.GENERIC
            File(root, "a.env").writeText(
                "API_KEY_1=$v\nDB_PASSWORD_PROD=$v\nAUTH_TOKEN_V2=$v\nTOKEN_URL_PROD=$v\nAPI_KEY_2=changeme\nAPI_KEY_3=<YOUR_API_KEY>\n",
            )
            File(root, "b.yaml").writeText("apiKeyProd: \"$v\"\nclientSecret: \"$v\"\napi-key: \"$v\"\n")
            val hits = Scanner.scan(root).sortedWith(compareBy({ it.file }, { it.line })).map { "${it.file}:${it.line}" }
            assertEquals(listOf("a.env:1", "a.env:2", "a.env:3", "b.yaml:1", "b.yaml:2", "b.yaml:3"), hits)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun theNameAloneIsNeverEnough() {
        assertNull(SecretDetector.scanLiteral("short1", "API_KEY_1"))
        assertNull(SecretDetector.scanLiteral("\${API_KEY}", "API_KEY_PROD"))
        assertNull(SecretDetector.scanLiteral("https://example.com/path?token=", "API_TOKEN_V2"))
    }
}
