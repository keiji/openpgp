package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File

class PgpDataTest {

    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun testIsAsciiArmoredForm() {
        val file = File(
            file.absolutePath,
            "0EE13652E9E9D0BF7115A3C9A71E2CA57AC1F09A_ecdsa_publickey_signedby_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )

        val actual = PgpData.isAsciiArmored(file)
        assertTrue(actual)
    }

    @Test
    fun testIsBinary() {
        val file = File(
            file.absolutePath,
            "hello_txt_detatched_sign_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.sig"
        )

        val actual = PgpData.isAsciiArmored(file)
        assertFalse(actual)
    }

    @Test
    fun testParseAsciiArmored() {
        val file = File(
            file.absolutePath,
            "0EE13652E9E9D0BF7115A3C9A71E2CA57AC1F09A_ecdsa_publickey_signedby_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )

        val pgpData = PgpData.loadAsciiArmored(file)
        assertTrue(pgpData.isAsciiArmor)
    }

    @Test
    fun testParseBinary() {
        val file = File(
            file.absolutePath,
            "hello_txt_detatched_sign_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.sig"
        )

        val pgpData = PgpData.loadBinary(file)
        assertFalse(pgpData.isAsciiArmor)
        assertEquals(0, pgpData.blockList.size)
        assertNotNull(pgpData.data)
    }

    @Test
    fun testLoad1() {
        val file = File(
            file.absolutePath,
            "0EE13652E9E9D0BF7115A3C9A71E2CA57AC1F09A_ecdsa_publickey_signedby_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )

        val pgpData = PgpData.load(file)
        assertTrue(pgpData.isAsciiArmor)
    }

    @Test
    fun testLoad2() {
        val file = File(
            file.absolutePath,
            "hello_txt_detatched_sign_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.sig"
        )

        val pgpData = PgpData.load(file)
        assertFalse(pgpData.isAsciiArmor)
        assertEquals(0, pgpData.blockList.size)
        assertNotNull(pgpData.data)
    }

    @Test
    fun testClearTextSignatureParse() {
        val signedMessageFile = File(
            file.absolutePath,
            "hello_gpg_txt_clearsigned_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )
        val clearText = File(
            file.absolutePath,
            "hello_gpg.txt"
        ).readText()
        val canonicalizedText = PgpData.canonicalize(clearText)

        val pgpData = PgpData.loadAsciiArmored(signedMessageFile)

        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        assertEquals(canonicalizedText.toHex(), data.toHex())
    }

}
