package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PublicKeyRsaTest {

    companion object {
        private const val SAMPLE1 = "00" +
                "230708090A0B00" +
                "210102030405"
    }

    @Test
    fun testEncode() {
        val expected = SAMPLE1
        val data = PublicKeyRsa().also {
            it.n = byteArrayOf(7, 8, 9, 10, 11)
            it.e = byteArrayOf(1, 2, 3, 4, 5)
        }

        val actual = ByteArrayOutputStream().let {
            data.writeTo(it)
            it.toByteArray()
        }

        assertEquals(expected, actual.toHex(""))
    }

    @Test
    fun testDecode() {
        val expected = PublicKeyRsa().also {
            it.n = byteArrayOf(7, 8, 9, 10, 11)
            it.e = byteArrayOf(1, 2, 3, 4, 5)
        }
        val data = parseHexString(SAMPLE1)
        val actual = PublicKeyRsa().also {
            it.readFrom(ByteArrayInputStream(data))
        }

        assertTrue(expected.equals(actual))
    }
}