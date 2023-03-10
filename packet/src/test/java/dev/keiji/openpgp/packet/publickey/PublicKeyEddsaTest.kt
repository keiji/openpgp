package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PublicKeyEddsaTest {

    companion object {
        private const val SAMPLE1 = "092B06010401DA470F01" +
                "0029010203040506"
    }

    @Test
    fun testEncode() {
        val expected = SAMPLE1
        val data = PublicKeyEddsa().also {
            it.ellipticCurveParameter = EllipticCurveParameter.Ed25519
            it.ecPoint = byteArrayOf(1, 2, 3, 4, 5, 6)
        }

        val actual = ByteArrayOutputStream().let {
            data.writeTo(it)
            it.toByteArray()
        }

        assertEquals(expected, actual.toHex(""))
    }

    @Test
    fun testDecode() {
        val expected = PublicKeyEddsa().also {
            it.ellipticCurveParameter = EllipticCurveParameter.Ed25519
            it.ecPoint = byteArrayOf(1, 2, 3, 4, 5, 6)
        }
        val data = parseHexString(SAMPLE1)
        val actual = PublicKeyEddsa().also {
            it.readFrom(ByteArrayInputStream(data))
        }

        assertTrue(expected.equals(actual))
    }
}
