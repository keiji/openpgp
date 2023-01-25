package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PublicKeyEcdhTest {

    companion object {
        private const val SAMPLE1 = "092B06010401DA470F01" +
                "002C0B16212C3742" + // 10110001011000100001001011000011011101000010 = 44bits
                "03" + // fields length
                "01" + // reserved
                "08" + // kdfHashFunctionId
                "09" // kdfAlgorithm
    }

    @Test
    fun testEncode() {
        val expected = SAMPLE1
        val data = PublicKeyEcdh().also {
            it.ellipticCurveParameter = EllipticCurveParameter.Ed25519
            it.ecPoint = byteArrayOf(11, 22, 33, 44, 55, 66)
            it.kdfHashFunction = HashAlgorithm.SHA2_256
            it.kdfAlgorithm = SymmetricKeyAlgorithm.AES256
        }

        val actual = ByteArrayOutputStream().let {
            data.writeTo(it)
            it.toByteArray()
        }

        assertEquals(expected, actual.toHex(""))
    }

    @Test
    fun testDecode() {
        val expected = PublicKeyEcdh().also {
            it.ellipticCurveParameter = EllipticCurveParameter.Ed25519
            it.ecPoint = byteArrayOf(11, 22, 33, 44, 55, 66)
            it.kdfHashFunction = HashAlgorithm.SHA2_256
            it.kdfAlgorithm = SymmetricKeyAlgorithm.AES256
        }
        val data = parseHexString(SAMPLE1)
        val actual = PublicKeyEcdh().also {
            it.readFrom(ByteArrayInputStream(data))
        }

        assertTrue(expected.equals(actual))
    }
}
