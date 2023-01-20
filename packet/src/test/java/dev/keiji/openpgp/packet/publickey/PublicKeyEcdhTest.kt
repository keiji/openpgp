package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PublicKeyEcdhTest {

    val binary = "092B06010401DA470F01" +
            "002C0B16212C3742" + // 10110001011000100001001011000011011101000010 = 44bits
            "03" + // fields length
            "01" + // reserved
            "01" + // kdfHashFunctionId
            "09" // kdfAlgorithm

    @Test
    fun testEncode() {
        val expected = binary
        val data = PublicKeyEcdh().also {
            it.ellipticCurveParameter = EllipticCurveParameter.Ed25519
            it.ecPoint = byteArrayOf(11, 22, 33, 44, 55, 66)
            it.kdfHashFunctionId = 1
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
            it.kdfHashFunctionId = 1
            it.kdfAlgorithm = SymmetricKeyAlgorithm.AES256
        }
        val data = parseHexString(binary)
        val actual = PublicKeyEcdh().also {
            it.readFrom(ByteArrayInputStream(data))
        }

        assertTrue(expected.equals(actual))
    }
}