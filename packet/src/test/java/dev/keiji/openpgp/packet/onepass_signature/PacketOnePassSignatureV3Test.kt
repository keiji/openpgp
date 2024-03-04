package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.PacketDecoder
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PacketOnePassSignatureV3Test {

    @Test
    fun testEncodeOldFormat() {
        val expected = "900D03000813FFFEFDFCFBFAF0F900"

        val packetOnePassSignature = PacketOnePassSignatureV3().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.keyId = byteArrayOf(
                0xFF.toByte(),
                0xFE.toByte(),
                0xFD.toByte(),
                0xFC.toByte(),
                0xFB.toByte(),
                0xFA.toByte(),
                0xF0.toByte(),
                0xF9.toByte(),
            )
            it.flag = 0
        }

        val actual = ByteArrayOutputStream().let {
            packetOnePassSignature.writeTo(true, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testKeyIdLengthMustBeEqual8_1() {
        try {
            PacketOnePassSignatureV3().also {
                it.keyId = byteArrayOf(
                    0xFF.toByte(),
                    0xFE.toByte(),
                    0xFD.toByte(),
                    0xFC.toByte(),
                    0xFB.toByte(),
                    0xFA.toByte(),
                    0xF0.toByte(),
                    0xF9.toByte(),
                    0xF8.toByte(),
                )
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun testKeyIdLengthMustBeEqual8_2() {
        try {
            PacketOnePassSignatureV3().also {
                it.keyId = byteArrayOf(
                    0xFF.toByte(),
                    0xFE.toByte(),
                    0xFD.toByte(),
                    0xFC.toByte(),
                    0xFB.toByte(),
                    0xFA.toByte(),
                    0xF0.toByte(),
                )
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun testEncodeNewFormat() {
        val expected = "C40D03000813FFFEFDFCFBFAF0F900"

        val packetOnePassSignature = PacketOnePassSignatureV3().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.keyId = byteArrayOf(
                0xFF.toByte(),
                0xFE.toByte(),
                0xFD.toByte(),
                0xFC.toByte(),
                0xFB.toByte(),
                0xFA.toByte(),
                0xF0.toByte(),
                0xF9.toByte(),
            )
            it.flag = 0
        }

        val actual = ByteArrayOutputStream().let {
            packetOnePassSignature.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeOldFormat() {
        val data = parseHexString("900D03000813FFFEFDFCFBFAF0F900")

        val expected = PacketOnePassSignatureV3().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.keyId = byteArrayOf(
                0xFF.toByte(),
                0xFE.toByte(),
                0xFD.toByte(),
                0xFC.toByte(),
                0xFB.toByte(),
                0xFA.toByte(),
                0xF0.toByte(),
                0xF9.toByte(),
            )
            it.flag = 0
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }

    @Test
    fun testDecodeNewFormat() {
        val data = parseHexString("C40D03000813FFFEFDFCFBFAF0F900")

        val expected = PacketOnePassSignatureV3().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.keyId = byteArrayOf(
                0xFF.toByte(),
                0xFE.toByte(),
                0xFD.toByte(),
                0xFC.toByte(),
                0xFB.toByte(),
                0xFA.toByte(),
                0xF0.toByte(),
                0xF9.toByte(),
            )
            it.flag = 0
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }
}
