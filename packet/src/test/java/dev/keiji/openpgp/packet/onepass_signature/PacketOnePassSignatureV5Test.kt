@file:Suppress(
    "LongMethod",
    "MaxLineLength",
)

package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.InvalidSignatureException
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

class PacketOnePassSignatureV5Test {

    @Test
    fun testEncodeOldFormat() {
        val expected =
            "903605000813000102030405060708090A0B0C0D0E0F05000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00"

        val packetOnePassSignature = PacketOnePassSignatureV5().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.salt = ByteArray(16) { index -> index.toByte() }
            it.keyVersion = 5
            it.fingerprint = ByteArray(32) { index -> index.toByte() }
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
    fun saltLengthMustBeEqual16_1() {
        try {
            PacketOnePassSignatureV5().also {
                it.salt = ByteArray(15)
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun saltLengthMustBeEqual16_2() {
        try {
            PacketOnePassSignatureV5().also {
                it.salt = ByteArray(17)
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun keyVersionMustBeEqual5_1() {
        try {
            PacketOnePassSignatureV5().also {
                it.keyVersion = 6
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun keyVersionMustBeEqual5_2() {
        try {
            PacketOnePassSignatureV5().also {
                it.keyVersion = 4
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun testEncodeNewFormat() {
        val expected =
            "C43605000813000102030405060708090A0B0C0D0E0F05000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00"

        val packetOnePassSignature = PacketOnePassSignatureV5().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.salt = ByteArray(16) { index -> index.toByte() }
            it.keyVersion = 5
            it.fingerprint = ByteArray(32) { index -> index.toByte() }
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
        val data =
            parseHexString("903605000813000102030405060708090A0B0C0D0E0F05000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00")

        val expected = PacketOnePassSignatureV5().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.salt = ByteArray(16) { index -> index.toByte() }
            it.keyVersion = 5
            it.fingerprint = ByteArray(32) { index -> index.toByte() }
            it.flag = 0
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }

    @Test
    fun testDecodeNewFormat() {
        val data =
            parseHexString("C43605000813000102030405060708090A0B0C0D0E0F05000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00")

        val expected = PacketOnePassSignatureV5().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_256
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
            it.salt = ByteArray(16) { index -> index.toByte() }
            it.keyVersion = 5
            it.fingerprint = ByteArray(32) { index -> index.toByte() }
            it.flag = 0
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }

    @Test
    fun keyVersionMustBeEqual5_3() {
        val data =
            parseHexString("903605000813000102030405060708090A0B0C0D0E0F06000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00")

        try {
            PacketDecoder.decode(ByteArrayInputStream(data))
            fail("")
        } catch (exception: InvalidSignatureException) {
            println(exception.message)
        }
    }

    @Test
    fun keyVersionMustBeEqual5_4() {
        val data =
            parseHexString("903605000813000102030405060708090A0B0C0D0E0F04000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00")

        try {
            PacketDecoder.decode(ByteArrayInputStream(data))
            fail("")
        } catch (exception: InvalidSignatureException) {
            println(exception.message)
        }
    }
}
