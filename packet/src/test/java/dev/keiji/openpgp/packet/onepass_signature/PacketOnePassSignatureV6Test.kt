package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.InvalidSignatureException
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayOutputStream

class PacketOnePassSignatureV6Test {

    @Test
    fun testEncode() {
        // version 6, sig type 0x00, hash SHA2-512(10), pk algo Ed25519(27=0x1B),
        // salt size 32, salt 0x00..0x1F, fingerprint 0x00..0x1F, flag 0.
        // The body is 70 octets long.
        val expected =
            "C4" + "46" + "06" + "00" + "0A" + "1B" +
                    "20" + "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                    "00"

        val packetOnePassSignature = PacketOnePassSignatureV6().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_512
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ED25519
            it.salt = ByteArray(32) { index -> index.toByte() }
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
    fun testDecode() {
        val packetBytes = parseHexString(
            "C44606000A1B20" +
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                    "00"
        )

        val expected = PacketOnePassSignatureV6().also {
            it.signatureType = SignatureType.BinaryDocument
            it.hashAlgorithm = HashAlgorithm.SHA2_512
            it.publicKeyAlgorithm = PublicKeyAlgorithm.ED25519
            it.salt = ByteArray(32) { index -> index.toByte() }
            it.fingerprint = ByteArray(32) { index -> index.toByte() }
            it.flag = 0
        }

        val packetOnePassSignature = PacketOnePassSignatureParser.parse(
            java.io.ByteArrayInputStream(packetBytes).let { stream ->
                stream.read() // skip the packet header
                stream.read()
                stream
            }
        )

        assertTrue(packetOnePassSignature is PacketOnePassSignatureV6)
        assertEquals(expected, packetOnePassSignature)
    }

    @Test
    fun fingerprintLengthMustBeEqual32() {
        try {
            PacketOnePassSignatureV6().also {
                it.fingerprint = ByteArray(31)
            }
            fail("")
        } catch (exception: IllegalArgumentException) {
            println(exception.message)
        }
    }

    @Test
    fun saltSizeMustMatchHashAlgorithm() {
        try {
            val data = parseHexString(
                "C44606000A1B20" +
                        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" +
                        "00"
            )
            // Corrupt the salt size octet (0x20 -> 0x1F): it no longer
            // matches the salt size 32 of SHA2-512.
            data[6] = 0x1F

            PacketOnePassSignatureParser.parse(
                java.io.ByteArrayInputStream(data).let { stream ->
                    stream.read() // skip the packet header
                    stream.read()
                    stream
                }
            )
            fail("")
        } catch (exception: InvalidSignatureException) {
            println(exception.message)
        }
    }
}
