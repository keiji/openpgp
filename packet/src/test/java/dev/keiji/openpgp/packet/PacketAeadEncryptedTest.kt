package dev.keiji.openpgp.packet

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedVersionException
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeySaltedIterated
import dev.keiji.openpgp.packet.seipd.PacketSymEncryptedAndIntegrityProtectedDataV2
import dev.keiji.openpgp.packet.skesk.PacketSymmetricKeyEncryptedSessionKeyV6
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class PacketAeadEncryptedTest {
    companion object {
        // A test vector from the obsolete draft-ietf-openpgp-crypto-refresh-07,
        // which uses a never-standardized version 5 SKESK packet.
        // RFC 9580 rejects this packet version.
        private val TEST_VECTOR_OBSOLETE_V5_SKESK = """
-----BEGIN PGP MESSAGE-----
w0AFHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+Np0a4jjV+iuVOuH4dcF
ddcvYCMpkFI+mlkJSSJAa+HD0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq
pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1
QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=
-----END PGP MESSAGE-----
        """.replace("\r\n", "\n")
            .trimIndent()
    }

    @Test
    fun obsoleteVersion5SkeskMustBeRejected() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(
                TEST_VECTOR_OBSOLETE_V5_SKESK.toByteArray(charset = StandardCharsets.UTF_8)
            )
        )
        val data = pgpData.blockList[0].data ?: return fail("data must not be null.")

        // A "version 5" SKESK was never standardized; RFC 9580 only
        // defines version 4 and version 6.
        try {
            PacketDecoder.decode(data)
            fail("version 5 SKESK must be rejected.")
        } catch (_: UnsupportedVersionException) {
            // expected
        }
    }

    @Test
    fun decodeSkeskV6EaxTest() {
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SKESK_V6_EAX)
        assertEquals(1, packetList.size)

        val skesk = packetList[0]
        assertEquals(Tag.SymmetricKeyEncryptedSessionKey, skesk.tag)
        assertTrue(skesk is PacketSymmetricKeyEncryptedSessionKeyV6)
        if (skesk is PacketSymmetricKeyEncryptedSessionKeyV6) {
            assertEquals(6, skesk.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, skesk.symmetricKeyAlgorithm)
            assertEquals(AeadAlgorithm.EAX, skesk.aeadAlgorithm)

            val string2Key = skesk.string2Key
            assertTrue(string2Key is String2KeySaltedIterated)
            if (string2Key is String2KeySaltedIterated) {
                assertEquals(
                    "A5:AE:57:9D:1F:C5:D8:2B",
                    string2Key.salt.toHex(":")
                )
                assertEquals(String2KeyType.SALTED_ITERATED, string2Key.type)
            }

            assertEquals(
                "69:22:4F:91:99:93:B3:50:6F:A3:B5:9A:6A:73:CF:F8",
                skesk.initializationVector?.toHex(":")
            )
        }
    }

    @Test
    fun decodeSkeskV6OcbTest() {
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SKESK_V6_OCB)
        assertEquals(1, packetList.size)

        val skesk = packetList[0]
        assertTrue(skesk is PacketSymmetricKeyEncryptedSessionKeyV6)
        if (skesk is PacketSymmetricKeyEncryptedSessionKeyV6) {
            assertEquals(6, skesk.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, skesk.symmetricKeyAlgorithm)
            assertEquals(AeadAlgorithm.OCB, skesk.aeadAlgorithm)
            assertEquals(
                "CF:CC:5C:11:66:4E:DB:9D:B4:25:90:D7:DC:46:B0",
                skesk.initializationVector?.toHex(":")
            )
        }
    }

    @Test
    fun decodeSkeskV6GcmTest() {
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SKESK_V6_GCM)
        assertEquals(1, packetList.size)

        val skesk = packetList[0]
        assertTrue(skesk is PacketSymmetricKeyEncryptedSessionKeyV6)
        if (skesk is PacketSymmetricKeyEncryptedSessionKeyV6) {
            assertEquals(6, skesk.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, skesk.symmetricKeyAlgorithm)
            assertEquals(AeadAlgorithm.GCM, skesk.aeadAlgorithm)
            assertEquals(
                "B4:2E:7C:48:3E:F4:88:44:57:CB:37:26",
                skesk.initializationVector?.toHex(":")
            )
        }
    }

    @Test
    fun decodeSeipdV2EaxTest() {
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SEIPD_V2_EAX)
        assertEquals(1, packetList.size)

        val seipd = packetList[0]
        assertTrue(seipd is PacketSymEncryptedAndIntegrityProtectedDataV2)
        if (seipd is PacketSymEncryptedAndIntegrityProtectedDataV2) {
            assertEquals(2, seipd.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, seipd.cipherAlgorithm)
            assertEquals(AeadAlgorithm.EAX, seipd.aeadAlgorithm)
            assertEquals(6, seipd.chunkSize)
            assertEquals(
                "9F:F9:0E:3B:32:19:64:F3:A4:29:13:C8:DC:C6:61:93:25:01:52:27:EF:B7:EA:EA:A4:9F:04:C2:E6:74:17:5D",
                seipd.salt.toHex(":")
            )
        }
    }

    @Test
    fun decodeSeipdV2OcbTest() {
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SEIPD_V2_OCB)
        assertEquals(1, packetList.size)

        val seipd = packetList[0]
        assertTrue(seipd is PacketSymEncryptedAndIntegrityProtectedDataV2)
        if (seipd is PacketSymEncryptedAndIntegrityProtectedDataV2) {
            assertEquals(2, seipd.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, seipd.cipherAlgorithm)
            assertEquals(AeadAlgorithm.OCB, seipd.aeadAlgorithm)
            assertEquals(6, seipd.chunkSize)
        }
    }

    @Test
    fun decodeSeipdV2GcmTest() {
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SEIPD_V2_GCM)
        assertEquals(1, packetList.size)

        val seipd = packetList[0]
        assertTrue(seipd is PacketSymEncryptedAndIntegrityProtectedDataV2)
        if (seipd is PacketSymEncryptedAndIntegrityProtectedDataV2) {
            assertEquals(2, seipd.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, seipd.cipherAlgorithm)
            assertEquals(AeadAlgorithm.GCM, seipd.aeadAlgorithm)
            assertEquals(6, seipd.chunkSize)
        }
    }

    @Test
    fun decodeSeipdV2X25519OcbTest() {
        // Appendix A.8.3.
        val packetList = PacketDecoder.decode(Rfc9580TestVectors.SEIPD_V2_X25519_OCB)
        assertEquals(1, packetList.size)

        val seipd = packetList[0]
        assertTrue(seipd is PacketSymEncryptedAndIntegrityProtectedDataV2)
        if (seipd is PacketSymEncryptedAndIntegrityProtectedDataV2) {
            assertEquals(2, seipd.version)
            assertEquals(SymmetricKeyAlgorithm.AES128, seipd.cipherAlgorithm)
            assertEquals(AeadAlgorithm.OCB, seipd.aeadAlgorithm)
            assertEquals(6, seipd.chunkSize)
        }
    }

    @Test
    fun encodeSkeskV6RoundTripTest() {
        val hexVectors = listOf(
            Rfc9580TestVectors.SKESK_V6_EAX,
            Rfc9580TestVectors.SKESK_V6_OCB,
            Rfc9580TestVectors.SKESK_V6_GCM,
        )
        hexVectors.forEach { vector ->
            val packetList = PacketDecoder.decode(vector)
            val actual = ByteArrayOutputStream().let {
                packetList[0].writeTo(it)
                it.toByteArray()
            }
            assertArrayEquals(vector, actual)
        }
    }

    @Test
    fun encodeSeipdV2RoundTripTest() {
        val hexVectors = listOf(
            Rfc9580TestVectors.SEIPD_V2_EAX,
            Rfc9580TestVectors.SEIPD_V2_OCB,
            Rfc9580TestVectors.SEIPD_V2_GCM,
            Rfc9580TestVectors.SEIPD_V2_X25519_OCB,
        )
        hexVectors.forEach { vector ->
            val packetList = PacketDecoder.decode(vector)
            val actual = ByteArrayOutputStream().let {
                packetList[0].writeTo(it)
                it.toByteArray()
            }
            assertArrayEquals(vector, actual)
        }
    }
}
