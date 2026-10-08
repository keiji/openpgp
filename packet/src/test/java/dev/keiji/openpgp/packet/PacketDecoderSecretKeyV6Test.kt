package dev.keiji.openpgp.packet

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedS2KUsageTypeException
import dev.keiji.openpgp.packet.secretkey.PacketSecretKeyV6
import dev.keiji.openpgp.packet.secretkey.PacketSecretSubkeyV6
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyArgon2
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class PacketDecoderSecretKeyV6Test {

    private fun loadPackets(armored: String): List<Packet> {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(armored.toByteArray(charset = StandardCharsets.UTF_8))
        )
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        return PacketDecoder.decode(data ?: return emptyList())
    }

    @Test
    fun decodeUnprotectedSecretKeyTest() {
        val packetList = loadPackets(ARMORED_SECRET_KEY_V6)
        assertEquals(4, packetList.size)

        val secretKeyPacket = packetList[0]
        assertEquals(Tag.SecretKey, secretKeyPacket.tag)
        assertTrue(secretKeyPacket is PacketSecretKeyV6)
        if (secretKeyPacket is PacketSecretKeyV6) {
            assertEquals(6, secretKeyPacket.version)
            assertEquals(PublicKeyAlgorithm.ED25519, secretKeyPacket.algorithm)
            assertEquals(SecretKeyEncryptionType.ClearText, secretKeyPacket.string2keyUsage)
            assertNull(secretKeyPacket.symmetricKeyEncryptionAlgorithm)
            assertNull(secretKeyPacket.aeadAlgorithm)
            assertNull(secretKeyPacket.initializationVector)

            // A version 6 packet where the S2K usage octet is zero has
            // no trailing 2-octet checksum: the data is the bare
            // 32-octet Ed25519 native secret key.
            assertEquals(
                "19:72:81:7B:12:BE:70:7E:8D:5F:58:6C:E6:13:61:20:1D:34:4E:B2:66:A2:C8:2F:DE:68:35:76:2B:65:B0:B7",
                secretKeyPacket.data.toHex(":")
            )
        }

        val secretSubkeyPacket = packetList[2]
        assertEquals(Tag.SecretSubkey, secretSubkeyPacket.tag)
        assertTrue(secretSubkeyPacket is PacketSecretSubkeyV6)
        if (secretSubkeyPacket is PacketSecretSubkeyV6) {
            assertEquals(PublicKeyAlgorithm.X25519, secretSubkeyPacket.algorithm)
            assertEquals(SecretKeyEncryptionType.ClearText, secretSubkeyPacket.string2keyUsage)
        }
    }

    @Test
    fun decodeLockedSecretKeyTest() {
        // Locked with a passphrase using AEAD and Argon2 (Appendix A.5).
        val packetList = loadPackets(ARMORED_LOCKED_SECRET_KEY_V6)
        assertEquals(4, packetList.size)

        val secretKeyPacket = packetList[0]
        assertTrue(secretKeyPacket is PacketSecretKeyV6)
        if (secretKeyPacket is PacketSecretKeyV6) {
            assertEquals(6, secretKeyPacket.version)
            assertEquals(SecretKeyEncryptionType.AEAD, secretKeyPacket.string2keyUsage)
            assertEquals(SymmetricKeyAlgorithm.AES256, secretKeyPacket.symmetricKeyEncryptionAlgorithm)
            assertEquals(AeadAlgorithm.OCB, secretKeyPacket.aeadAlgorithm)

            val string2Key = secretKeyPacket.string2Key
            assertTrue(string2Key is String2KeyArgon2)
            if (string2Key is String2KeyArgon2) {
                assertEquals(
                    "5D:6F:D7:1C:9E:09:6D:1E:B6:91:7B:6E:6E:1E:EC:AE",
                    string2Key.salt.toHex(":")
                )
            }

            // The AEAD nonce: 15 octets for OCB.
            assertEquals(
                "B4:A8:A9:27:4F:AB:E6:32:F8:75:A7:06:59:20:21",
                secretKeyPacket.initializationVector?.toHex(":")
            )
        }

        val secretSubkeyPacket = packetList[2]
        assertTrue(secretSubkeyPacket is PacketSecretSubkeyV6)
        if (secretSubkeyPacket is PacketSecretSubkeyV6) {
            assertEquals(SecretKeyEncryptionType.AEAD, secretSubkeyPacket.string2keyUsage)
            assertEquals(SymmetricKeyAlgorithm.AES256, secretSubkeyPacket.symmetricKeyEncryptionAlgorithm)
            assertEquals(AeadAlgorithm.OCB, secretSubkeyPacket.aeadAlgorithm)
        }
    }

    @Test
    fun encodeUnprotectedSecretKeyRoundTripTest() {
        assertRoundTrip(ARMORED_SECRET_KEY_V6)
    }

    @Test
    fun encodeLockedSecretKeyRoundTripTest() {
        assertRoundTrip(ARMORED_LOCKED_SECRET_KEY_V6)
    }

    private fun assertRoundTrip(armored: String) {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(armored.toByteArray(charset = StandardCharsets.UTF_8))
        )
        val expected = pgpData.blockList[0].data
        assertNotNull(expected)
        expected ?: return

        val packetList = PacketDecoder.decode(expected)
        val actual = ByteArrayOutputStream().let {
            PacketEncoder.encode(packetList, it)
            it.toByteArray()
        }

        assertArrayEquals(expected, actual)
    }

    @Test
    fun version6SecretKeyMustNotUseS2KUsageOctet255() {
        val packet = PacketSecretKeyV6().also {
            it.string2keyUsage = SecretKeyEncryptionType.CheckSum
        }

        try {
            ByteArrayOutputStream().let {
                packet.writeTo(false, it)
            }
            org.junit.jupiter.api.fail("A version 6 packet MUST NOT use the S2K usage octet 255.")
        } catch (_: UnsupportedS2KUsageTypeException) {
            // expected
        }
    }
}
