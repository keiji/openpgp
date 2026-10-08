package dev.keiji.openpgp.packet

import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV6
import dev.keiji.openpgp.packet.publickey.PublicKeyEd25519
import dev.keiji.openpgp.packet.publickey.PublicKeyX25519
import dev.keiji.openpgp.packet.signature.PacketSignatureV6
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketType
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class PacketDecoderCertificateV6Test {

    private fun loadCertificatePackets(): List<Packet> {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(ARMORED_CERT_V6.toByteArray(charset = StandardCharsets.UTF_8))
        )
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        return PacketDecoder.decode(data ?: return emptyList())
    }

    @Test
    fun decodeCertificateTest() {
        val packetList = loadCertificatePackets()

        // Public Key + Direct Key self-signature + Public Subkey +
        // Subkey Binding signature.
        assertEquals(4, packetList.size)

        val primaryKeyPacket = packetList[0]
        assertEquals(Tag.PublicKey, primaryKeyPacket.tag)
        assertTrue(primaryKeyPacket is PacketPublicKeyV6)
        if (primaryKeyPacket is PacketPublicKeyV6) {
            assertEquals(6, primaryKeyPacket.version)
            assertEquals(PublicKeyAlgorithm.ED25519, primaryKeyPacket.algorithm)
            // 2022-11-30T16:08:03Z
            assertEquals(1669824483, primaryKeyPacket.createdDateTimeEpoch)

            val publicKey = primaryKeyPacket.publicKey
            assertTrue(publicKey is PublicKeyEd25519)
            if (publicKey is PublicKeyEd25519) {
                assertEquals(
                    "F9:4D:A7:BB:48:D6:0A:61:E5:67:70:6A:65:87:D0:33:19:99:BB:9D:89:1A:08:24:2E:AD:84:54:3D:F8:95:A3",
                    publicKey.nativePublicKey?.toHex(":")
                )
            }
        }

        val directKeySignaturePacket = packetList[1]
        assertEquals(Tag.Signature, directKeySignaturePacket.tag)
        assertTrue(directKeySignaturePacket is PacketSignatureV6)
        if (directKeySignaturePacket is PacketSignatureV6) {
            assertEquals(6, directKeySignaturePacket.version)
            assertEquals(SignatureType.SignatureDirectlyOnKey, directKeySignaturePacket.signatureType)
            assertEquals(PublicKeyAlgorithm.ED25519, directKeySignaturePacket.publicKeyAlgorithm)
            assertEquals(
                dev.keiji.openpgp.HashAlgorithm.SHA2_512,
                directKeySignaturePacket.hashAlgorithm
            )

            assertEquals(
                "10:3E:2D:7D:22:7E:C0:E6:D7:CE:44:71:DB:36:BF:C9:70:83:25:36:90:27:14:98:A7:EF:05:76:C0:7F:AA:E1",
                directKeySignaturePacket.salt.toHex(":")
            )

            val issuerFingerprint = directKeySignaturePacket.hashedSubpacketList
                .firstOrNull { it.getType() == SubpacketType.IssuerFingerprint }
            assertNotNull(issuerFingerprint)
        }

        val subkeyPacket = packetList[2]
        assertEquals(Tag.PublicSubkey, subkeyPacket.tag)
        assertTrue(subkeyPacket is PacketPublicKeyV6)
        if (subkeyPacket is PacketPublicKeyV6) {
            assertEquals(PublicKeyAlgorithm.X25519, subkeyPacket.algorithm)

            val subkey = subkeyPacket.publicKey
            assertTrue(subkey is PublicKeyX25519)
            if (subkey is PublicKeyX25519) {
                assertEquals(
                    "86:93:24:83:67:F9:E5:01:5D:B9:22:F8:F4:80:95:DD:A7:84:98:7F:2D:59:85:B1:2F:BA:D1:6C:AF:5E:44:35",
                    subkey.nativePublicKey?.toHex(":")
                )
            }
        }

        val subkeyBindingSignaturePacket = packetList[3]
        assertEquals(Tag.Signature, subkeyBindingSignaturePacket.tag)
        assertTrue(subkeyBindingSignaturePacket is PacketSignatureV6)
        if (subkeyBindingSignaturePacket is PacketSignatureV6) {
            assertEquals(SignatureType.SubKeyBinding, subkeyBindingSignaturePacket.signatureType)
            assertEquals(PublicKeyAlgorithm.ED25519, subkeyBindingSignaturePacket.publicKeyAlgorithm)
            assertEquals(
                "A6:E9:18:6D:9D:59:35:FC:8F:E5:63:14:CD:B5:27:48:6A:5A:51:20:F9:B7:62:A2:35:A7:29:F0:39:01:0A:56",
                subkeyBindingSignaturePacket.salt.toHex(":")
            )
        }
    }

    @Test
    fun hashedDataStreamForDirectKeySignatureTest() {
        // The Direct Key self-signature is made over the data described
        // in RFC 9580 Appendix A.3.1.
        val packetList = loadCertificatePackets()

        val directKeySignature = packetList[1] as PacketSignatureV6
        val actual = directKeySignature.getContentBytes(packetList)

        assertArrayEquals(
            Rfc9580TestVectors.HASHED_STREAM_DIRECT_KEY,
            actual
        )
    }

    @Test
    fun hashedDataStreamForSubkeyBindingSignatureTest() {
        // The Subkey Binding signature is made over the data described
        // in RFC 9580 Appendix A.3.1.
        val packetList = loadCertificatePackets()

        val subkeyBindingSignature = packetList[3] as PacketSignatureV6
        val actual = subkeyBindingSignature.getContentBytes(packetList)

        assertArrayEquals(
            Rfc9580TestVectors.HASHED_STREAM_SUBKEY_BINDING,
            actual
        )
    }

    @Test
    fun encodeCertificateRoundTripTest() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(ARMORED_CERT_V6.toByteArray(charset = StandardCharsets.UTF_8))
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
}
