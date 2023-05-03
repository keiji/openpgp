package dev.keiji.openpgp.packet

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.subpacket.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.security.MessageDigest

class PacketDecoderRevocationKeySignatureTest {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun decodeRevocationKeySignatureTest() {
        val revocationFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_revocation_key.gpg"
        )

        val revocationPgpData = PgpData.loadAsciiArmored(revocationFile)
        val revocationData = revocationPgpData.blockList[0].data
        assertNotNull(revocationData)
        revocationData ?: return

        val publicKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
        )

        val publicKeyPgpData = PgpData.loadAsciiArmored(publicKeyFile)
        val publicKeyData = publicKeyPgpData.blockList[0].data
        assertNotNull(publicKeyData)
        publicKeyData ?: return

        val packetList = PacketDecoder.decode(revocationData)
        assertEquals(1, packetList.size)

        val packetSignature = packetList[0]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(
                SignatureType.KeyRevocation,
                packetSignature.signatureType
            )
            assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

            val hashedSubpackets = packetSignature.hashedSubpacketList
            assertEquals(3, hashedSubpackets.size)

            val issuerFingerprintSubpacket = hashedSubpackets[0]
            assertEquals(SubpacketType.IssuerFingerprint, issuerFingerprintSubpacket.getType())
            if (issuerFingerprintSubpacket is IssuerFingerprint) {
                assertEquals(4, issuerFingerprintSubpacket.version)
                assertEquals(
                    "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD",
                    issuerFingerprintSubpacket.fingerprint.toHex()
                )
            }
            val signatureCreationTimeSubpacket = hashedSubpackets[1]
            assertEquals(
                SubpacketType.SignatureCreationTime,
                signatureCreationTimeSubpacket.getType()
            )
            if (signatureCreationTimeSubpacket is SignatureCreationTime) {
                assertEquals(1671618357, signatureCreationTimeSubpacket.value)
            }

            val subpackets = packetSignature.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "3E58DE6CC926B4AD",
                    issuerSubpacket.keyId.toHex()
                )
            }

            val hash2bytes = packetSignature.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "41B9",
                hash2bytes.toHex()
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEcdsa)
            if (signature is SignatureEcdsa) {
                assertEquals(
                    "3B89F7FDABCB9F175723BBAEBDC9824EBA058F7137DE98C424284FCC8D1399F9",
                    signature.r?.toHex(),
                )
                assertEquals(
                    "DF9AC4C499EF8724ED305637AE0382A91B504A6130266A1C439356EFF7995AE1",
                    signature.s?.toHex(),
                )
            }

            // Verify signature
            val publicKeyPacket = PacketDecoder.decode(publicKeyData)
            val contentBytes = packetSignature.getContentBytes(publicKeyPacket)
            val contentHashBytes = MessageDigest.getInstance("SHA-256").let {
                it.update(contentBytes)
                it.digest()
            }

            assertEquals(0x41.toByte(), contentHashBytes[0])
            assertEquals(0xB9.toByte(), contentHashBytes[1])
            assertEquals("41B9ED05D9F7CA34734684864C6C83FDE3EF0F2220DB8F36FA81BF0E8F1635E3", contentHashBytes.toHex())
        }

    }
}
