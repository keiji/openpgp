package dev.keiji.openpgp.packet

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.subpacket.Issuer
import dev.keiji.openpgp.packet.signature.subpacket.IssuerFingerprint
import dev.keiji.openpgp.packet.signature.subpacket.ReasonForRevocation
import dev.keiji.openpgp.packet.signature.subpacket.SignatureCreationTime
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketType
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import java.io.File
import org.junit.jupiter.api.Test

class PacketDecoderRevocationKeyTest {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun decodeRevocationKeyTest() {
        val revocationFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_revocation_key.gpg"
        )

        val revocationPgpData = PgpData.loadAsciiArmored(revocationFile)
        val revocationData = revocationPgpData.blockList[0].data
        assertNotNull(revocationData)
        revocationData ?: return

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
                    issuerFingerprintSubpacket.fingerprint.toHex("")
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
            val reasonForRevocationSubpacket = hashedSubpackets[2]
            assertEquals(SubpacketType.ReasonForRevocation, reasonForRevocationSubpacket.getType())
            if (reasonForRevocationSubpacket is ReasonForRevocation) {
                assertEquals(
                    ReasonForRevocation.Reason.KeyIsRetiredAndNoLongerUsed,
                    reasonForRevocationSubpacket.code,
                )
                assertEquals(
                    "Hello this is test revoke",
                    reasonForRevocationSubpacket.reason,
                )
            }

            val subpackets = packetSignature.subpacketList
            assertEquals(1, subpackets.size)

            val issuerSubpacket = subpackets[0]
            assertEquals(SubpacketType.Issuer, issuerSubpacket.getType())
            if (issuerSubpacket is Issuer) {
                assertEquals(
                    "3E58DE6CC926B4AD",
                    issuerSubpacket.keyId.toHex("")
                )
            }

            val hash2bytes = packetSignature.hash2bytes
            assertEquals(2, hash2bytes.size)
            assertEquals(
                "41B9",
                hash2bytes.toHex("")
            )

            val signature = packetSignature.signature
            assertNotNull(signature)
            signature ?: return

            assertTrue(signature is SignatureEcdsa)
            if (signature is SignatureEcdsa) {
                assertEquals(
                    "3B89F7FDABCB9F175723BBAEBDC9824EBA058F7137DE98C424284FCC8D1399F9",
                    signature.r?.toHex(""),
                )
                assertEquals(
                    "DF9AC4C499EF8724ED305637AE0382A91B504A6130266A1C439356EFF7995AE1",
                    signature.s?.toHex(""),
                )
            }
        }
    }
}
