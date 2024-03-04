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
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File

class PacketEncoderRevocationTest {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun encodeRevocationKeyTest() {
        val publicKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_revocation_key.gpg"
        )

        val publicKeyPgpData = PgpData.loadAsciiArmored(publicKeyFile)
        val expected = publicKeyPgpData.blockList[0].data
        Assertions.assertNotNull(expected)
        expected ?: return

        val packetRevocationSignature = createEddsaRevocationSignaturePacket()

        val packetList = listOf(
            packetRevocationSignature,
        )

        val actual = ByteArrayOutputStream().let {
            PacketEncoder.encode(true, packetList, it)
            it.toByteArray()
        }

        val expectedHex = expected.toHex(":")
        val actualHex = actual.toHex(":")
        assertEquals(expectedHex, actualHex)
    }

    private fun createEddsaRevocationSignaturePacket(): PacketSignatureV4 {
        val signaturePacket = PacketSignatureV4()
            .also {
                it.signatureType = SignatureType.KeyRevocation
                it.publicKeyAlgorithm = PublicKeyAlgorithm.ECDSA
                it.hashAlgorithm = HashAlgorithm.SHA2_256
            }

        signaturePacket.hashedSubpacketList = listOf(
            IssuerFingerprint().also {
                it.version = 4
                it.fingerprint = parseHexString(
                    "FE:FF:2E:18:5C:F8:F0:63:AD:2E:42:46:3E:58:DE:6C:C9:26:B4:AD",
                    delimiter = ":"
                )
            },
            SignatureCreationTime().also {
                it.value = 1671618357
            },
            ReasonForRevocation().also {
                it.code = ReasonForRevocation.Reason.KeyIsRetiredAndNoLongerUsed
                it.reason = "Hello this is test revoke"
            }
        )

        signaturePacket.subpacketList = listOf(
            Issuer().also {
                it.keyId = parseHexString("3E:58:DE:6C:C9:26:B4:AD", delimiter = ":")
            }
        )

        signaturePacket.hash2bytes = byteArrayOf(0x41.toByte(), 0xB9.toByte())

        signaturePacket.signature = SignatureEcdsa().also {
            it.r = parseHexString(
                "3B:89:F7:FD:AB:CB:9F:17:57:23:BB:AE:BD:C9:82:4E:BA:05:8F:71:37:DE:98:C4:24:28:4F:CC:8D:13:99:F9",
                delimiter = ":"
            )
            it.s = parseHexString(
                "DF:9A:C4:C4:99:EF:87:24:ED:30:56:37:AE:03:82:A9:1B:50:4A:61:30:26:6A:1C:43:93:56:EF:F7:99:5A:E1",
                delimiter = ":"
            )
        }

        return signaturePacket
    }
}
