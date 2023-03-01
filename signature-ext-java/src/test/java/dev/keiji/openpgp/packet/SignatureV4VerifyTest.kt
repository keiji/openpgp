package dev.keiji.openpgp.packet

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.verify
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File

class SignatureV4VerifyTest {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun veriftyTest() {
        val publicKeyData =
            File(
                file.absolutePath,
                "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
            )
                .readText()

        val signatureData =
            File(
                file.absolutePath,
                "hello_txt_signed_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
            )
                .readBytes()

        val packetCompressedData = PacketDecoder.decode(ByteArrayInputStream(signatureData))
            .first { it is PacketCompressedData } as PacketCompressedData

        val packetList = PacketDecoder.decode(packetCompressedData.rawDataInputStream)
        val packetSignature = packetList.first { it is PacketSignatureV4 } as PacketSignatureV4

        assertEquals(
            SignatureType.BinaryDocument,
            packetSignature.signatureType
        )
        assertEquals(OpenPgpAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

        val signature = packetSignature.signature
        assertNotNull(signature)
        signature ?: return

        assertTrue(signature is SignatureEcdsa)
        if (signature is SignatureEcdsa) {
            val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
            val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey

            val contentHash = packetSignature.hash(packetList)

            val result = signature.verify(packetPublicKey, contentHash)
            assertTrue(result)
        }
    }
}
