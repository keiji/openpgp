package dev.keiji.openpgp.packet

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.verify
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File

class SignatureV4VerifyTest {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun verifyEcdsaSignatureTest() {
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

        val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
        val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey
        val contentBytes = packetSignature.getContentBytes(packetList)

        val result = signature.verify(packetPublicKey, packetSignature.hashAlgorithm, contentBytes)
        assertTrue(result)
    }

    @Test
    fun verifyRsaSignatureTest() {
        val publicKeyData =
            File(
                file.absolutePath,
                "7B27AACBE3CCE445DABC4009A6ADD410C459A09B_rsa3072_publickey.gpg"
            )
                .readText()

        val signatureData =
            File(
                file.absolutePath,
                "hello_txt_signed_by_7B27AACBE3CCE445DABC4009A6ADD410C459A09B.gpg"
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
        assertEquals(OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN, packetSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

        val signature = packetSignature.signature
        assertNotNull(signature)
        signature ?: return

        val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
        val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey
        val contentBytes = packetSignature.getContentBytes(packetList)

        val result = signature.verify(
            packetPublicKey,
            packetSignature.hashAlgorithm,
            contentBytes
        )
        assertTrue(result)
    }
}
