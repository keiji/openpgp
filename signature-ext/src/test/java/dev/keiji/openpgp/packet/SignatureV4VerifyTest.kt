package dev.keiji.openpgp.packet

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.verify
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File

class SignatureV4VerifyTest {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun verifyEcdsaClearSignedTest() {
        val publicKeyFile = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
        )
        val publicKeyPgpData = PgpData.load(publicKeyFile)

        val signatureFile = File(
            file.absolutePath,
            "hello_gpg_txt_clearsigned_by_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )
        val signaturePgpData = PgpData.load(signatureFile)

        val clearText = signaturePgpData.blockList[0].data
        assertNotNull(clearText)
        clearText ?: return

        val signatureData = signaturePgpData.blockList[0].blockList[0].data
        assertNotNull(signatureData)
        signatureData ?: return

        val packetList = PacketDecoder.decode(signatureData)
        val packetSignature = packetList.first { it is PacketSignatureV4 } as PacketSignatureV4

        assertEquals(
            SignatureType.CanonicalTextDocument,
            packetSignature.signatureType
        )
        assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

        val signature = packetSignature.signature
        assertNotNull(signature)
        signature ?: return

        val publicKeyData = publicKeyPgpData.blockList[0].data
        assertNotNull(publicKeyData)
        publicKeyData ?: return

        val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
        val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey

        val result = packetSignature.verify(packetPublicKey, clearText)
        assertTrue(result)
    }

    @Test
    fun verifyEcdsaSignatureTest() {
        val publicKeyFile =
            File(
                file.absolutePath,
                "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
            )
        val publicKeyPgpData = PgpData.load(publicKeyFile)

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
        assertEquals(PublicKeyAlgorithm.ECDSA, packetSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

        val signature = packetSignature.signature
        assertNotNull(signature)
        signature ?: return

        val publicKeyData = publicKeyPgpData.blockList[0].data
        assertNotNull(publicKeyData)
        publicKeyData ?: return

        val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
        val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey

        val result = packetSignature.verify(packetPublicKey, packetList)
        assertTrue(result)
    }

    @Test
    fun verifyRsaSignatureTest() {
        val publicKeyFile =
            File(
                file.absolutePath,
                "7B27AACBE3CCE445DABC4009A6ADD410C459A09B_rsa3072_publickey.gpg"
            )
        val publicKeyPgpData = PgpData.load(publicKeyFile)

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
        assertEquals(PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN, packetSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_256, packetSignature.hashAlgorithm)

        val signature = packetSignature.signature
        assertNotNull(signature)
        signature ?: return

        val publicKeyData = publicKeyPgpData.blockList[0].data
        assertNotNull(publicKeyData)
        publicKeyData ?: return

        val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
        val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey

        val result = packetSignature.verify(packetPublicKey, packetList)
        assertTrue(result)
    }

    @Test
    fun verifyEddsaSignatureTest() {
        val publicKeyFile =
            File(
                file.absolutePath,
                "413520773B53EF3E51577B7F2182AE8BEED4CBC0_eddsa_publickey_armored.gpg"
            )
        val publicKeyPgpData = PgpData.load(publicKeyFile)

        val signatureData =
            File(
                file.absolutePath,
                "hello_txt_signed_by_413520773B53EF3E51577B7F2182AE8BEED4CBC0.gpg"
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
        assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY, packetSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_512, packetSignature.hashAlgorithm)

        val signature = packetSignature.signature
        assertNotNull(signature)
        signature ?: return

        val publicKeyData = publicKeyPgpData.blockList[0].data
        assertNotNull(publicKeyData)
        publicKeyData ?: return

        val publicKeyPacketList = PacketDecoder.decode(publicKeyData)
        val packetPublicKey = publicKeyPacketList.first { it is PacketPublicKey } as PacketPublicKey

        val result = packetSignature.verify(packetPublicKey, packetList)
        assertTrue(result)
    }
}
