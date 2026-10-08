package dev.keiji.openpgp.packet

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.signature.PacketSignatureV6
import dev.keiji.openpgp.packet.signature.verify
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.charset.StandardCharsets

/**
 * Signature verification with the test vectors from RFC 9580 Appendix A.
 */
class SignatureV6VerifyTest {
    private val file = File("src/test/resources/rfc9580")

    @Test
    fun verifyDirectKeySelfSignatureTest() {
        // RFC 9580 Appendix A.3: the version 6 Direct Key self-signature
        // of the Ed25519 primary key.
        val packetList = PacketDecoder.decode(
            File(file.absolutePath, "A3_ed25519_x25519_certificate_v6.gpg").readBytes()
        )
        assertEquals(4, packetList.size)

        val primaryKeyPacket = packetList.filterIsInstance<PacketPublicKey>().first()
        assertEquals(PublicKeyAlgorithm.ED25519, primaryKeyPacket.algorithm)

        val directKeySignature = packetList
            .filterIsInstance<PacketSignatureV6>()
            .first { it.signatureType == SignatureType.SignatureDirectlyOnKey }

        assertEquals(PublicKeyAlgorithm.ED25519, directKeySignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_512, directKeySignature.hashAlgorithm)

        val result = directKeySignature.verify(primaryKeyPacket, packetList)
        assertTrue(result)
    }

    @Test
    fun verifySubkeyBindingSignatureTest() {
        // RFC 9580 Appendix A.3: the version 6 Subkey Binding signature
        // over the X25519 subkey.
        val packetList = PacketDecoder.decode(
            File(file.absolutePath, "A3_ed25519_x25519_certificate_v6.gpg").readBytes()
        )
        assertEquals(4, packetList.size)

        val primaryKeyPacket = packetList.filterIsInstance<PacketPublicKey>().first()

        val subkeyBindingSignature = packetList
            .filterIsInstance<PacketSignatureV6>()
            .first { it.signatureType == SignatureType.SubKeyBinding }

        assertEquals(PublicKeyAlgorithm.ED25519, subkeyBindingSignature.publicKeyAlgorithm)
        assertEquals(HashAlgorithm.SHA2_512, subkeyBindingSignature.hashAlgorithm)

        val result = subkeyBindingSignature.verify(primaryKeyPacket, packetList)
        assertTrue(result)
    }

    @Test
    fun verifyInlineSignedMessageTest() {
        // RFC 9580 Appendix A.7: inline-signed message signed by the
        // Ed25519 key from Appendix A.3.
        val certificatePacketList = PacketDecoder.decode(
            File(file.absolutePath, "A3_ed25519_x25519_certificate_v6.gpg").readBytes()
        )
        val primaryKeyPacket = certificatePacketList
            .filterIsInstance<PacketPublicKey>()
            .first()

        val packetList = PacketDecoder.decode(
            File(file.absolutePath, "A7_inline_signed_message_v6.gpg").readBytes()
        )
        // One-Pass Signature (v6) + Literal Data + Signature (v6).
        assertEquals(3, packetList.size)
        assertEquals(dev.keiji.openpgp.packet.Tag.OnePassSignature, packetList[0].tag)
        assertEquals(dev.keiji.openpgp.packet.Tag.LiteralData, packetList[1].tag)
        assertEquals(dev.keiji.openpgp.packet.Tag.Signature, packetList[2].tag)

        val signaturePacket = packetList
            .filterIsInstance<PacketSignatureV6>()
            .first()
        assertEquals(SignatureType.CanonicalTextDocument, signaturePacket.signatureType)
        assertEquals(PublicKeyAlgorithm.ED25519, signaturePacket.publicKeyAlgorithm)

        val result = signaturePacket.verify(primaryKeyPacket, packetList)
        assertTrue(result)
    }

    @Test
    fun verifyCleartextSignedMessageTest() {
        // RFC 9580 Appendix A.6: cleartext signed message that makes use
        // of dash-escaping, signed by the Ed25519 key from Appendix A.3.
        val certificatePacketList = PacketDecoder.decode(
            File(file.absolutePath, "A3_ed25519_x25519_certificate_v6.gpg").readBytes()
        )
        val primaryKeyPacket = certificatePacketList
            .filterIsInstance<PacketPublicKey>()
            .first()

        val cleartextPgpData = PgpData.load(
            File(file.absolutePath, "A6_cleartext_signed_message_v6.gpg")
        )
        assertEquals(PgpData.Type.Cleartext, cleartextPgpData.type)

        val clearText = cleartextPgpData.blockList[0].data
        assertNotNull(clearText)
        clearText ?: return

        // The dash-escaped lines must have been unescaped.
        assertEquals(
            "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n",
            String(clearText, charset = StandardCharsets.UTF_8)
                .replace("\r\n", "\n"),
        )

        val signatureData = cleartextPgpData.blockList[0].blockList[0].data
        assertNotNull(signatureData)
        signatureData ?: return

        val signaturePacketList = PacketDecoder.decode(signatureData)
        val signaturePacket = signaturePacketList
            .filterIsInstance<PacketSignatureV6>()
            .first()
        assertEquals(SignatureType.CanonicalTextDocument, signaturePacket.signatureType)

        val result = signaturePacket.verify(primaryKeyPacket, clearText)
        assertTrue(result)
    }

    @Test
    fun verifyDetachedSignatureOfV6CertificateFailsWithWrongKeyTest() {
        // Verification must fail when the signature is checked against
        // the X25519 subkey instead of the Ed25519 signing key.
        val packetList = PacketDecoder.decode(
            File(file.absolutePath, "A3_ed25519_x25519_certificate_v6.gpg").readBytes()
        )
        val subkeyPacket = packetList.filterIsInstance<PacketPublicKey>().last()

        val directKeySignature = packetList
            .filterIsInstance<PacketSignatureV6>()
            .first { it.signatureType == SignatureType.SignatureDirectlyOnKey }

        val result = directKeySignature.verify(subkeyPacket, packetList)
        assertEquals(false, result)
    }
}
