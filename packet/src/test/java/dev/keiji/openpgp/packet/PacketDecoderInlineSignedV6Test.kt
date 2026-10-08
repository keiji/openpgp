package dev.keiji.openpgp.packet

import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.signature.PacketSignatureV6
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * RFC 9580 Appendix A.7: Sample Inline-Signed Message.
 */
class PacketDecoderInlineSignedV6Test {

    private fun loadPackets(): List<Packet> {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(
                ARMORED_INLINE_SIGNED_V6.toByteArray(charset = StandardCharsets.UTF_8)
            )
        )
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        return PacketDecoder.decode(data ?: return emptyList())
    }

    @Test
    fun decodeInlineSignedMessageTest() {
        val packetList = loadPackets()

        // One-Pass Signature (v6) + Literal Data + version 6 Signature.
        assertEquals(3, packetList.size)
        assertEquals(Tag.OnePassSignature, packetList[0].tag)
        assertEquals(Tag.LiteralData, packetList[1].tag)
        assertEquals(Tag.Signature, packetList[2].tag)

        val literalDataPacket = packetList[1] as PacketLiteralData
        assertEquals(
            "What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n",
            String(literalDataPacket.values, charset = StandardCharsets.UTF_8)
        )

        val signaturePacket = packetList[2]
        assertTrue(signaturePacket is PacketSignatureV6)
        if (signaturePacket is PacketSignatureV6) {
            assertEquals(6, signaturePacket.version)
            assertEquals(SignatureType.CanonicalTextDocument, signaturePacket.signatureType)
        }
    }

    @Test
    fun encodeInlineSignedMessageRoundTripTest() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(
                ARMORED_INLINE_SIGNED_V6.toByteArray(charset = StandardCharsets.UTF_8)
            )
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
