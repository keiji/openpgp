package dev.keiji.openpgp.packet

import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PacketTrustTest {

    @Test
    fun testEncodeOldFormat() {
        val expected = ""

        val packetTrust = PacketTrust().also {
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val actual = ByteArrayOutputStream().let {
            packetTrust.writeTo(true, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testEncodeNewFormat() {
        val expected = ""

        val packetTrust = PacketTrust().also {
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val actual = ByteArrayOutputStream().let {
            packetTrust.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeOldFormat() {
        val data = parseHexString("B0050102030405")

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList.isEmpty()

        assertTrue(actual)
    }

    @Test
    fun testDecodeNewFormat() {
        val data = parseHexString("CC050102030405")

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList.isEmpty()

        assertTrue(actual)
    }
}
