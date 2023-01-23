package dev.keiji.openpgp.packet

import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PacketMarkerTest {

    @Test
    fun testEncodeOldFormat() {
        val expected = "A803504750"

        val packetMarker = PacketMarker()

        val actual = ByteArrayOutputStream().let {
            packetMarker.writeTo(true, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testEncodeNewFormat() {
        val expected = "CA03504750"

        val packetMarker = PacketMarker()

        val actual = ByteArrayOutputStream().let {
            packetMarker.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeOldFormat() {
        val data = parseHexString("A803504750")

        val expected = PacketMarker()

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }

    @Test
    fun testDecodeNewFormat() {
        val data = parseHexString("CA03504750")

        val expected = PacketMarker()

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }
}