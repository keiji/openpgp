package dev.keiji.openpgp.packet

import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.InvalidParameterException

class PacketPaddingTest {

    @Test
    fun testEncodeOldFormat() {
        val packetPadding = PacketPadding().also {
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        try {
            ByteArrayOutputStream().let {
                packetPadding.writeTo(true, it)
            }
            fail("")
        } catch (exception: InvalidParameterException) {
            println(exception.message)
        }
    }

    @Test
    fun testEncodeNewFormat() {
        val expected = "D50401020304"

        val packetPadding = PacketPadding().also {
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        val actual = ByteArrayOutputStream().let {
            packetPadding.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeNewFormat() {
        val data = parseHexString("D50401020304")

        val expected = PacketPadding().also {
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }
}
