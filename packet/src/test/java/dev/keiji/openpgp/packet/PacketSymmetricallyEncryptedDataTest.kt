package dev.keiji.openpgp.packet

import dev.keiji.openpgp.ObsoletePacketDetectedException
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

@Suppress("DEPRECATION")
class PacketSymmetricallyEncryptedDataTest {

    @Test
    fun testEncodeOldFormat() {
        val expected = ""

        val packetSymmetricallyEncryptedData = PacketSymmetricallyEncryptedData().also {
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val actual = ByteArrayOutputStream().let {
            packetSymmetricallyEncryptedData.writeTo(true, it)
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

        val packetSymmetricallyEncryptedData = PacketSymmetricallyEncryptedData().also {
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val actual = ByteArrayOutputStream().let {
            packetSymmetricallyEncryptedData.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeOldFormat() {
        try {
            val data = parseHexString("A4050102030405")
            PacketDecoder.decode(ByteArrayInputStream(data))
            fail("")
        } catch (exception: ObsoletePacketDetectedException) {
            println(exception.message)
        }
    }

    @Test
    fun testDecodeNewFormat() {
        try {
            val data = parseHexString("C9050102030405")
            PacketDecoder.decode(ByteArrayInputStream(data))
            fail("")
        } catch (exception: ObsoletePacketDetectedException) {
            println(exception.message)
        }
    }
}
