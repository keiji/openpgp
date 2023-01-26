package dev.keiji.openpgp.packet

import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PacketCompressedDataTest {

    @Test
    fun testEncodeOldFormat() {
        val expected = "A0050101020304"

        val packetCompressedData = PacketCompressedData().also {
            it.compressionAlgorithm = CompressionAlgorithm.ZIP
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        val actual = ByteArrayOutputStream().let {
            packetCompressedData.writeTo(true, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testEncodeNewFormat() {
        val expected = "C8050101020304"

        val packetCompressedData = PacketCompressedData().also {
            it.compressionAlgorithm = CompressionAlgorithm.ZIP
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        val actual = ByteArrayOutputStream().let {
            packetCompressedData.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeOldFormat() {
        val data = parseHexString("A0050101020304")

        val expected = PacketCompressedData().also {
            it.compressionAlgorithm = CompressionAlgorithm.ZIP
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }

    @Test
    fun testDecodeNewFormat() {
        val data = parseHexString("C8050101020304")

        val expected = PacketCompressedData().also {
            it.compressionAlgorithm = CompressionAlgorithm.ZIP
            it.data = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }
}
