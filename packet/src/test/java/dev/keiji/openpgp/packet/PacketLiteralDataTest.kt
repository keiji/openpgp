package dev.keiji.openpgp.packet

import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.*

class PacketLiteralDataTest {

    @Test
    fun testEncodeOldFormat() {
        val expected = "AC15620A73616D706C652E64617463CFE6370102030405"

        val packetLiteralData = PacketLiteralData().also {
            it.format = LiteralDataFormat.Binary
            it.fileName = "sample.dat"
            it.date = 1674569271
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val actual = ByteArrayOutputStream().let {
            packetLiteralData.writeTo(true, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testEncodeNewFormat() {
        val expected = "CB15620A73616D706C652E64617463CFE6370102030405"

        val packetLiteralData = PacketLiteralData().also {
            it.format = LiteralDataFormat.Binary
            it.fileName = "sample.dat"
            it.date = 1674569271
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val actual = ByteArrayOutputStream().let {
            packetLiteralData.writeTo(false, it)
            it.toByteArray()
        }

        assertEquals(
            expected,
            actual.toHex("")
        )
    }

    @Test
    fun testDecodeOldFormat() {
        val data = parseHexString("AC15620A73616D706C652E64617463CFE6370102030405")

        val expected = PacketLiteralData().also {
            it.format = LiteralDataFormat.Binary
            it.fileName = "sample.dat"
            it.date = 1674569271
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }

    @Test
    fun testDecodeNewFormat() {
        val data = parseHexString("CB15620A73616D706C652E64617463CFE6370102030405")

        val expected = PacketLiteralData().also {
            it.format = LiteralDataFormat.Binary
            it.fileName = "sample.dat"
            it.date = 1674569271
            it.values = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        }

        val packetList = PacketDecoder.decode(ByteArrayInputStream(data))
        val actual = packetList[0]

        assertTrue(actual == expected)
    }
}