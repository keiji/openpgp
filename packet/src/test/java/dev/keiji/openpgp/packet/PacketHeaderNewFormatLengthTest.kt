package dev.keiji.openpgp.packet

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayInputStream
import java.math.BigInteger

class PacketHeaderNewFormatLengthTest {

    @Test
    fun encodeNewPacketLengthTest0() {
        val data = BigInteger.ZERO
        val expected = byteArrayOf(0x00)
        val actual = PacketHeader.encodeNewPacketLength(data)
        assertArrayEquals(expected, actual)
    }

    @Test
    fun encodeNewPacketLengthTest191() {
        val data = BigInteger.valueOf(191)
        val expected = byteArrayOf(191.toByte())
        val actual = PacketHeader.encodeNewPacketLength(data)
        assertArrayEquals(expected, actual)
    }

    @Test
    fun encodeNewPacketLengthTest192() {
        val data = BigInteger.valueOf(192)

        val expected = byteArrayOf(192.toByte(), 0x00)
        val actual = PacketHeader.encodeNewPacketLength(data)

        // It is recognized because its first octet is in the range 192 to 223.
        assertEquals(192.toByte(), actual[0])
        assertArrayEquals(expected, actual)
    }

    @Test
    fun encodeNewPacketLengthTest8383() {
        val data = BigInteger.valueOf(8383)

        val expected = byteArrayOf(0b11_011111.toByte(), 0xFF.toByte())
        val actual = PacketHeader.encodeNewPacketLength(data)

        // It is recognized because its first octet is in the range 192 to 223.
        assertEquals(223.toByte(), actual[0])
        assertArrayEquals(expected, actual)
    }

    @Test
    fun encodeNewPacketLengthTest8384() {
        val data = BigInteger.valueOf(8384)

        val expected = byteArrayOf(0xFF.toByte(), 0x00, 0x00, 0x20, 0xC0.toByte())
        val actual = PacketHeader.encodeNewPacketLength(data)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun encodeNewPacketLengthTest4294967295() {
        val data = BigInteger.valueOf(4294967295)

        // A five-octet Body Length header encodes packet lengths of up to 4,294,967,295 (0xFFFFFFFF) octets in length.
        val expected =
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        val actual = PacketHeader.encodeNewPacketLength(data)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun encodeNewPacketLengthTest4294967296() {
        val data = BigInteger.valueOf(4294967296)

        try {
            // Partial Body Length is not supported.
            PacketHeader.encodeNewPacketLength(data)
            fail("")
        } catch (exception: UnsupportedOperationException) {
            println(exception.message)
        }
    }

    @Test
    fun decodeNewPacketLengthTest0() {
        val data = byteArrayOf(0x00)
        val expected = BigInteger.ZERO

        val bais = ByteArrayInputStream(data)
        val actual = PacketHeader.decodeNewPacketLength(bais)

        assertEquals(expected, actual)
    }

    @Test
    fun decodeNewPacketLengthTest191() {
        val data = byteArrayOf(191.toByte())
        val expected = BigInteger.valueOf(191)

        val bais = ByteArrayInputStream(data)
        val actual = PacketHeader.decodeNewPacketLength(bais)

        assertEquals(expected, actual)
    }

    @Test
    fun decodeNewPacketLengthTest192() {
        val data = byteArrayOf(192.toByte(), 0x00)
        val expected = BigInteger.valueOf(192)

        val bais = ByteArrayInputStream(data)
        val actual = PacketHeader.decodeNewPacketLength(bais)

        assertEquals(expected, actual)
    }

    @Test
    fun decodeNewPacketLengthTest8383() {
        val data = byteArrayOf(0b11_011111.toByte(), 0xFF.toByte())
        val expected = BigInteger.valueOf(8383)

        val bais = ByteArrayInputStream(data)
        val actual = PacketHeader.decodeNewPacketLength(bais)

        assertEquals(expected, actual)
    }

    @Test
    fun decodeNewPacketLengthTest8384() {
        val data = byteArrayOf(0xFF.toByte(), 0x00, 0x00, 0x20, 0xC0.toByte())
        val expected = BigInteger.valueOf(8384)

        val bais = ByteArrayInputStream(data)
        val actual = PacketHeader.decodeNewPacketLength(bais)

        assertEquals(expected, actual)
    }

    @Test
    fun decodeNewPacketLengthTest4294967295() {
        val data =
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        val expected = BigInteger.valueOf(4294967295)

        val bais = ByteArrayInputStream(data)
        val actual = PacketHeader.decodeNewPacketLength(bais)

        assertEquals(expected, actual)
    }

    @Test
    fun decodeNewPacketLengthTestPartialNotSupported() {
        (224 until 255).forEach {
            val values = byteArrayOf(it.toByte())
            val bais = ByteArrayInputStream(values)

            try {
                PacketHeader.decodeNewPacketLength(bais)
                fail("")
            } catch (exception: UnsupportedOperationException) {
                println(exception.message)
            }
        }
    }

//    @Test
    fun encodeDecodeNewPacketLengthTest() {
        (0..4294967295).forEach {
            val data = BigInteger.valueOf(it)
            val encoded = PacketHeader.encodeNewPacketLength(data)
            val decoded = PacketHeader.decodeNewPacketLength(ByteArrayInputStream(encoded))
            assertEquals(data, decoded)
        }
    }
}
