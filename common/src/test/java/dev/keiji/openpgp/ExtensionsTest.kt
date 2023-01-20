package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ExtensionsTest {
    @Test
    fun intTo2ByteArrayTest1() {
        val data = 0x020F
        val expected = byteArrayOf(0x02, 0x0F)

        val actual = data.to2ByteArray()
        assertArrayEquals(expected, actual)

        val reversed = actual.toInt()
        assertEquals(data, reversed)

    }

    @Test
    fun intTo2ByteArrayTest2() {
        val data = 0xFFFF
        val expected = byteArrayOf(0xFF.toByte(), 0xFF.toByte())

        val actual = 0xFFFF.to2ByteArray()
        assertArrayEquals(expected, actual)

        val reversed = actual.toInt()
        assertEquals(data, reversed)
    }

    @Test
    fun intToByteArray() {
        val data = 1987999990

        val actual = data.toByteArray()
        val reversed = actual.toInt()

        assertEquals(data, reversed)
    }

    @Test
    fun intTo2ByteArray() {
        val data = 0xFFFF

        val actual = data.toByteArray()
        val reversed = actual.toInt()

        assertEquals(data, reversed)
    }

    @Test
    fun longTo2ByteArray() {
        val data: Long = Long.MAX_VALUE

        val actual = data.toByteArray()
        val reversed = actual.toLong()

        assertEquals(data, reversed)
    }
}