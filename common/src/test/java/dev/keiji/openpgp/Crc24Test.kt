package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

class Crc24Test {

    @Test
    fun test1() {
        val crc24 = Crc24()

        val data = "Hello CRC24".toByteArray(charset = StandardCharsets.US_ASCII)
        val expected = Crc24.to3ByteArray(0x25259C)

        crc24.update(ByteArrayInputStream(data))
        val actual = crc24.value

        assertEquals(
            expected.toHex(),
            actual.toHex(),
        )
    }

    @Test
    fun test2() {
        val crc24 = Crc24()

        val data = "Hello CRC24".toByteArray(charset = StandardCharsets.US_ASCII)
        val expected = Crc24.to3ByteArray(0x25259C)

        data.forEach {
            crc24.update(it)
        }
        val actual = crc24.value

        assertEquals(
            expected.toHex(),
            actual.toHex(),
        )
    }

    @Test
    fun testReset() {
        val crc24 = Crc24()

        val data = "Hello CRC24".toByteArray(charset = StandardCharsets.US_ASCII)
        val expected = Crc24.to3ByteArray(Crc24.RFC4880_INITIAL)

        crc24.update(ByteArrayInputStream(data))
        crc24.reset()

        val actual = crc24.value

        assertEquals(
            expected.toHex(),
            actual.toHex(),
        )
    }
}
