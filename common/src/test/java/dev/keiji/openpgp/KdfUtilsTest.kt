package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class KdfUtilsTest {

    @Test
    fun iteration1Test() {
        val data = "123456".toByteArray()
        val salt = byteArrayOf(0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x037)
        val expected = parseHexString(
            "77:37:84:A6:02:B6:C8:1E:3F:09:2F:4D:7D:00:E1:7C:C8:22:D8:8F:73:60:FC:F2:D2:EF:2D:9D:90:1F:44:B6",
            ":"
        )

        val result = KdfUtils.iteration(
            data,
            salt,
            100000,
            "SHA-256"
        )
        println(result.toHex(":"))

        assertArrayEquals(expected, result)
    }

    @Test
    fun iteration2Test() {
        val data = "12345678".toByteArray()
        val salt = byteArrayOf(0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x048)
        val expected = parseHexString(
            "26:75:D6:16:4A:0D:48:27:D1:D0:0C:7E:EA:62:0D:01:5C:00:03:0A:1C:AB:38:B4:D0:DD:60:0B:27:DC:96:30",
            ":"
        )

        val result = KdfUtils.iteration(
            data,
            salt,
            100000,
            "SHA-256"
        )
        println(result.toHex(":"))

        assertArrayEquals(expected, result)
    }
}
