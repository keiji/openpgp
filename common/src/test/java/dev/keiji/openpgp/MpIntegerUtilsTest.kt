package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StreamCorruptedException
import java.math.BigInteger

class MpIntegerUtilsTest {

    @Test
    fun readFromTest1() {
        val data = "00:FE:" +
                "3B:89:F7:FD:AB:CB:9F:17:57:23:BB:AE:BD:C9:82:4E:BA:05:8F:71:37:DE:98:C4:24:28:4F:CC:8D:13:99:F9:" +
                "01:00:" +
                "DF:9A:C4:C4:99:EF:87:24:ED:30:56:37:AE:03:82:A9:1B:50:4A:61:30:26:6A:1C:43:93:56:EF:F7:99:5A:E1"
        val dataBytes = parseHexString(data, delimiter = ":")
        val bais = ByteArrayInputStream(dataBytes)

        val actual1 = MpIntegerUtils.readFrom(bais)
        assertNotNull(actual1)
        actual1 ?: return
        assertEquals(
            "3B:89:F7:FD:AB:CB:9F:17:57:23:BB:AE:BD:C9:82:4E:BA:05:8F:71:37:DE:98:C4:24:28:4F:CC:8D:13:99:F9",
            actual1.toHex(":")
        )

        val actual2 = MpIntegerUtils.readFrom(bais)
        assertNotNull(actual2)
        actual2 ?: return
        assertEquals(
            "DF:9A:C4:C4:99:EF:87:24:ED:30:56:37:AE:03:82:A9:1B:50:4A:61:30:26:6A:1C:43:93:56:EF:F7:99:5A:E1",
            actual2.toHex(":")
        )

        val actual3 = MpIntegerUtils.readFrom(bais)
        assertNull(actual3)
    }

    @Test
    fun readFromExceptionTest1() {
        val data = "00:09:01"
        val dataBytes = parseHexString(data, delimiter = ":")
        val bais = ByteArrayInputStream(dataBytes)

        try {
            MpIntegerUtils.readFrom(bais)
            fail()
        } catch (exception: StreamCorruptedException) {
            println(exception.message)
        }
    }

    @Test
    fun writeToTest1() {
        val data = BigInteger.valueOf(0x100)
        val dataBytes = data.toByteArray()
        val baos = ByteArrayOutputStream()

        MpIntegerUtils.writeTo(dataBytes, baos)

        val actual = baos.toByteArray()
        assertArrayEquals(
            byteArrayOf(0x00, 0x09, 0x01, 0x00),
            actual
        )
    }

    @Test
    fun writeToTest2() {
        val data = BigInteger.valueOf(65537)
        val dataBytes = data.toByteArray()
        val baos = ByteArrayOutputStream()

        MpIntegerUtils.writeTo(dataBytes, baos)

        val actual = baos.toByteArray()
        assertArrayEquals(
            byteArrayOf(0x00, 0x11, 0x01, 0x00, 0x01),
            actual
        )
    }

    @Test
    fun writeToTest3() {
        val data = parseHexString(
            "B7:01:D7:2D:4D:09:C2:D8:0C:A3:3B:04:FA:EC:CB:6D:F3:62:77:B6:B4:C8:75:2A:8D:DE:DF:75:99:1D:CA:BD",
            delimiter = ":"
        )
        val expected = parseHexString(
            "01:00:" +
                    "B7:01:D7:2D:4D:09:C2:D8:0C:A3:3B:04:FA:EC:CB:6D:F3:62:77:B6:B4:C8:75:2A:8D:DE:DF:75:99:1D:CA:BD",
            delimiter = ":"
        )
        val baos = ByteArrayOutputStream()

        MpIntegerUtils.writeTo(data, baos)

        val actual = baos.toByteArray()
        assertArrayEquals(expected, actual)
    }
}
