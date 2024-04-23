@file:Suppress("MaxLineLength")

package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import java.math.BigInteger

private const val PUBLIC_EXPONENT_E = "1:00:01"
private const val PRIME1 =
    "C6:5D:C3:36:1C:A9:3E:B9:8E:16:37:86:7E:A5:41:10:14:F0:4F:CB:8A:65:FD:AD:B6:7B:2D:B5:A9:59:88:2F:36:58:83:26:5E:C5:E2:9E:DC:EE:B5:3A:36:C6:A8:F4:94:44:6D:CC:28:3A:7A:08:91:A7:6B:4B:58:BA:A6:A8:43:70:65:0A:BE:0F:6B:D0:F2:00:CB:6E:77:E8:76:7E:E0:A9:31:DA:82:30:AB:8C:C8:92:C0:6C:7E:85:2B:D6:D3:60:2A:FF:19:A9:24:44:85:B2:5D:34:C4:ED:06:C7:32:7E:F0:30:36:EF:AD:9D:D9:EA:0C:50:75:B0:89:BF"

class FingerprintUtilsTest {

    @Test
    fun stripTest1() {
        val data = byteArrayOf(0x00, 0x05, 0x08, 0xA3.toByte())
        val expected = byteArrayOf(0x05, 0x08, 0xA3.toByte())

        val actual = MpIntegerUtils.strip(data)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun stripTest2() {
        val data = byteArrayOf(0x05, 0x08, 0xA3.toByte())
        val expected = byteArrayOf(0x05, 0x08, 0xA3.toByte())

        val actual = MpIntegerUtils.strip(data)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun convertToMpIntegerTest1() {
        val data = parseHexString(PUBLIC_EXPONENT_E, ":")
        val expected = byteArrayOf(
            0, 17, // 00:11 = 17 bit
            *data,
        )

        val actual = MpIntegerUtils.toMpInteger(BigInteger(+1, data))

        assertArrayEquals(expected, actual)
    }

    @Test
    fun convertToMpIntegerTest2() {
        val data = parseHexString(PRIME1, ":")
        val expected = byteArrayOf(
            0x04, 0x00, // 04:00 = 1024 bit
            *data,
        )

        val actual = MpIntegerUtils.toMpInteger(BigInteger(+1, data))

        assertArrayEquals(expected, actual)
    }
}
