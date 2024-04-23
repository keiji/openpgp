@file:Suppress("MaxLineLength")

package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

private const val FINGERPRINT_V4 = "74:A8:1B:71:53:FF:91:D3:5D:04:3D:B5:4E:85:62:D8:B3:5E:46:BA"
private const val FINGERPRINT_V5 =
    "F0:3C:05:1F:23:90:B5:49:88:5A:D5:A3:8B:12:7E:5D:FC:DA:06:BC:9F:BA:0D:88:83:AC:F9:D4:F7:49:1E:B6"

private const val CREATION_DATETIME = "63:56:28:A0"
private const val PUBLIC_EXPONENT_E = "1:00:01"
private const val PRIME1 =
    "C6:5D:C3:36:1C:A9:3E:B9:8E:16:37:86:7E:A5:41:10:14:F0:4F:CB:8A:65:FD:AD:B6:7B:2D:B5:A9:59:88:2F:36:58:83:26:5E:C5:E2:9E:DC:EE:B5:3A:36:C6:A8:F4:94:44:6D:CC:28:3A:7A:08:91:A7:6B:4B:58:BA:A6:A8:43:70:65:0A:BE:0F:6B:D0:F2:00:CB:6E:77:E8:76:7E:E0:A9:31:DA:82:30:AB:8C:C8:92:C0:6C:7E:85:2B:D6:D3:60:2A:FF:19:A9:24:44:85:B2:5D:34:C4:ED:06:C7:32:7E:F0:30:36:EF:AD:9D:D9:EA:0C:50:75:B0:89:BF"
private const val PRIME2 =
    "CA:D4:BD:D3:3E:2E:C2:54:1B:00:EE:E9:3A:6B:22:8F:1A:BA:E1:A5:87:93:3C:4A:6F:3C:C6:36:BB:BE:3A:B6:E3:09:A3:0D:7C:D2:6D:A2:FB:D8:5C:1C:3B:F3:A0:18:46:6A:AD:C2:FF:D7:8D:EF:DB:F4:53:D6:12:93:63:C5:8F:13:09:45:D7:6D:DD:EA:E9:24:CD:2C:06:A1:75:85:F1:A4:89:84:9C:6E:4E:58:87:7E:A7:AB:C9:70:0F:9D:FE:52:F3:40:28:0B:35:91:AE:BE:2B:70:48:D4:21:B0:98:00:73:64:47:87:CB:E5:E8:38:31:2C:5F:5E:44:23"

class FingerprintUtilsRsaTest {

    @Test
    fun calcFingerprintRsaV4Test1() {
        val creationDatetime = parseHexString(CREATION_DATETIME, ":")
        val publicExponentE = parseHexString(PUBLIC_EXPONENT_E, ":")
        val prime1 = parseHexString(PRIME1, ":")
        val prime2 = parseHexString(PRIME2, ":")

        val expected = parseHexString(FINGERPRINT_V4, ":")

        val actual =
            FingerprintUtils.calcV4Fingerprint(
                creationDatetime,
                FingerprintUtils.RsaAlgorithmSpecificField.getInstance(
                    publicExponentE,
                    prime1,
                    prime2,
                )
            )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcFingerprintRsaV5Test1() {
        val creationDatetime = parseHexString(CREATION_DATETIME, ":")
        val publicExponentE = parseHexString(PUBLIC_EXPONENT_E, ":")
        val prime1 = parseHexString(PRIME1, ":")
        val prime2 = parseHexString(PRIME2, ":")

        val expected = parseHexString(FINGERPRINT_V5, ":")

        val actual =
            FingerprintUtils.calcV5Fingerprint(
                creationDatetime,
                FingerprintUtils.RsaAlgorithmSpecificField.getInstance(
                    publicExponentE,
                    prime1,
                    prime2,
                )
            )

        assertArrayEquals(expected, actual)
    }
}
