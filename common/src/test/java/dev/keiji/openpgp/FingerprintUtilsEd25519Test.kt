@file:Suppress("MaxLineLength")

package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

private const val CREATION_DATETIME_V4 = "63:81:C3:5F"
private const val PUBLIC_KEY_V4 =
    "79:8E:E8:F9:51:B4:3F:30:8C:4B:5B:29:68:46:78:A0:F2:89:3E:02:15:32:F0:70:B5:B5:C9:4E:1D:01:EE:33"
private const val FINGERPRINT_V4 = "0E:E1:36:52:E9:E9:D0:BF:71:15:A3:C9:A7:1E:2C:A5:7A:C1:F0:9A"

// Test vector from RFC 9580 Appendix A.3 (Sample Version 6 Certificate).
private const val CREATION_DATETIME_V6 = "63:87:7F:E3"
private const val PUBLIC_KEY_V6 =
    "F9:4D:A7:BB:48:D6:0A:61:E5:67:70:6A:65:87:D0:33:19:99:BB:9D:89:1A:08:24:2E:AD:84:54:3D:F8:95:A3"
private const val FINGERPRINT_V6 =
    "CB:18:6C:4F:06:09:A6:97:E4:D5:2D:FA:6C:72:2B:0C:1F:1E:27:C1:8A:56:70:8F:65:25:EC:27:BA:D9:AC:C9"
private const val KEY_ID_V6 = "CB:18:6C:4F:06:09:A6:97"

// Test vector from RFC 9580 Appendix A.3 (Sample Version 6 Certificate, subkey).
private const val SUBKEY_PUBLIC_KEY_V6 =
    "86:93:24:83:67:F9:E5:01:5D:B9:22:F8:F4:80:95:DD:A7:84:98:7F:2D:59:85:B1:2F:BA:D1:6C:AF:5E:44:35"
private const val SUBKEY_FINGERPRINT_V6 =
    "12:C8:3F:1E:70:6F:63:08:FE:15:1A:41:77:43:A1:F0:33:79:0E:93:E9:97:84:88:D1:DB:37:8D:A9:93:08:85"

class FingerprintUtilsEd25519Test {

    @Test
    fun calcFingerprintEd25519LegacyV4Test() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME_V4, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY_V4, ":")
        val publicKeyCompressedPoint =
            byteArrayOf(0x40) + publicKeyBytes

        val expected = parseHexString(FINGERPRINT_V4, ":")

        val actual = FingerprintUtils.calcV4Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.Ed25519AlgorithmSpecificField.getInstance(publicKeyCompressedPoint),
        )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcFingerprintEd25519V6Test() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME_V6, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY_V6, ":")

        val expected = parseHexString(FINGERPRINT_V6, ":")

        val actual = FingerprintUtils.calcV6Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.Ed25519NativeAlgorithmSpecificField.getInstance(publicKeyBytes),
        )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcFingerprintX25519V6Test() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME_V6, ":")
        val subkeyPublicKeyBytes = parseHexString(SUBKEY_PUBLIC_KEY_V6, ":")

        val expected = parseHexString(SUBKEY_FINGERPRINT_V6, ":")

        val actual = FingerprintUtils.calcV6Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.X25519NativeAlgorithmSpecificField.getInstance(subkeyPublicKeyBytes),
        )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcKeyIdV6Test() {
        val fingerprint = parseHexString(FINGERPRINT_V6, ":")

        val expected = parseHexString(KEY_ID_V6, ":")

        // The Key ID is the high-order 64 bits of the fingerprint.
        assertArrayEquals(expected, FingerprintUtils.calcV6KeyId(fingerprint))
    }
}
