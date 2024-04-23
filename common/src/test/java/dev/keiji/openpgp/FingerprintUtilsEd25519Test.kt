package dev.keiji.openpgp

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

private const val FINGERPRINT_V4 = "0E:E1:36:52:E9:E9:D0:BF:71:15:A3:C9:A7:1E:2C:A5:7A:C1:F0:9A"
private const val FINGERPRINT_V5 =
    "8F:DC:6C:F3:CB:73:FD:6B:8D:2A:DE:DF:35:6E:55:D8:12:E3:DF:2F:F7:8E:A2:30:40:BE:B6:4B:12:40:9B:8B"

private const val CREATION_DATETIME = "63:81:C3:5F"
private const val PUBLIC_KEY =
    "79:8E:E8:F9:51:B4:3F:30:8C:4B:5B:29:68:46:78:A0:F2:89:3E:02:15:32:F0:70:B5:B5:C9:4E:1D:01:EE:33"

class FingerprintUtilsEd25519Test {

    @Test
    fun calcFingerprintEd25519V4Test1() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY, ":")

        val publicKey = Ed25519PublicKeyParameters(publicKeyBytes)

        val expected = parseHexString(FINGERPRINT_V4, ":")

        val actual = FingerprintUtils.calcV4Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.Ed25519AlgorithmSpecificField.getInstance(publicKey.encodeToCompressed()),
        )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcFingerprintEd25519V5Test1() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY, ":")

        val publicKey = Ed25519PublicKeyParameters(publicKeyBytes)

        val expected = parseHexString(FINGERPRINT_V5, ":")

        val actual = FingerprintUtils.calcV5Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.Ed25519AlgorithmSpecificField.getInstance(publicKey.encodeToCompressed()),
        )

        assertArrayEquals(expected, actual)
    }
}

private fun Ed25519PublicKeyParameters.encodeToCompressed(): ByteArray {
    return ByteArrayOutputStream().let {

        // The first byte(0x40) indicates an compressed raw format.
        it.write(byteArrayOf(0x40))

        it.write(encoded)

        it.toByteArray()
    }
}
