package dev.keiji.openpgp

import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

private const val FINGERPRINT_V4_1 = "4A760C6B808BD120B36868F5B592C41A51D3BC7D"
private const val CREATION_DATETIME_1 = "64:54:AB:01"
private const val PUBLIC_KEY_1 =
    "A3:83:CC:A9:99:78:B1:B3:12:96:3F:61:B7:A0:49:97:75:B6:0D:22:CE:AF:C5:5A:55:D5:12:EA:82:4B:E5:12"

private const val FINGERPRINT_V4_2 = "70F57FA5415F550B32D6173E86CFC005CF85EB1A"
private const val CREATION_DATETIME_2 = "65:50:F0:22"
private const val PUBLIC_KEY_2 =
    "b3:f0:4f:76:b5:85:62:1e:25:0d:0b:10:bd:8e:16:f4:86:aa:5f:62:ad:35:e2:1c:67:ac:5e:58:ab:2c:4a:1e"

class FingerprintUtilsX25519Test {

    @Test
    fun calcFingerprintX25519V4Test1() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME_1, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY_1, ":")

        val publicKey = X25519PublicKeyParameters(publicKeyBytes)

        val expected = parseHexString(FINGERPRINT_V4_1, delimiter = null)

        val actual = FingerprintUtils.calcV4Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.X25519AlgorithmSpecificField.getInstance(publicKey.encodeToCompressed()),
        )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcFingerprintX25519V4Test2() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME_2, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY_2, ":")

        val publicKey = X25519PublicKeyParameters(publicKeyBytes)

        val expected = parseHexString(FINGERPRINT_V4_2, delimiter = null)

        val actual = FingerprintUtils.calcV4Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.X25519AlgorithmSpecificField.getInstance(publicKey.encodeToCompressed()),
        )

        assertArrayEquals(expected, actual)
    }
}

private fun X25519PublicKeyParameters.encodeToCompressed(): ByteArray {
    return ByteArrayOutputStream().let {

        // The first byte(0x40) indicates an compressed raw format.
        it.write(byteArrayOf(0x40))

        it.write(encoded)

        it.toByteArray()
    }
}
