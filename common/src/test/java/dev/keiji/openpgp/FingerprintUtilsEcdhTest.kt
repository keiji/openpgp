@file:Suppress("MaxLineLength")

package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.interfaces.ECPublicKey

private const val FINGERPRINT_V4 = "46:07:DC:FF:CB:58:6F:79:BF:CB:FA:1B:B1:ED:1E:E7:03:85:77:49"

private const val CREATION_DATETIME = "64:54:C1:C9"
private const val PRIVATE_KEY =
    "FE:9E:85:71:8C:73:1A:ED:87:57:73:8B:17:0A:57:7F:F2:10:AC:5C:E7:51:7E:8D:05:00:5C:58:74:94:AB:52"
private const val PUBLIC_KEY =
    "04:6D:6F:1E:ED:AF:47:65:23:6B:91:3C:40:5D:03:9E:7A:97:E0:B9:CC:88:FD:1F:84:AA:ED:E7:39:1E:56:C6:92:77:05:ED:BB:36:DD:17:7A:D1:02:7E:F5:AD:FD:00:E6:73:C9:59:58:09:EA:E0:22:22:2B:E6:F0:E0:28:A2:75"

class FingerprintUtilsEcdhTest {

    @Test
    fun calcFingerprintEcdhV4Test1() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME, ":")
        val privateKeyBytes = parseHexString(PRIVATE_KEY, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY, ":")
        val expected = parseHexString(FINGERPRINT_V4, ":")

        val (_, publicKey) = EcKeyPairUtils.convertKeyPairFromECBigIntAndCurve(
            privateKeyBytes,
            EllipticCurveParameter.Secp256r1,
        )

        assertTrue(publicKey is ECPublicKey)
        publicKey as ECPublicKey
        assertArrayEquals(publicKeyBytes, publicKey.encodeToUncompressed())

        val actual = FingerprintUtils.calcV4Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.EcdhAlgorithmSpecificField.getInstance(
                EllipticCurveParameter.Secp256r1,
                publicKey,
            )
        )

        assertArrayEquals(expected, actual)
    }
}
