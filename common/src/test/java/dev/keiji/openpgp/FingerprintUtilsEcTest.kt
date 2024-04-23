@file:Suppress("MaxLineLength")

package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.security.interfaces.ECPublicKey

private const val FINGERPRINT_V4 = "B5:8E:13:13:C6:91:7B:F9:C9:19:01:D1:54:9E:2A:F2:BE:8A:D6:5C"
private const val FINGERPRINT_V5 =
    "83:FA:09:61:93:0E:52:87:BD:44:0C:7D:1C:F4:8D:A1:ED:09:71:8E:0D:4E:9A:8B:96:A9:F5:16:5D:18:50:14"

private const val CREATION_DATETIME = "63:5C:CD:82"
private const val PRIVATE_KEY =
    "F8:B8:05:30:40:0C:CD:5A:09:75:6A:3C:A0:F6:45:DD:4E:39:C5:B7:FA:4B:6C:5A:DD:66:4C:7A:4A:34:CA:09"
private const val PUBLIC_KEY =
    "04:15:CE:11:9D:F0:0E:99:AD:B3:EB:08:79:DD:C1:50:7A:4B:89:BD:94:CC:89:7D:85:33:3A:CC:BF:63:4C:0F:0A:3A:1A:33:E0:7F:77:A0:20:2A:2C:88:1E:CF:92:96:83:8B:00:93:8F:E4:7B:8C:5C:B8:E7:32:37:59:1D:FA:F0"

class FingerprintUtilsEcTest {

    @Test
    fun calcFingerprintEcV4Test1() {
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
            FingerprintUtils.EcdsaAlgorithmSpecificField.getInstance(
                EllipticCurveParameter.Secp256r1,
                publicKey,
            )
        )

        assertArrayEquals(expected, actual)
    }

    @Test
    fun calcFingerprintEcV5Test1() {
        val creationDatetimeBytes = parseHexString(CREATION_DATETIME, ":")
        val privateKeyBytes = parseHexString(PRIVATE_KEY, ":")
        val publicKeyBytes = parseHexString(PUBLIC_KEY, ":")
        val expected = parseHexString(FINGERPRINT_V5, ":")

        val (_, publicKey) = EcKeyPairUtils.convertKeyPairFromECBigIntAndCurve(
            privateKeyBytes,
            EllipticCurveParameter.Secp256r1,
        )

        assertTrue(publicKey is ECPublicKey)
        publicKey as ECPublicKey
        assertArrayEquals(publicKeyBytes, publicKey.encodeToUncompressed())

        val actual = FingerprintUtils.calcV5Fingerprint(
            creationDatetimeBytes,
            FingerprintUtils.EcdsaAlgorithmSpecificField.getInstance(
                EllipticCurveParameter.Secp256r1,
                publicKey,
            )
        )

        assertArrayEquals(expected, actual)
    }
}
