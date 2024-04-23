package dev.keiji.openpgp

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

internal object EcKeyPairUtils {
    private const val ALGORITHM_EC = "EC"

    fun convertKeyPairFromECBigIntAndCurve(
        privateKeyBytes: ByteArray,
        ellipticCurveParameter: EllipticCurveParameter,
    ): Pair<PrivateKey, PublicKey> = convertKeyPairFromECBigIntAndCurve(
        BigInteger(+1, privateKeyBytes),
        ellipticCurveParameter
    )

    private fun convertKeyPairFromECBigIntAndCurve(
        privateKeyValue: BigInteger,
        ellipticCurveParameter: EllipticCurveParameter,
    ): Pair<ECPrivateKey, ECPublicKey> {

        val spec: ECNamedCurveParameterSpec =
            ECNamedCurveTable.getParameterSpec(ellipticCurveParameter.stdName)

        val privateKeySpec = ECPrivateKeySpec(privateKeyValue, spec)
        val keyFactory = KeyFactory.getInstance(ALGORITHM_EC, BouncyCastleProvider())

        val privateKey =
            keyFactory.generatePrivate(privateKeySpec) as org.bouncycastle.jce.interfaces.ECPrivateKey

        /**
         * A public key will be calculated from a private key.
         * https://stackoverflow.com/a/49211667
         */
        val q: ECPoint = spec.g.multiply(privateKey.d)

        val publicKeySpec = ECPublicKeySpec(q, spec)
        val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

        return Pair(privateKey as ECPrivateKey, publicKey)
    }
}
