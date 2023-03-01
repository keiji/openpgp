package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.packet.publickey.PublicKeyEcdsa
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.InvalidParameterException
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

private const val ALGORITHM_EC = "EC"

fun PublicKeyEcdsa.toNativePublicKey(): PublicKey {
    val ellipticCurveParameterSnapshot =
        ellipticCurveParameter ?: throw InvalidParameterException("ellipticCurveParameter must not be null.")

    val ecPoint = ECPoint(
        BigInteger(+1, ecPointX),
        BigInteger(+1, ecPointY)
    )

    val parameterSpec = ECGenParameterSpec(ellipticCurveParameterSnapshot.stdName)
    val parameters = AlgorithmParameters.getInstance(ALGORITHM_EC).also {
        it.init(parameterSpec)
    }
    val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
    val publicKeySpec = ECPublicKeySpec(ecPoint, ecParameters)

    return KeyFactory.getInstance(ALGORITHM_EC).generatePublic(publicKeySpec)
}
