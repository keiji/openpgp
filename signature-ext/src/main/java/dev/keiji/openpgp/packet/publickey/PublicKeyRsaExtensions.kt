package dev.keiji.openpgp.packet.publickey

import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec

private const val ALGORITHM_RSA = "RSA"

fun PublicKeyRsa.toNativePublicKey(): PublicKey {
    val publicKeySpec = RSAPublicKeySpec(BigInteger(+1, n), BigInteger(+1, e))

    val keyFactory = KeyFactory.getInstance(ALGORITHM_RSA)
    return keyFactory.generatePublic(publicKeySpec)
}
