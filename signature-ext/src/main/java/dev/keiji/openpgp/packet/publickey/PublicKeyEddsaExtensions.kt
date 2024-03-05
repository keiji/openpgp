package dev.keiji.openpgp.packet.publickey

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters

fun PublicKeyEddsa.toBouncycastlePublicKey(): Ed25519PublicKeyParameters {
    @Suppress("MagicNumber")
    val buffer = ecPoint?.copyOfRange(1, 33)
    return Ed25519PublicKeyParameters(buffer)
}
