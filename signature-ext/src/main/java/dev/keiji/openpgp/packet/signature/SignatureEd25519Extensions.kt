package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.packet.Utils
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PublicKeyEd25519
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.InvalidParameterException

fun SignatureEd25519.verify(
    packetPublicKey: PacketPublicKey,
    hashAlgorithm: HashAlgorithm,
    contentBytes: ByteArray,
): Boolean {
    val publicKey = packetPublicKey.publicKey
    if (publicKey !is PublicKeyEd25519) {
        return false
    }

    val nativePublicKeyBytes = publicKey.nativePublicKey
        ?: throw InvalidParameterException("parameter `nativePublicKey` must not be null")

    // An Ed25519 signature MUST use a hash algorithm with a digest size
    // of at least 256 bits.
    when (hashAlgorithm) {
        HashAlgorithm.SHA2_256,
        HashAlgorithm.SHA3_256,
        HashAlgorithm.SHA2_384,
        HashAlgorithm.SHA2_512,
        HashAlgorithm.SHA3_512,
        -> Unit

        else -> throw UnsupportedAlgorithmException(
            "HashAlgorithm ${hashAlgorithm.textName} is too small for Ed25519."
        )
    }

    val nativePublicKey = Ed25519PublicKeyParameters(nativePublicKeyBytes)

    val hashBytes = Utils.createHashBytes(hashAlgorithm, contentBytes)

    val sign = Ed25519Signer().also {
        it.init(false, nativePublicKey)
        it.update(hashBytes, 0, hashBytes.size)
    }
    return sign.verifySignature(nativeSignature)
}
