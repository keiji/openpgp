package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.packet.Utils
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PublicKeyEd448
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed448Signer
import java.security.InvalidParameterException

fun SignatureEd448.verify(
    packetPublicKey: PacketPublicKey,
    hashAlgorithm: HashAlgorithm,
    contentBytes: ByteArray,
): Boolean {
    val publicKey = packetPublicKey.publicKey
    if (publicKey !is PublicKeyEd448) {
        return false
    }

    val nativePublicKeyBytes = publicKey.nativePublicKey
        ?: throw InvalidParameterException("parameter `nativePublicKey` must not be null")

    // An Ed448 signature MUST use a hash algorithm with a digest size
    // of at least 512 bits.
    when (hashAlgorithm) {
        HashAlgorithm.SHA2_512,
        HashAlgorithm.SHA3_512,
        -> Unit

        else -> throw UnsupportedAlgorithmException(
            "HashAlgorithm ${hashAlgorithm.textName} is too small for Ed448."
        )
    }

    val nativePublicKey = Ed448PublicKeyParameters(nativePublicKeyBytes)

    val hashBytes = Utils.createHashBytes(hashAlgorithm, contentBytes)

    // Ed448 is used with the empty string as a context string.
    val sign = Ed448Signer(ByteArray(0)).also {
        it.init(false, nativePublicKey)
        it.update(hashBytes, 0, hashBytes.size)
    }
    return sign.verifySignature(nativeSignature)
}
