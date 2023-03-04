package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import java.security.MessageDigest

fun Signature.verify(packetPublicKey: PacketPublicKey, hashAlgorithm: HashAlgorithm, contentBytes: ByteArray): Boolean {
    return when (this) {
        is SignatureEddsa -> verify(packetPublicKey, hashAlgorithm, contentBytes)
        is SignatureEcdsa -> verify(packetPublicKey, hashAlgorithm, contentBytes)
        is SignatureRsa -> verify(packetPublicKey, hashAlgorithm, contentBytes)
        else -> throw UnsupportedAlgorithmException("")
    }
}

internal fun getMessageDigest(hashAlgorithm: HashAlgorithm): MessageDigest {
    val algorithmName = when (hashAlgorithm) {
        HashAlgorithm.MD5 -> "MD5"
        HashAlgorithm.SHA1 -> "SHA-1"
        HashAlgorithm.SHA2_256 -> "SHA-256"
        else -> throw UnsupportedHashAlgorithmException("hashAlgorithm ${hashAlgorithm.textName} is not supported.")
    }
    return MessageDigest.getInstance(algorithmName)
}

internal fun createHashBytes(hashAlgorithm: HashAlgorithm, contentBytes: ByteArray): ByteArray {
    return getMessageDigest(hashAlgorithm).let {
        it.update(contentBytes)
        it.digest()
    }
}
