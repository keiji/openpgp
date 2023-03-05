package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedAlgorithmException
import dev.keiji.openpgp.packet.publickey.PacketPublicKey

fun Signature.verify(packetPublicKey: PacketPublicKey, hashAlgorithm: HashAlgorithm, contentBytes: ByteArray): Boolean {
    return when (this) {
        is SignatureEddsa -> verify(packetPublicKey, hashAlgorithm, contentBytes)
        is SignatureEcdsa -> verify(packetPublicKey, hashAlgorithm, contentBytes)
        is SignatureRsa -> verify(packetPublicKey, hashAlgorithm, contentBytes)
        else -> throw UnsupportedAlgorithmException("")
    }
}
