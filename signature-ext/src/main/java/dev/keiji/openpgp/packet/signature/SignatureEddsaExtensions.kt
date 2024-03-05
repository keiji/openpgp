package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.packet.Utils
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PublicKeyEddsa
import dev.keiji.openpgp.packet.publickey.toBouncycastlePublicKey
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.ByteArrayOutputStream

fun SignatureEddsa.verify(
    packetPublicKey: PacketPublicKey,
    hashAlgorithm: HashAlgorithm,
    contentBytes: ByteArray,
): Boolean {
    val publicKey = packetPublicKey.publicKey
    if (publicKey is PublicKeyEddsa) {
        val nativePublicKey = publicKey.toBouncycastlePublicKey()

        val hashBytes = Utils.createHashBytes(hashAlgorithm, contentBytes)

        val sign = Ed25519Signer().also {
            it.init(false, nativePublicKey)
            it.update(hashBytes, 0, hashBytes.size)
        }
        return sign.verifySignature(toNativeSignature())
    }

    return false
}

fun SignatureEddsa.toNativeSignature(): ByteArray? {
    val rSnapshot = r ?: return null
    val sSnapshot = s ?: return null

    return ByteArrayOutputStream().let {
        it.write(rSnapshot)
        it.write(sSnapshot)

        it.toByteArray()
    }
}
