package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PublicKeyEcdsa
import dev.keiji.openpgp.packet.publickey.toNativePublicKey
import java.io.ByteArrayOutputStream
import java.security.Signature

fun SignatureEcdsa.verify(packetPublicKey: PacketPublicKey, contentHash: ByteArray): Boolean {
    val nativeSignature = toNativeSignature()

    val publicKey = packetPublicKey.publicKey
    if (publicKey is PublicKeyEcdsa) {
        val nativePublicKey = publicKey.toNativePublicKey()

        val sign = Signature.getInstance("NoneWithECDSA").also {
            it.initVerify(nativePublicKey)
            it.update(contentHash)
        }
        return sign.verify(nativeSignature)
    }

    return false
}

fun SignatureEcdsa.toNativeSignature(): ByteArray? {
    val rSnapshot = r ?: return null
    val sSnapshot = s ?: return null

    val rLength = rSnapshot.size
    val sLength = sSnapshot.size

    val length = 1 + 1 + rLength + 1 + 1 + sLength

    return ByteArrayOutputStream().let {
        it.write(0x30)
        it.write(length)

        it.write(0x02)
        it.write(rLength)
        it.write(rSnapshot)

        it.write(0x02)
        it.write(sLength)
        it.write(sSnapshot)

        it.toByteArray()
    }
}
