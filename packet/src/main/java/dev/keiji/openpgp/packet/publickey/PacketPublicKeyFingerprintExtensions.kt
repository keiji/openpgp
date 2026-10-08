@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.UnsupportedVersionException
import dev.keiji.openpgp.to2ByteArray
import dev.keiji.openpgp.toByteArray
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/**
 * Computes the fingerprint of the key carried by this packet.
 *
 * A version 4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
 * followed by the two-octet packet length, followed by the entire
 * Public Key packet starting with the version field.
 *
 * A version 6 fingerprint is the 256-bit SHA-256 hash of the octet
 * 0x9B, followed by the four-octet packet length, followed by the
 * entire Public Key packet starting with the version field.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.5.4
 */
fun PacketPublicKey.fingerprint(): ByteArray {
    val keyPacketBody = ByteArrayOutputStream().let {
        writeContentTo(it)
        it.toByteArray()
    }

    return when (version) {
        PacketPublicKeyV4.VERSION -> {
            val messageDigest = MessageDigest.getInstance("SHA-1")
            messageDigest.update(0x99.toByte())
            messageDigest.update(keyPacketBody.size.to2ByteArray())
            messageDigest.update(keyPacketBody)
            messageDigest.digest()
        }

        PacketPublicKeyV6.VERSION -> {
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(0x9B.toByte())
            messageDigest.update(keyPacketBody.size.toByteArray())
            messageDigest.update(keyPacketBody)
            messageDigest.digest()
        }

        else -> throw UnsupportedVersionException("Key version $version is not supported.")
    }
}

/**
 * Computes the Key ID of the key carried by this packet.
 *
 * For a version 4 key, the Key ID is the low-order 64 bits of the
 * fingerprint. For a version 6 key, the Key ID is the high-order
 * 64 bits of the fingerprint.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.5.4
 */
fun PacketPublicKey.keyId(): ByteArray {
    val fingerprint = fingerprint()
    return when (version) {
        PacketPublicKeyV4.VERSION -> fingerprint.copyOfRange(
            fingerprint.size - Long.SIZE_BYTES,
            fingerprint.size,
        )

        PacketPublicKeyV6.VERSION -> fingerprint.copyOfRange(0, Long.SIZE_BYTES)

        else -> throw UnsupportedVersionException("Key version $version is not supported.")
    }
}
