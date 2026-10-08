package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

/**
 * Algorithm-Specific Part for X25519 Keys.
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.5.5.7
 */
class PublicKeyX25519 : PublicKey() {

    var nativePublicKey: ByteArray? = null
        set(value) {
            require(value == null || value.size == NATIVE_OCTET_LENGTH) {
                "nativePublicKey length must be $NATIVE_OCTET_LENGTH but ${value?.size}"
            }
            field = value
        }

    override fun readFrom(inputStream: InputStream) {
        nativePublicKey = ByteArray(NATIVE_OCTET_LENGTH).also {
            inputStream.read(it)
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        val nativePublicKeySnapshot = nativePublicKey
            ?: throw InvalidParameterException("parameter `nativePublicKey` must not be null")
        outputStream.write(nativePublicKeySnapshot)
    }

    override fun toDebugString(): String {
        return """
 * PublicKey X25519
    * nativePublicKey: ${nativePublicKey?.toHex()}
        """.trimIndent()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyX25519

        return nativePublicKey.contentEquals(other.nativePublicKey)
    }

    override fun hashCode(): Int {
        return nativePublicKey?.contentHashCode() ?: 0
    }

    companion object {
        const val NATIVE_OCTET_LENGTH = 32
    }
}
