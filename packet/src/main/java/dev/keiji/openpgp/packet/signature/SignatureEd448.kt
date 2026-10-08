package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

/**
 * Algorithm-Specific Fields for Ed448 Signatures:
 * 114 octets of the native signature.
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.2.3.5
 */
class SignatureEd448 : Signature() {

    var nativeSignature: ByteArray? = null
        set(value) {
            require(value == null || value.size == NATIVE_OCTET_LENGTH) {
                "nativeSignature length must be $NATIVE_OCTET_LENGTH but ${value?.size}"
            }
            field = value
        }

    override fun readFrom(inputStream: InputStream) {
        nativeSignature = ByteArray(NATIVE_OCTET_LENGTH).also {
            inputStream.read(it)
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        val nativeSignatureSnapshot = nativeSignature
            ?: throw InvalidParameterException("parameter `nativeSignature` must not be null")
        outputStream.write(nativeSignatureSnapshot)
    }

    override fun toDebugString(): String {
        return " * SignatureEd448\n" +
                "   * nativeSignature: ${nativeSignature?.toHex()}\n" +
                ""
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignatureEd448

        return nativeSignature.contentEquals(other.nativeSignature)
    }

    override fun hashCode(): Int {
        return nativeSignature?.contentHashCode() ?: 0
    }

    companion object {
        const val NATIVE_OCTET_LENGTH = 114
    }
}
