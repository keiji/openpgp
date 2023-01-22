package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.OpenPgpAlgorithm
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class SignatureTarget : Subpacket() {
    override val typeValue: Int = SubpacketType.SignatureTarget.value

    var publicKeyAlgorithm: OpenPgpAlgorithm? = null
    var hashAlgorithm: HashAlgorithm? = null
    var hash: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        publicKeyAlgorithm = OpenPgpAlgorithm.findById(inputStream.read())
        hashAlgorithm = HashAlgorithm.findBy(inputStream.read())
        hash = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val publicKeyAlgorithmSnapshot =
            publicKeyAlgorithm ?: throw InvalidParameterException("`publicKeyAlgorithm` must not be null.")
        val hashAlgorithmSnapshot =
            hashAlgorithm ?: throw InvalidParameterException("`hashAlgorithm` must not be null.")

        outputStream.write(publicKeyAlgorithmSnapshot.id)
        outputStream.write(hashAlgorithmSnapshot.id)
        outputStream.write(hash)
    }

    override fun toDebugString(): String {
        return " * SignersUserId\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm?.name}\n" +
                "   * hashAlgorithm: ${hashAlgorithm?.name}\n" +
                "   * hash: ${hash.toHex("")}\n" +
                ""
    }
}
