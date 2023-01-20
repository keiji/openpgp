package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.OpenPgpAlgorithm
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class RevocationKey : Subpacket() {
    override val typeValue: Int = SubpacketType.RevocationKey.value

    var revocationClass: Int = -1
    var publicKeyAlgorithm: OpenPgpAlgorithm? = null

    var fingerprint: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        revocationClass = inputStream.read()
        publicKeyAlgorithm = OpenPgpAlgorithm.findById(inputStream.read())
        fingerprint = inputStream.readBytes()
    }

    override fun writeTo(outputStream: OutputStream) {
        val publicKeyAlgorithmSnapshot =
            publicKeyAlgorithm ?: throw InvalidParameterException("`publicKeyAlgorithm` must not be null.")

        outputStream.write(revocationClass)
        outputStream.write(publicKeyAlgorithmSnapshot.id)
        outputStream.write(fingerprint)
    }

    override fun toDebugString(): String {
        return " * RevocationKey\n" +
                "   * revocationClass: $revocationClass\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm?.name}\n" +
                "   * fingerprint: ${fingerprint.toHex("")}\n" +
                ""
    }
}
