package dev.keiji.openpgp.packet.skesk

import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.packet.secretkey.s2k.String2Key
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyParser
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeySimple
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PacketSymmetricKeyEncryptedSessionKeyV4 : PacketSymmetricKeyEncryptedSessionKey() {
    companion object {
        const val VERSION = 3
    }

    override val version: Int = VERSION

    var symmetricKeyAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES256

    var string2Key: String2Key = String2KeySimple()

    var encryptedSessionKey: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        val symmetricKeyAlgorithmByte = inputStream.read()
        symmetricKeyAlgorithm = SymmetricKeyAlgorithm.findBy(symmetricKeyAlgorithmByte)
            ?: throw UnsupportedSymmetricKeyAlgorithmException("symmetricKeyAlgorithm id $symmetricKeyAlgorithmByte is not supported.")

        string2Key = String2KeyParser.parse(inputStream)

        encryptedSessionKey = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val encryptedSessionKeySnapshot = encryptedSessionKey
            ?: throw InvalidParameterException("`encryptedSessionKey` must not be null.")

        outputStream.write(version)
        outputStream.write(symmetricKeyAlgorithm.id)
        string2Key.writeTo(outputStream)
        outputStream.write(encryptedSessionKeySnapshot)
    }

    override fun toDebugString(): String {
        return " * PacketSymmetricKeyEncryptedSessionKeyV4\n" +
                "   * Version: $version\n" +
                "   * symmetricKeyAlgorithm: ${symmetricKeyAlgorithm.name}\n" +
                "   * aeadAlgorithm: ${string2Key.toDebugString()}\n" +
                "   * encryptedSessionKey: ${encryptedSessionKey?.toHex()}\n" +
                ""
    }
}
