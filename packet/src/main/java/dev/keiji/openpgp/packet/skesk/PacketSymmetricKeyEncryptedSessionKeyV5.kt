package dev.keiji.openpgp.packet.skesk

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.secretkey.s2k.String2Key
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyParser
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeySimple
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

class PacketSymmetricKeyEncryptedSessionKeyV5 : PacketSymmetricKeyEncryptedSessionKey() {
    companion object {
        const val VERSION = 5
    }

    override val version: Int = VERSION

    var symmetricKeyAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES256
    var aeadAlgorithm: AeadAlgorithm = AeadAlgorithm.GCM

    var string2Key: String2Key = String2KeySimple()

    var initializationVector: ByteArray? = null

    var encryptedSessionKeyWithTag: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {

        val fieldsBytesLength = inputStream.read()
        val fieldsByteArrayInputStream = ByteArray(fieldsBytesLength).let {
            inputStream.read(it)
            ByteArrayInputStream(it)
        }

        val symmetricKeyAlgorithmByte = fieldsByteArrayInputStream.read()
        symmetricKeyAlgorithm = SymmetricKeyAlgorithm.findBy(symmetricKeyAlgorithmByte)
            ?: throw UnsupportedSymmetricKeyAlgorithmException("symmetricKeyAlgorithm id $symmetricKeyAlgorithmByte is not supported.")
        println(symmetricKeyAlgorithm.id)

        val aeadAlgorithmByte = fieldsByteArrayInputStream.read()
        aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte)
            ?: throw UnsupportedAeadAlgorithmException("aeadAlgorithm ID $aeadAlgorithmByte is not supported")

        val string2KeyFieldLength = fieldsByteArrayInputStream.read()
        val string2KeyFieldStream = ByteArray(string2KeyFieldLength).let {
            fieldsByteArrayInputStream.read(it)
            ByteArrayInputStream(it)
        }
        string2Key = String2KeyParser.parse(string2KeyFieldStream)

        val initializationVectorLength = (fieldsBytesLength
                - 1 // symmetric cipher algorithm identifier
                - 1 // AEAD algorithm identifier
                - 1 // count of the following field
                - string2KeyFieldLength
                )
        initializationVector = ByteArray(initializationVectorLength).also {
            fieldsByteArrayInputStream.read(it)
        }

        encryptedSessionKeyWithTag = inputStream.readBytes()
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(version)

        val string2KeyFieldBytes = ByteArrayOutputStream().let {
            string2Key.writeTo(it)
            it.toByteArray()
        }
        val string2KeyFieldLength = string2KeyFieldBytes.size

        val fieldsBytes = ByteArrayOutputStream().let { baos ->
            baos.write(symmetricKeyAlgorithm.id)
            baos.write(aeadAlgorithm.id)
            baos.write(string2KeyFieldLength)
            baos.write(string2KeyFieldBytes)
            initializationVector?.also { iv ->
                baos.write(iv)
            }
            baos.toByteArray()
        }
        val fieldsBytesLength = fieldsBytes.size

        outputStream.write(fieldsBytesLength)
        outputStream.write(fieldsBytes)

        encryptedSessionKeyWithTag?.also {
            outputStream.write(it)
        }
    }

    override fun toDebugString(): String {
        return " * PacketSymmetricKeyEncryptedSessionKeyV4\n" +
                "   * Version: $version\n" +
                "   * symmetricKeyAlgorithm: ${symmetricKeyAlgorithm.id}\n" +
                "   * aeadAlgorithm: ${string2Key.toDebugString()}\n" +
                "   * initializationVector: ${initializationVector?.toHex()}\n" +
                "   * encryptedSessionKeyWithTag: ${encryptedSessionKeyWithTag?.toHex()}\n" +
                ""
    }
}
