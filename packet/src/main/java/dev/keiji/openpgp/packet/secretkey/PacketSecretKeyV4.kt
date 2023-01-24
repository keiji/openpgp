package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedS2KUsageTypeException
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.secretkey.s2k.String2Key
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyParser
import dev.keiji.openpgp.toByteArray
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

open class PacketSecretKeyV4 : PacketPublicKeyV4() {
    override val tagValue: Int = Tag.SecretKey.value

    var string2keyUsage: SecretKeyEncryptionType = SecretKeyEncryptionType.ClearText

    var symmetricKeyEncryptionAlgorithm: SymmetricKeyAlgorithm? = null
    var aeadAlgorithm: AeadAlgorithm? = null

    var string2Key: String2Key? = null

    var initializationVector: ByteArray? = null

    var data: ByteArray? = null

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val string2keyUsageByte = inputStream.read()
        string2keyUsage = SecretKeyEncryptionType.findBy(string2keyUsageByte)
            ?: throw UnsupportedS2KUsageTypeException("S2KUsageType $string2keyUsageByte is not supported.")

        when (string2keyUsage) {
            SecretKeyEncryptionType.ClearText -> {
                // Do nothing
            }
            SecretKeyEncryptionType.CheckSum -> {
                val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
                symmetricKeyEncryptionAlgorithm =
                    SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)
                string2Key = String2KeyParser.parse(inputStream)
            }
            SecretKeyEncryptionType.SHA1 -> {
                val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
                symmetricKeyEncryptionAlgorithm =
                    SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)
                string2Key = String2KeyParser.parse(inputStream)
            }
            SecretKeyEncryptionType.AEAD -> {
                val symmetricKeyEncryptionAlgorithmByte = inputStream.read()
                symmetricKeyEncryptionAlgorithm =
                    SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)

                val aeadAlgorithmByte = inputStream.read()
                aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte)
            }
            else -> {
                // Known symmetric cipher algo ID
            }
        }

        initializationVector = ByteArray(8).also {
            inputStream.read(it)
        }

        data = inputStream.readBytes()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val dataSnapshot =
            data ?: throw InvalidParameterException("Parameter `data` must not be null.")
        super.writeContentTo(outputStream)

        outputStream.write(string2keyUsage.id)
        symmetricKeyEncryptionAlgorithm?.also {
            outputStream.write(it.id)
        }
        aeadAlgorithm?.also {
            outputStream.write(it.id)
            val initializationVectorLength = initializationVector?.size ?: 0
            outputStream.write(initializationVectorLength.toByteArray())
        }
        string2Key?.writeTo(outputStream)
        outputStream.write(dataSnapshot)
    }
}
