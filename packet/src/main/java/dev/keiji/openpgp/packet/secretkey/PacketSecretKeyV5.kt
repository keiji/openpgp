package dev.keiji.openpgp.packet.secretkey

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV5
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.secretkey.s2k.String2Key
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyParser
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

open class PacketSecretKeyV5 : PacketPublicKeyV5() {
    override val tagValue: Int = Tag.SecretKey.value

    var string2keyUsage: SecretKeyEncryptionType = SecretKeyEncryptionType.ClearText

    var symmetricKeyEncryptionAlgorithm: SymmetricKeyAlgorithm? = null

    var aeadAlgorithm: AeadAlgorithm? = null

    var string2Key: String2Key? = null

    var initializationVector: ByteArray? = null
    var nonce: ByteArray? = null

    var data: ByteArray = byteArrayOf()

    var checkSum: ByteArray? = null

    override fun readContentFrom(inputStream: InputStream) {
        super.readContentFrom(inputStream)

        val string2keyUsageByte = inputStream.read()
        string2keyUsage = SecretKeyEncryptionType.findBy(string2keyUsageByte)
            ?: throw UnsupportedS2KUsageTypeException("S2KUsageType ${string2keyUsageByte} is not supported.")

        val optionalFieldsLength = inputStream.read()
        val optionalFieldsInputStream = ByteArray(optionalFieldsLength).let {
            inputStream.read(it)
            ByteArrayInputStream(it)
        }

        if (string2keyUsage == SecretKeyEncryptionType.ClearText) {
            // Do nothing
        } else {
            when (string2keyUsage) {
                SecretKeyEncryptionType.CheckSum -> {
                    throw UnsupportedS2KUsageTypeException("SecretKey version 5 format MUST NOT use the CheckSum")
                }

                SecretKeyEncryptionType.SHA1 -> {
                    val symmetricKeyEncryptionAlgorithmByte = optionalFieldsInputStream.read()
                    symmetricKeyEncryptionAlgorithm =
                        SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)

                    val string2KeyFieldLength = optionalFieldsInputStream.read()
                    val string2KeyInputStream = ByteArray(string2KeyFieldLength).let {
                        optionalFieldsInputStream.read(it)
                        ByteArrayInputStream(it)
                    }
                    string2Key = String2KeyParser.parse(string2KeyInputStream)

                    initializationVector = optionalFieldsInputStream.readAllBytes()
                    println("initializationVector: ${initializationVector?.size}")
                }

                SecretKeyEncryptionType.AEAD -> {
                    val symmetricKeyEncryptionAlgorithmByte = optionalFieldsInputStream.read()
                    symmetricKeyEncryptionAlgorithm =
                        SymmetricKeyAlgorithm.findBy(symmetricKeyEncryptionAlgorithmByte)

                    val aeadAlgorithmByte = optionalFieldsInputStream.read()
                    aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte)

                    val string2KeyFieldLength = optionalFieldsInputStream.read()
                    val string2KeyInputStream = ByteArray(string2KeyFieldLength).let {
                        optionalFieldsInputStream.read(it)
                        ByteArrayInputStream(it)
                    }
                    string2Key = String2KeyParser.parse(string2KeyInputStream)

                    // M is the key size of the symmetric algorithm and N is the nonce size of
                    // the AEAD algorithm. M + N - 64 bits are derived using HKDF (see [RFC5869]).
                    nonce = optionalFieldsInputStream.readAllBytes()
                    println("nonce: ${nonce?.size}")
                }

                else -> {
                    // Known symmetric cipher algo ID
                }
            }
        }

        val secretKeyMaterialLength = ByteArray(4).let {
            inputStream.read(it)
            it.toInt()
        }

        data = ByteArray(secretKeyMaterialLength).also {
            inputStream.read(it)
        }

        if (string2keyUsage == SecretKeyEncryptionType.ClearText) {
            checkSum = ByteArray(2).also {
                inputStream.read(it)
            }
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val encryptionParameterFieldsOutputStream = ByteArrayOutputStream()

        when (string2keyUsage) {
            SecretKeyEncryptionType.ClearText -> {
                val checkSumSnapshot =
                    checkSum ?: throw InvalidParameterException("checkSum must not be null.")
                encryptionParameterFieldsOutputStream.write(0)
                encryptionParameterFieldsOutputStream.write(data.size.toByteArray())
                encryptionParameterFieldsOutputStream.write(data)
                encryptionParameterFieldsOutputStream.write(checkSumSnapshot)
            }

            SecretKeyEncryptionType.CheckSum -> {
                throw UnsupportedS2KUsageTypeException("SecretKey version 5 format MUST NOT use the CheckSum")
            }

            SecretKeyEncryptionType.SHA1 -> {
                val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
                    ?: throw InvalidParameterException("symmetricKeyEncryptionAlgorithm must not be null.")
                val string2KeySnapshot = string2Key
                    ?: throw InvalidParameterException("string2Key must not be null.")
                val initializationVectorSnapshot = initializationVector
                    ?: throw InvalidParameterException("initializationVector must not be null.")

                val bytes = ByteArrayOutputStream().let {
                    it.write(symmetricKeyEncryptionAlgorithmSnapshot.id)

                    val s2kSpecifierBytes = ByteArrayOutputStream().let {
                        string2KeySnapshot.writeTo(it)
                        it.toByteArray()
                    }
                    it.write(s2kSpecifierBytes.size)
                    it.write(s2kSpecifierBytes)
                    it.write(initializationVectorSnapshot)
                    it.toByteArray()
                }

                encryptionParameterFieldsOutputStream.write(bytes.size.toByteArray())
                encryptionParameterFieldsOutputStream.write(bytes)
            }

            SecretKeyEncryptionType.AEAD -> {
                val symmetricKeyEncryptionAlgorithmSnapshot = symmetricKeyEncryptionAlgorithm
                    ?: throw InvalidParameterException("symmetricKeyEncryptionAlgorithm must not be null.")
                val aeadAlgorithmSnapshot = aeadAlgorithm
                    ?: throw InvalidParameterException("aeadAlgorithm must not be null.")
                val string2KeySnapshot = string2Key
                    ?: throw InvalidParameterException("string2Key must not be null.")
                val nonceSnapshot = nonce
                    ?: throw InvalidParameterException("nonce must not be null.")

                val bytes = ByteArrayOutputStream().let {
                    it.write(symmetricKeyEncryptionAlgorithmSnapshot.id)
                    it.write(aeadAlgorithmSnapshot.id)

                    val s2kSpecifierBytes = ByteArrayOutputStream().let {
                        string2KeySnapshot.writeTo(it)
                        it.toByteArray()
                    }
                    it.write(s2kSpecifierBytes.size)
                    it.write(s2kSpecifierBytes)
                    it.write(nonceSnapshot)
                    it.toByteArray()
                }

                encryptionParameterFieldsOutputStream.write(bytes.size.toByteArray())
                encryptionParameterFieldsOutputStream.write(bytes)
            }

            else -> {
                // Known symmetric cipher algo ID
                val initializationVectorSnapshot = initializationVector
                    ?: throw InvalidParameterException("initializationVector must not be null.")
                outputStream.write(initializationVectorSnapshot)
            }
        }

        super.writeContentTo(outputStream)
        outputStream.write(string2keyUsage.id)
        outputStream.write(encryptionParameterFieldsOutputStream.toByteArray())
    }

    override fun toDebugString(): String {
        return """
 * PacketSecretKeyV5ß
    * Version: $version
    * Algorithm: ${algorithm.name}
    * PublicKey:
    ${publicKey?.toString()}
        """.trimIndent()
    }
}
