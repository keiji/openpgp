package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.*
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

private const val KEY_ID_LENGTH = 8

class PacketOnePassSignatureV3 : PacketOnePassSignature() {
    companion object {
        const val VERSION = 3
    }

    override val version: Int = VERSION

    var signatureType: SignatureType? = null
    var hashAlgorithm: HashAlgorithm? = null
    var publicKeyAlgorithm: PublicKeyAlgorithm? = null

    var keyId: ByteArray = ByteArray(KEY_ID_LENGTH)
        set(value) {
            if (value.size != KEY_ID_LENGTH) {
                throw IllegalArgumentException("keyId length must be equal $KEY_ID_LENGTH but ${value.size}")
            }
            field = value
        }

    var flag: Int = -1
        set(value) {
            if (value < 0) {
                throw IllegalArgumentException("flag must be greater or equal 0 but $value")
            }
            if (value > 0xFF) {
                throw IllegalArgumentException("flag must be less or equal 255 but $value")
            }
            field = value
        }

    override fun readContentFrom(inputStream: InputStream) {
        val signatureTypeByte = inputStream.read()
        signatureType = SignatureType.findBy(signatureTypeByte)
            ?: throw UnsupportedSymmetricKeyAlgorithmException("signatureType id $signatureTypeByte is not supported.")

        val hashAlgorithmByte = inputStream.read()
        hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)
            ?: throw UnsupportedSymmetricKeyAlgorithmException("hashAlgorithm id $hashAlgorithmByte is not supported.")

        val publicKeyAlgorithmByte = inputStream.read()
        publicKeyAlgorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedSymmetricKeyAlgorithmException("publicKeyAlgorithm id $publicKeyAlgorithmByte is not supported.")

        inputStream.read(keyId)

        flag = inputStream.read()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val signatureTypeSnapshot = signatureType
            ?: throw InvalidParameterException("`signatureType` must not be null.")
        val hashAlgorithmSnapshot = hashAlgorithm
            ?: throw InvalidParameterException("`hashAlgorithm` must not be null.")
        val publicKeyAlgorithmSnapshot = publicKeyAlgorithm
            ?: throw InvalidParameterException("`publicKeyAlgorithm` must not be null.")

        outputStream.write(version)
        outputStream.write(signatureTypeSnapshot.value)
        outputStream.write(hashAlgorithmSnapshot.id)
        outputStream.write(publicKeyAlgorithmSnapshot.id)
        outputStream.write(keyId)
        outputStream.write(flag)
    }

    override fun toDebugString(): String {
        return " * PacketOnePassSignatureV3\n" +
                "   * Version: $version\n" +
                "   * signatureType: ${signatureType?.name}\n" +
                "   * hashAlgorithm: ${hashAlgorithm?.textName}\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm?.name}\n" +
                "   * keyId: ${keyId.toHex("")}\n" +
                "   * flag: $flag\n" +
                ""
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketOnePassSignatureV3

        if (version != other.version) return false
        if (signatureType != other.signatureType) return false
        if (hashAlgorithm != other.hashAlgorithm) return false
        if (publicKeyAlgorithm != other.publicKeyAlgorithm) return false
        if (!keyId.contentEquals(other.keyId)) return false
        if (flag != other.flag) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + (signatureType?.hashCode() ?: 0)
        result = 31 * result + (hashAlgorithm?.hashCode() ?: 0)
        result = 31 * result + (publicKeyAlgorithm?.hashCode() ?: 0)
        result = 31 * result + keyId.contentHashCode()
        result = 31 * result + flag
        return result
    }


}
