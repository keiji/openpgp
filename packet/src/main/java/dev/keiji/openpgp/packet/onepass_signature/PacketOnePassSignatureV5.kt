@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.InvalidSignatureException
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

private const val SALT_LENGTH = 16

class PacketOnePassSignatureV5 : PacketOnePassSignature() {
    companion object {
        const val VERSION = 5
    }

    override val version: Int = VERSION

    var signatureType: SignatureType? = null
    var hashAlgorithm: HashAlgorithm? = null
    var publicKeyAlgorithm: PublicKeyAlgorithm? = null

    var salt: ByteArray = ByteArray(SALT_LENGTH)
        set(value) {
            require(value.size == SALT_LENGTH) { "salt length must be equal $SALT_LENGTH but $value" }
            field = value
        }

    var keyVersion: Int = VERSION
        set(value) {
            /**
             * An application that encounters a v5 One-Pass Signature packet
             * where the key version number is not 5 MUST treat the signature as invalid.
             */
            require(value == VERSION) { "keyVersion must be $VERSION but $value" }
            field = value
        }

    var fingerprint: ByteArray = byteArrayOf()

    var flag: Int = -1

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

        inputStream.read(salt)

        val keyVersionByte = inputStream.read()
        val fingerprintLength = when (keyVersionByte) {
            VERSION -> 32

            /**
             * An application that encounters a v5 One-Pass Signature packet
             * where the key version number is not 5 MUST treat the signature as invalid.
             */
            else -> throw InvalidSignatureException("`keyVersion` $keyVersion is invalid.")
        }

        keyVersion = keyVersionByte
        fingerprint = ByteArray(fingerprintLength).also {
            inputStream.read(it)
        }

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
        outputStream.write(salt)
        outputStream.write(keyVersion)
        outputStream.write(fingerprint)
        outputStream.write(flag)
    }

    override fun toDebugString(): String {
        return " * PacketOnePassSignatureV5\n" +
                "   * Version: $version\n" +
                "   * signatureType: ${signatureType?.name}\n" +
                "   * hashAlgorithm: ${hashAlgorithm?.textName}\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm?.name}\n" +
                "   * salt: ${salt.toHex("")}\n" +
                "   * keyVersion: $keyVersion\n" +
                "   * fingerprint: ${fingerprint.toHex("")}\n" +
                "   * flag: $flag\n" +
                ""
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketOnePassSignatureV5

        if (version != other.version) return false
        if (signatureType != other.signatureType) return false
        if (hashAlgorithm != other.hashAlgorithm) return false
        if (publicKeyAlgorithm != other.publicKeyAlgorithm) return false
        if (!salt.contentEquals(other.salt)) return false
        if (keyVersion != other.keyVersion) return false
        if (!fingerprint.contentEquals(other.fingerprint)) return false
        if (flag != other.flag) return false

        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + (signatureType?.hashCode() ?: 0)
        result = 31 * result + (hashAlgorithm?.hashCode() ?: 0)
        result = 31 * result + (publicKeyAlgorithm?.hashCode() ?: 0)
        result = 31 * result + salt.contentHashCode()
        result = 31 * result + keyVersion
        result = 31 * result + fingerprint.contentHashCode()
        result = 31 * result + flag
        return result
    }


}
