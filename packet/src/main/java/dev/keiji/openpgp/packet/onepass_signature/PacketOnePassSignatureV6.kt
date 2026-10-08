@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.onepass_signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.InvalidSignatureException
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import dev.keiji.openpgp.UnsupportedSignatureTypeException
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

/**
 * A version 6 One-Pass Signature packet.
 *
 * The differences from a version 3 One-Pass Signature packet are that
 * a variable-length salt field (a 1-octet salt size followed by the salt,
 * where the size MUST match the salt size defined for the hash algorithm
 * in Table 23 of RFC 9580) follows the public key algorithm, and that
 * the fingerprint of the signing key (32 octets) replaces the Key ID.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.4
 */
class PacketOnePassSignatureV6 : PacketOnePassSignature() {
    companion object {
        const val VERSION = 6

        const val FINGERPRINT_LENGTH = 32
    }

    override val version: Int = VERSION

    var signatureType: SignatureType? = null
    var hashAlgorithm: HashAlgorithm? = null
    var publicKeyAlgorithm: PublicKeyAlgorithm? = null

    var salt: ByteArray = byteArrayOf()

    var fingerprint: ByteArray = byteArrayOf()
        set(value) {
            require(value.size == FINGERPRINT_LENGTH) {
                "fingerprint length must be $FINGERPRINT_LENGTH but ${value.size}"
            }
            field = value
        }

    var flag: Int = -1

    override fun readContentFrom(inputStream: InputStream) {
        val signatureTypeByte = inputStream.read()
        signatureType = SignatureType.findBy(signatureTypeByte)
            ?: throw UnsupportedSignatureTypeException(
                "SignatureType id $signatureTypeByte is not supported."
            )

        val hashAlgorithmByte = inputStream.read()
        val hashAlgorithm = HashAlgorithm.findBy(hashAlgorithmByte)
            ?: throw UnsupportedSymmetricKeyAlgorithmException(
                "hashAlgorithm id $hashAlgorithmByte is not supported."
            )
        this.hashAlgorithm = hashAlgorithm

        val publicKeyAlgorithmByte = inputStream.read()
        publicKeyAlgorithm = PublicKeyAlgorithm.findById(publicKeyAlgorithmByte)
            ?: throw UnsupportedPublicKeyAlgorithmException(
                "publicKeyAlgorithm id $publicKeyAlgorithmByte is not supported."
            )

        val saltSize = inputStream.read()
        val expectedSaltSize = hashAlgorithm.v6SaltSize
            ?: throw UnsupportedHashAlgorithmException(
                "HashAlgorithm ${hashAlgorithm.textName} can not be used " +
                        "by a version 6 One-Pass Signature packet."
            )
        if (saltSize != expectedSaltSize) {
            throw InvalidSignatureException(
                "Salt size $saltSize does not match the salt size " +
                        "$expectedSaltSize of ${hashAlgorithm.textName}."
            )
        }
        salt = ByteArray(saltSize).also {
            inputStream.read(it)
        }

        fingerprint = ByteArray(FINGERPRINT_LENGTH).also {
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
        outputStream.write(salt.size)
        outputStream.write(salt)
        outputStream.write(fingerprint)
        outputStream.write(flag)
    }

    override fun toDebugString(): String {
        return " * PacketOnePassSignatureV6\n" +
                "   * Version: $version\n" +
                "   * signatureType: ${signatureType?.name}\n" +
                "   * hashAlgorithm: ${hashAlgorithm?.textName}\n" +
                "   * publicKeyAlgorithm: ${publicKeyAlgorithm?.name}\n" +
                "   * salt: ${salt.toHex()}\n" +
                "   * fingerprint: ${fingerprint.toHex()}\n" +
                "   * flag: $flag\n" +
                ""
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PacketOnePassSignatureV6

        if (version != other.version) return false
        if (signatureType != other.signatureType) return false
        if (hashAlgorithm != other.hashAlgorithm) return false
        if (publicKeyAlgorithm != other.publicKeyAlgorithm) return false
        if (!salt.contentEquals(other.salt)) return false
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
        result = 31 * result + fingerprint.contentHashCode()
        result = 31 * result + flag
        return result
    }
}
