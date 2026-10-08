package dev.keiji.openpgp.packet.pkesk

import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.UnsupportedPublicKeyAlgorithmException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

/**
 * The algorithm-specific part of a Public Key Encrypted Session Key packet,
 * comprising the encrypted session key.
 *
 * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.3
 */
sealed class EncryptedSessionKey {

    abstract fun readFrom(inputStream: InputStream)

    abstract fun writeTo(outputStream: OutputStream)

    abstract fun toDebugString(): String

    /**
     * Algorithm-Specific Fields for RSA Encryption:
     * an MPI of RSA-encrypted value m^e mod n.
     * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.3
     */
    class Rsa : EncryptedSessionKey() {
        var mPowerEmodN: ByteArray? = null

        override fun readFrom(inputStream: InputStream) {
            mPowerEmodN = MpIntegerUtils.readFrom(inputStream)
        }

        override fun writeTo(outputStream: OutputStream) {
            val mPowerEmodNSnapshot = mPowerEmodN
                ?: throw InvalidParameterException("parameter `mPowerEmodN` must not be null")
            MpIntegerUtils.writeTo(mPowerEmodNSnapshot, outputStream)
        }

        override fun toDebugString(): String {
            return " * EncryptedSessionKey Rsa\n" +
                    "   * mPowerEmodN: ${mPowerEmodN?.toHex()}\n" +
                    ""
        }
    }

    /**
     * Algorithm-Specific Fields for Elgamal Encryption.
     * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.4
     */
    class Elgamal : EncryptedSessionKey() {
        var gPowerKmodP: ByteArray? = null
        var mTimesYPowerKmodP: ByteArray? = null

        override fun readFrom(inputStream: InputStream) {
            gPowerKmodP = MpIntegerUtils.readFrom(inputStream)
            mTimesYPowerKmodP = MpIntegerUtils.readFrom(inputStream)
        }

        override fun writeTo(outputStream: OutputStream) {
            val gPowerKmodPSnapshot = gPowerKmodP
                ?: throw InvalidParameterException("parameter `gPowerKmodP` must not be null")
            val mTimesYPowerKmodPSnapshot = mTimesYPowerKmodP
                ?: throw InvalidParameterException("parameter `mTimesYPowerKmodP` must not be null")

            MpIntegerUtils.writeTo(gPowerKmodPSnapshot, outputStream)
            MpIntegerUtils.writeTo(mTimesYPowerKmodPSnapshot, outputStream)
        }

        override fun toDebugString(): String {
            return " * EncryptedSessionKey Elgamal\n" +
                    "   * gPowerKmodP: ${gPowerKmodP?.toHex()}\n" +
                    "   * mTimesYPowerKmodP: ${mTimesYPowerKmodP?.toHex()}\n" +
                    ""
        }
    }

    /**
     * Algorithm-Specific Fields for ECDH Encryption:
     * an MPI of an ephemeral EC point, followed by a 1-octet size and
     * a symmetric key encoded by the method described in Section 11.5
     * of RFC 9580.
     * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.5
     */
    class Ecdh : EncryptedSessionKey() {
        var ephemeralPoint: ByteArray? = null
        var encodedSymmetricKey: ByteArray? = null

        override fun readFrom(inputStream: InputStream) {
            ephemeralPoint = MpIntegerUtils.readFrom(inputStream)

            val size = inputStream.read()
            encodedSymmetricKey = ByteArray(size).also {
                inputStream.read(it)
            }
        }

        override fun writeTo(outputStream: OutputStream) {
            val ephemeralPointSnapshot = ephemeralPoint
                ?: throw InvalidParameterException("parameter `ephemeralPoint` must not be null")
            val encodedSymmetricKeySnapshot = encodedSymmetricKey
                ?: throw InvalidParameterException("parameter `encodedSymmetricKey` must not be null")

            MpIntegerUtils.writeTo(ephemeralPointSnapshot, outputStream)
            outputStream.write(encodedSymmetricKeySnapshot.size)
            outputStream.write(encodedSymmetricKeySnapshot)
        }

        override fun toDebugString(): String {
            return " * EncryptedSessionKey Ecdh\n" +
                    "   * ephemeralPoint: ${ephemeralPoint?.toHex()}\n" +
                    "   * encodedSymmetricKey: ${encodedSymmetricKey?.toHex()}\n" +
                    ""
        }
    }

    /**
     * Algorithm-Specific Fields for X25519 Encryption:
     * 32 octets representing an ephemeral X25519 public key, followed by
     * a 1-octet size of the following fields and the encrypted session key.
     * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.6
     */
    class X25519 : EncryptedSessionKey() {
        var ephemeralPublicKey: ByteArray? = null
            set(value) {
                require(value == null || value.size == NATIVE_OCTET_LENGTH) {
                    "ephemeralPublicKey length must be $NATIVE_OCTET_LENGTH but ${value?.size}"
                }
                field = value
            }

        var encryptedSessionKey: ByteArray? = null

        override fun readFrom(inputStream: InputStream) {
            ephemeralPublicKey = ByteArray(NATIVE_OCTET_LENGTH).also {
                inputStream.read(it)
            }

            val size = inputStream.read()
            encryptedSessionKey = ByteArray(size).also {
                inputStream.read(it)
            }
        }

        override fun writeTo(outputStream: OutputStream) {
            val ephemeralPublicKeySnapshot = ephemeralPublicKey
                ?: throw InvalidParameterException("parameter `ephemeralPublicKey` must not be null")
            val encryptedSessionKeySnapshot = encryptedSessionKey
                ?: throw InvalidParameterException("parameter `encryptedSessionKey` must not be null")

            outputStream.write(ephemeralPublicKeySnapshot)
            outputStream.write(encryptedSessionKeySnapshot.size)
            outputStream.write(encryptedSessionKeySnapshot)
        }

        override fun toDebugString(): String {
            return " * EncryptedSessionKey X25519\n" +
                    "   * ephemeralPublicKey: ${ephemeralPublicKey?.toHex()}\n" +
                    "   * encryptedSessionKey: ${encryptedSessionKey?.toHex()}\n" +
                    ""
        }

        companion object {
            const val NATIVE_OCTET_LENGTH = 32
        }
    }

    /**
     * Algorithm-Specific Fields for X448 Encryption:
     * 56 octets representing an ephemeral X448 public key, followed by
     * a 1-octet size of the following fields and the encrypted session key.
     * https://www.rfc-editor.org/rfc/rfc9580#section-5.1.7
     */
    class X448 : EncryptedSessionKey() {
        var ephemeralPublicKey: ByteArray? = null
            set(value) {
                require(value == null || value.size == NATIVE_OCTET_LENGTH) {
                    "ephemeralPublicKey length must be $NATIVE_OCTET_LENGTH but ${value?.size}"
                }
                field = value
            }

        var encryptedSessionKey: ByteArray? = null

        override fun readFrom(inputStream: InputStream) {
            ephemeralPublicKey = ByteArray(NATIVE_OCTET_LENGTH).also {
                inputStream.read(it)
            }

            val size = inputStream.read()
            encryptedSessionKey = ByteArray(size).also {
                inputStream.read(it)
            }
        }

        override fun writeTo(outputStream: OutputStream) {
            val ephemeralPublicKeySnapshot = ephemeralPublicKey
                ?: throw InvalidParameterException("parameter `ephemeralPublicKey` must not be null")
            val encryptedSessionKeySnapshot = encryptedSessionKey
                ?: throw InvalidParameterException("parameter `encryptedSessionKey` must not be null")

            outputStream.write(ephemeralPublicKeySnapshot)
            outputStream.write(encryptedSessionKeySnapshot.size)
            outputStream.write(encryptedSessionKeySnapshot)
        }

        override fun toDebugString(): String {
            return " * EncryptedSessionKey X448\n" +
                    "   * ephemeralPublicKey: ${ephemeralPublicKey?.toHex()}\n" +
                    "   * encryptedSessionKey: ${encryptedSessionKey?.toHex()}\n" +
                    ""
        }

        companion object {
            const val NATIVE_OCTET_LENGTH = 56
        }
    }

    companion object {
        fun getInstance(publicKeyAlgorithm: PublicKeyAlgorithm): EncryptedSessionKey {
            return when (publicKeyAlgorithm) {
                PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN -> Rsa()
                PublicKeyAlgorithm.RSA_ENCRYPT_ONLY -> Rsa()
                PublicKeyAlgorithm.ELGAMAL_ENCRYPT_ONLY -> Elgamal()
                PublicKeyAlgorithm.ECDH -> Ecdh()
                PublicKeyAlgorithm.X25519 -> X25519()
                PublicKeyAlgorithm.X448 -> X448()
                else -> throw UnsupportedPublicKeyAlgorithmException(
                    "PublicKeyAlgorithm ${publicKeyAlgorithm.name} is not supported for PKESK."
                )
            }
        }
    }
}
