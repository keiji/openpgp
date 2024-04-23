@file:Suppress("MagicNumber")

package dev.keiji.openpgp

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-08#name-key-ids-and-fingerprints
 */
object FingerprintUtils {

    interface AlgorithmSpecificField {
        val algorithmId: Int
        val encode: ByteArray
    }

    class RsaAlgorithmSpecificField private constructor(
        private val publicExponentE: BigInteger,
        private val modulusN: BigInteger,
    ) : AlgorithmSpecificField {

        companion object {
            fun getInstance(
                rsaPublicKey: RSAPublicKey,
            ): RsaAlgorithmSpecificField =
                RsaAlgorithmSpecificField(rsaPublicKey.publicExponent, rsaPublicKey.modulus)

            fun getInstance(
                publicExponentEBytes: ByteArray,
                prime1PBytes: ByteArray,
                prime2QBytes: ByteArray,
            ): RsaAlgorithmSpecificField {
                val prime1P = BigInteger(+1, prime1PBytes)
                val prime2Q = BigInteger(+1, prime2QBytes)
                val modulusN = prime1P.multiply(prime2Q)

                return RsaAlgorithmSpecificField(
                    BigInteger(+1, publicExponentEBytes),
                    modulusN
                )
            }
        }

        override val algorithmId: Int
            get() = PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN.id

        override val encode: ByteArray
            get() {
                return ByteArrayOutputStream().let { baos ->
                    baos.write(MpIntegerUtils.toMpInteger(modulusN))
                    baos.write(MpIntegerUtils.toMpInteger(publicExponentE))
                    baos.toByteArray()
                }
            }
    }

    class EcdsaAlgorithmSpecificField private constructor(
        private val ellipticCurveParameter: EllipticCurveParameter,
        private val ecPublicKey: ECPublicKey,
    ) : AlgorithmSpecificField {

        companion object {
            fun getInstance(
                ellipticCurveParameter: EllipticCurveParameter,
                ecPublicKey: ECPublicKey,
            ) = EcdsaAlgorithmSpecificField(ellipticCurveParameter, ecPublicKey)
        }

        override val algorithmId: Int
            get() = PublicKeyAlgorithm.ECDSA.id

        override val encode: ByteArray
            get() {
                val oid = ellipticCurveParameter.oid
                val oidSize = oid.size.toByte()
                val algorithmSpecificField =
                    MpIntegerUtils.toMpInteger(BigInteger(ecPublicKey.encodeToUncompressed()))

                return ByteArrayOutputStream().let { baos ->
                    baos.write(byteArrayOf(oidSize))
                    baos.write(oid)
                    baos.write(algorithmSpecificField)
                    baos.toByteArray()
                }
            }
    }

    class EcdhAlgorithmSpecificField private constructor(
        private val ellipticCurveParameter: EllipticCurveParameter,
        private val ecPublicKey: ECPublicKey,
    ) : AlgorithmSpecificField {

        companion object {
            fun getInstance(
                ellipticCurveParameter: EllipticCurveParameter,
                ecPublicKey: ECPublicKey,
            ) = EcdhAlgorithmSpecificField(ellipticCurveParameter, ecPublicKey)
        }

        override val algorithmId: Int
            get() = PublicKeyAlgorithm.ECDH.id

        private val hashAlgorithm: HashAlgorithm = when (ellipticCurveParameter) {
            EllipticCurveParameter.Secp256r1 -> HashAlgorithm.SHA2_256
            EllipticCurveParameter.Secp384r1 -> HashAlgorithm.SHA2_384
            EllipticCurveParameter.Secp521r1 -> HashAlgorithm.SHA2_512
            else -> HashAlgorithm.SHA2_256
        }

        private val symmetricKeyAlgorithm: SymmetricKeyAlgorithm = when (ellipticCurveParameter) {
            EllipticCurveParameter.Secp256r1 -> SymmetricKeyAlgorithm.AES128
            EllipticCurveParameter.Secp384r1 -> SymmetricKeyAlgorithm.AES256
            EllipticCurveParameter.Secp521r1 -> SymmetricKeyAlgorithm.AES256
            else -> SymmetricKeyAlgorithm.AES128
        }

        override val encode: ByteArray
            get() {
                val oid = ellipticCurveParameter.oid
                val oidSize = oid.size.toByte()
                val mpiEcPoint =
                    MpIntegerUtils.toMpInteger(BigInteger(ecPublicKey.encodeToUncompressed()))

                val kdfFieldBytes = ByteArrayOutputStream().let { baos ->
                    baos.write(0x01)
                    baos.write(hashAlgorithm.id)
                    baos.write(symmetricKeyAlgorithm.id)
                    baos.toByteArray()
                }
                val kdfFieldSize = kdfFieldBytes.size

                return ByteArrayOutputStream().let { baos ->
                    baos.write(byteArrayOf(oidSize))
                    baos.write(oid)
                    baos.write(mpiEcPoint)
                    baos.write(kdfFieldSize)
                    baos.write(kdfFieldBytes)
                    baos.toByteArray()
                }
            }
    }

    class Ed25519AlgorithmSpecificField private constructor(
        private val ecPublicKeyCompressedPointFormatBytes: ByteArray,
    ) : AlgorithmSpecificField {

        companion object {
            fun getInstance(
                ecPublicKeyCompressedPointFormatBytes: ByteArray,
            ) = Ed25519AlgorithmSpecificField(ecPublicKeyCompressedPointFormatBytes)
        }

        @Suppress("DEPRECATION")
        override val algorithmId: Int
            get() = PublicKeyAlgorithm.EDDSA_LEGACY.id

        override val encode: ByteArray
            get() {
                val oid = EllipticCurveParameter.Ed25519.oid
                val oidSize = oid.size.toByte()
                val mpiEcPoint =
                    MpIntegerUtils.toMpInteger(BigInteger(ecPublicKeyCompressedPointFormatBytes))

                return ByteArrayOutputStream().let { baos ->
                    baos.write(byteArrayOf(oidSize))
                    baos.write(oid)
                    baos.write(mpiEcPoint)
                    baos.toByteArray()
                }
            }
    }

    class X25519AlgorithmSpecificField private constructor(
        private val ecPublicKeyCompressedPointFormatBytes: ByteArray,
    ) : AlgorithmSpecificField {

        companion object {
            fun getInstance(
                ecPublicKeyCompressedPointFormatBytes: ByteArray,
            ) = X25519AlgorithmSpecificField(ecPublicKeyCompressedPointFormatBytes)
        }

        override val algorithmId: Int
            get() = PublicKeyAlgorithm.ECDH.id

        private val hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA2_256
        private val symmetricKeyAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES128

        override val encode: ByteArray
            get() {
                val oid = EllipticCurveParameter.CV25519.oid
                val oidSize = oid.size.toByte()
                val mpiEcPoint =
                    MpIntegerUtils.toMpInteger(BigInteger(ecPublicKeyCompressedPointFormatBytes))

                val kdfFieldBytes = ByteArrayOutputStream().let { baos ->
                    baos.write(0x01)
                    baos.write(hashAlgorithm.id)
                    baos.write(symmetricKeyAlgorithm.id)
                    baos.toByteArray()
                }
                val kdfFieldSize = kdfFieldBytes.size

                return ByteArrayOutputStream().let { baos ->
                    baos.write(byteArrayOf(oidSize))
                    baos.write(oid)
                    baos.write(mpiEcPoint)
                    baos.write(kdfFieldSize)
                    baos.write(kdfFieldBytes)
                    baos.toByteArray()
                }
            }
    }

    fun calcV4Fingerprint(
        generationDatetime: Int,
        algorithmSpecificField: AlgorithmSpecificField,
    ): ByteArray = calcV4Fingerprint(
        generationDatetime.toByteArray(),
        algorithmSpecificField,
    )

    internal fun calcV4Fingerprint(
        generationDatetime: ByteArray,
        algorithmSpecificField: AlgorithmSpecificField,
    ): ByteArray {
        val be = ByteArrayOutputStream().let { baos ->

            // b: Version number
            baos.write(byteArrayOf(0x04))

            // c: Timestamp of key creation
            baos.write(generationDatetime)

            // d: Algorithm ID
            baos.write(algorithmSpecificField.algorithmId)

            // e: Algorithm specific field
            baos.write(algorithmSpecificField.encode)

            baos.toByteArray()
        }

        val messageDigest = MessageDigest.getInstance("SHA-1").also {
            it.update(0x99.toByte())

            // length b-e
            it.update(be.size.to2ByteArray())
            it.update(be)
        }

        return messageDigest.digest()
    }

    fun calcV5Fingerprint(
        generationDatetime: ByteArray,
        algorithmSpecificField: AlgorithmSpecificField,
    ): ByteArray {
        // f: Algorithm specific field
        val f = ByteArrayOutputStream().let { baos ->
            baos.write(algorithmSpecificField.encode)
            baos.toByteArray()
        }
        val bf = ByteArrayOutputStream().let { baos ->

            // b: Version number
            baos.write(byteArrayOf(0x05))

            // c: Timestamp of key creation
            baos.write(generationDatetime)

            // d: Algorithm ID
            baos.write(algorithmSpecificField.algorithmId)

            // e: four-octet scalar octet count for the following key material;
            baos.write(f.size.toByteArray())

            // f: Algorithm specific field
            baos.write(f)

            baos.toByteArray()
        }

        val messageDigest = MessageDigest.getInstance("SHA-256").also {
            it.update(0x9A.toByte())

            // length b-f
            it.update(bf.size.toByteArray())
            it.update(bf)
        }

        return messageDigest.digest()
    }
}
