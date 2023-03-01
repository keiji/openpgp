package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.*
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PublicKeyEcdh : PublicKey() {

    var ellipticCurveParameter: EllipticCurveParameter? = null
    var ecPoint: ByteArray? = null

    val ecPointX: ByteArray?
        get() {
            val ecPointSnapshot = ecPoint ?: return null
            if (ecPointSnapshot.size < 2) {
                return null
            }
            if (ecPointSnapshot.size % 2 != 1) {
                return null
            }
            if (ecPointSnapshot[0] != 0x04.toByte()) {
                return null
            }
            val tokenLength = (ecPointSnapshot.size - 1) / 2
            return ecPointSnapshot.copyOfRange(1, tokenLength + 1)
        }

    val ecPointY: ByteArray?
        get() {
            val ecPointSnapshot = ecPoint ?: return null
            if (ecPointSnapshot.size < 2) {
                return null
            }
            if (ecPointSnapshot.size % 2 != 1) {
                return null
            }
            if (ecPointSnapshot[0] != 0x04.toByte()) {
                return null
            }
            val tokenLength = (ecPointSnapshot.size - 1) / 2
            return ecPointSnapshot.copyOfRange(tokenLength + 1, ecPointSnapshot.size)
        }

    // KDF parameters
    var kdfHashFunction: HashAlgorithm? = null
    var kdfAlgorithm: SymmetricKeyAlgorithm? = null

    override fun readFrom(inputStream: InputStream) {
        val oidLength = inputStream.read()

        // 0 and 0xFF are reserved for future extensions.
        // if (oidLength == 0x00 || oidLength == 0xFF) { }

        val oidBytes = ByteArray(oidLength).also {
            inputStream.read(it)
        }

        ellipticCurveParameter = EllipticCurveParameter.findByOid(oidBytes)
        ecPoint = MpIntegerUtils.readFrom(inputStream)

        val kdfFieldLength = inputStream.read()
        if (kdfFieldLength < 0) {
            throw InvalidParameterException("kdf field length must not be positive value.")
        }

        // 0 and 0xFF are reserved for future extensions.
        // if (kdfFieldLength == 0x00 || kdfFieldLength == 0xFF) { }

        val kdfBytes = ByteArray(kdfFieldLength).also {
            inputStream.read(it)
        }

        // a one-octet value 1, reserved for future extensions.
        // kdfBytes[0] == 1

        val kdfHashFunctionId = kdfBytes[1].toUnsignedInt()
        kdfHashFunction = HashAlgorithm.findBy(kdfHashFunctionId)

        val kdfAlgorithmId = kdfBytes[2].toUnsignedInt()
        kdfAlgorithm = SymmetricKeyAlgorithm.findBy(kdfAlgorithmId)
    }

    override fun writeTo(outputStream: OutputStream) {
        val ellipticCurveParameterSnapshot = ellipticCurveParameter
            ?: throw InvalidParameterException("parameter `ellipticCurveParameter` must not be null")
        val ecPointSnapshot =
            ecPoint ?: throw InvalidParameterException("parameter `ecPoint` must not be null")
        val kdfHashFunctionSnapshot =
            kdfHashFunction ?: throw InvalidParameterException("parameter `kdfHashFunction` must not be null")
        val kdfAlgorithmSnapshot =
            kdfAlgorithm ?: throw InvalidParameterException("parameter `kdfAlgorithm` must not be null")

        val ellipticCurveParameterBytes = ellipticCurveParameterSnapshot.oid

        outputStream.write(ellipticCurveParameterBytes.size)
        outputStream.write(ellipticCurveParameterBytes)
        MpIntegerUtils.writeTo(ecPointSnapshot, outputStream)

        val kdfBytes = ByteArrayOutputStream().let {
            // a one-octet value 1, reserved for future extensions.
            it.write(1)

            it.write(kdfHashFunctionSnapshot.id)
            it.write(kdfAlgorithmSnapshot.id)
            it.toByteArray()
        }

        outputStream.write(kdfBytes.size)
        outputStream.write(kdfBytes)
    }

    override fun toDebugString(): String {
        return """
* PublicKey ECDH
    * ellipticCurveParameter: ${ellipticCurveParameter?.name}
    * ecPoint: ${ecPoint?.toHex()} - x: $ecPointX, y: $ecPointY
    * kdfHashFunctionId: ${kdfHashFunction?.id}
    * kdfAlgorithmId: ${kdfAlgorithm?.id}
        """.trimIndent()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyEcdh

        if (ellipticCurveParameter != other.ellipticCurveParameter) return false
        if (ecPoint != null) {
            if (other.ecPoint == null) return false
            if (!ecPoint.contentEquals(other.ecPoint)) return false
        } else if (other.ecPoint != null) return false
        if (kdfHashFunction != other.kdfHashFunction) return false
        if (kdfAlgorithm != other.kdfAlgorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ellipticCurveParameter?.hashCode() ?: 0
        result = 31 * result + (ecPoint?.contentHashCode() ?: 0)
        result = 31 * result + (kdfHashFunction?.hashCode() ?: 0)
        result = 31 * result + (kdfAlgorithm?.hashCode() ?: 0)
        return result
    }
}
