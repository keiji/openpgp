package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PublicKeyEcdsa : PublicKey() {

    var ellipticCurveParameter: EllipticCurveParameter? = null
    var ecPoint: ByteArray? = null

    override fun readFrom(inputStream: InputStream) {
        val oidLength = inputStream.read()

        // 0 and 0xFF are reserved for future extensions.
        // if (oidLength == 0x00 || oidLength == 0xFF) { }

        val oidBytes = ByteArray(oidLength).also {
            inputStream.read(it)
        }

        ellipticCurveParameter = EllipticCurveParameter.findByOid(oidBytes)
        ecPoint = MpIntegerUtils.readFrom(inputStream)
    }

    override fun writeTo(outputStream: OutputStream) {
        val ellipticCurveParameterSnapshot = ellipticCurveParameter
            ?: throw InvalidParameterException("parameter `ellipticCurveParameter` must not be null")
        val ecPointSnapshot =
            ecPoint ?: throw InvalidParameterException("parameter `ecPoint` must not be null")

        val ellipticCurveParameterBytes = ellipticCurveParameterSnapshot.oid

        outputStream.write(ellipticCurveParameterBytes.size)
        outputStream.write(ellipticCurveParameterBytes)
        MpIntegerUtils.writeTo(ecPointSnapshot, outputStream)
    }

    override fun toDebugString(): String {
        return """
* PublicKey ECDSA
    * ellipticCurveParameter: ${ellipticCurveParameter?.name}
    * ecPoint: ${ecPoint?.toHex()}
        """.trimIndent()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyEcdsa

        if (ellipticCurveParameter != other.ellipticCurveParameter) return false
        if (ecPoint != null) {
            if (other.ecPoint == null) return false
            if (!ecPoint.contentEquals(other.ecPoint)) return false
        } else if (other.ecPoint != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ellipticCurveParameter?.hashCode() ?: 0
        result = 31 * result + (ecPoint?.contentHashCode() ?: 0)
        return result
    }
}
