package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.MpIntegerUtils
import dev.keiji.openpgp.toHex
import dev.keiji.openpgp.toUnsignedInt
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidParameterException

class PublicKeyEcdh : PublicKey() {

    var ellipticCurveParameter: EllipticCurveParameter? = null
    var ecPoint: ByteArray? = null

    // KDF parameters
    var kdfHashFunctionId: Int = -1
    var kdfAlgorithmId: Int = -1

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

        // 0 and 0xFF are reserved for future extensions.
        // if (kdfFieldLength == 0x00 || kdfFieldLength == 0xFF) { }

        val kdfBytes = ByteArray(kdfFieldLength).also {
            inputStream.read(it)
        }

        // a one-octet value 1, reserved for future extensions.
        // kdfBytes[0] == 1

        kdfHashFunctionId = kdfBytes[1].toUnsignedInt()
        kdfAlgorithmId = kdfBytes[2].toUnsignedInt()
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

        val kdfBytes = ByteArrayOutputStream().let {
            // a one-octet value 1, reserved for future extensions.
            it.write(1)

            it.write(kdfHashFunctionId)
            it.write(kdfAlgorithmId)
            it.toByteArray()
        }

        outputStream.write(kdfBytes.size)
        outputStream.write(kdfBytes)
    }

    override fun toDebugString(): String {
        return """
* PublicKey ECDH
    * ellipticCurveParameter: ${ellipticCurveParameter?.name}
    * ecPoint: ${ecPoint?.toHex()}
    * kdfHashFunctionId: $kdfHashFunctionId
    * kdfAlgorithmId: $kdfAlgorithmId
        """.trimIndent()
    }
}
