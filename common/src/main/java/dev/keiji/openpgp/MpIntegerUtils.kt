package dev.keiji.openpgp

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.StreamCorruptedException
import java.math.BigInteger

/**
 * Multi-precision Integer Utilities.
 *
 * https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-multiprecision-integers
 */
object MpIntegerUtils {
    internal fun strip(byteArray: ByteArray): ByteArray {
        if (byteArray[0] == 0x00.toByte()) {
            return byteArray.copyOfRange(1, byteArray.size)
        }
        return byteArray
    }

    fun toMpInteger(bigInteger: BigInteger): ByteArray {
        return ByteArrayOutputStream().let { baos ->
            baos.write(bigInteger.bitLength().to2ByteArray())
            baos.write(strip(bigInteger.toByteArray()))
            baos.toByteArray()
        }
    }

    fun readFrom(inputStream: InputStream): ByteArray? {
        val precision = ByteArray(2).also {
            inputStream.read(it)
        }
        val bitLength = precision.toInt()
        val byteLength = bitLength / Byte.SIZE_BITS + if (bitLength % Byte.SIZE_BITS == 0) 0 else 1

        if (byteLength == 0) {
            return null
        }

        val value = ByteArray(byteLength)
        val len = inputStream.read(value)

        if (len != byteLength) {
            throw StreamCorruptedException("Precision $byteLength bytes but $len bytes read.")
        }
        return value
    }

    fun writeTo(value: ByteArray, outputStream: OutputStream) {
        val bigInteger = BigInteger(+1, value)
        val bitLength = bigInteger.bitLength()
        val precision = bitLength.to2ByteArray()
        outputStream.write(precision)
        outputStream.write(value)
    }
}
