@file:Suppress("MagicNumber")

package dev.keiji.openpgp

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.interfaces.ECPublicKey
import kotlin.experimental.and
import kotlin.math.max

/**
 * Encode EC public key to byteArray as uncompressed for OpenPGP.
 *
 * On document "Functional Specification of the OpenPGP Smart Card Application",
 * a public key specification is described as below.
 *
 * ```
 * Public key is a point denoted as PP on the curve,
 * equal to x times PB where x is the private key, coded on 2z or z+1 bytes.
 *
 * The public key for ECDSA/DH consists of two raw big-endian integers with the same length as a field element each.
 *
 * In compliance with EN 419212 the format is
 *  04 || x || y
 * where the first byte(0x04) indicates an uncompressed raw format.
 * ```
 */
fun ECPublicKey.encodeToUncompressed(): ByteArray {
    return ByteArrayOutputStream().let {
        // The first byte(0x04) indicates an uncompressed raw format.
        it.write(byteArrayOf(0x04))

        val affineX = w.affineX.toByteArray()
        val affineY = w.affineY.toByteArray()

        /**
         * Sometimes, element of signature data doesn't match expectElementLength
         * and it have 0x00 at index-0.
         * (It behavior same to of BigInteger.toByteArray())
         */
        val affineXSize = affineX.size - if (isContainZeroPrefix(affineX)) 1 else 0
        val affineYSize = affineY.size - if (isContainZeroPrefix(affineY)) 1 else 0

        // affineX and affineY size must be equal.
        // The OpenPGP Card specification says that
        //
        // > The public key for ECDSA/DH consists of two raw big-endian integers
        // > with the same length as a field element each."
        //
        // @See dev.keiji.bocchi.openpgp.SignatureContainer
        val expectLength = max(affineXSize, affineYSize)

        write(affineX, it, expectLength)
        write(affineY, it, expectLength)

        it.toByteArray()
    }
}

private fun isContainZeroPrefix(data: ByteArray): Boolean {
    if (data.size < 2) {
        return false
    }

    if (data[0] != 0x00.toByte()) {
        return false
    }

    // most-significant bit on.
    return (data[1] and 0b1000_0000.toByte()) != 0.toByte()
}

/**
 * Write byteArray to OutputStream.
 * And if data had 0x00 at index-0, the element will be removed.
 */
private fun write(data: ByteArray, outputStream: OutputStream, expectLength: Int) {
    if (data.size == expectLength) {
        outputStream.write(data, 0, expectLength)
        return
    }

    val paddingLength = expectLength - data.size

    if (paddingLength < 0) {
        /**
         * Sometimes, element of signature data doesn't match expectElementLength
         * and it have 0x00 at index-0.
         * (It behavior same to of BigInteger.toByteArray())
         *
         * And that signature will be decided BAD SIGNATURE by OpenPGP,
         * because of OpenPGP strictly check the signature data.
         *
         * 0x00 element at index-0 must be removed.
         */
        val offset = if (isContainZeroPrefix(data)) 1 else 0
        outputStream.write(data, offset, (data.size - offset))

    } else if (!isContainZeroPrefix(data)) {
        @Suppress("ForEachOnRange")
        // Append 0 padding
        (0 until paddingLength).forEach { _ ->
            outputStream.write(0)
        }
        outputStream.write(data, 0, data.size)
    }
}
