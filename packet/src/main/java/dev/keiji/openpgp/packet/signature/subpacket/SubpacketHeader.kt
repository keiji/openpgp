@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.to2ByteArray
import dev.keiji.openpgp.toByteArray
import java.io.InputStream
import java.io.OutputStream

private const val CRITICAL_BIT = 0b01000000

class SubpacketHeader {
    var length: Int = 0
    var isCriticalBit = false
    var typeValue: Int = 0

    fun readFrom(inputStream: InputStream) {
        val octet1st = inputStream.read()
        if (octet1st < 192) { // One octet
            length = octet1st
        } else if (octet1st < 255) { // Two octets
            val octet2nd = inputStream.read()
            // See RFC4880Bis
            val subpacketLen = ((octet1st - 192) shl 8) + octet2nd + 192
            length = subpacketLen
        } else { // firstByte == 0xFF - four octets
            // Five octets
            val octet2nd = inputStream.read()
            val octet3rd = inputStream.read()
            val octet4th = inputStream.read()
            val octet5th = inputStream.read()

            // See RFC4880Bis
            val subpacketLen =
                (octet2nd shl 24) or (octet3rd shl 16) or (octet4th shl 8) or octet5th
            length = subpacketLen
        }

        val typeByte = inputStream.read()
        isCriticalBit = (typeByte and CRITICAL_BIT) != 0
        typeValue = typeByte and CRITICAL_BIT.inv()
    }

    fun writeTo(outputStream: OutputStream) {
        val lengthBytes = if (length < 192) {
            byteArrayOf(length.toByte())
        } else if (length < 255) {
            val value = length - 192
            val values = value.to2ByteArray()
            byteArrayOf(
                0xFF.toByte(),
                *values
            )
        } else {
            val values = length.toByteArray()
            byteArrayOf(
                0xFF.toByte(),
                *values
            )
        }
        outputStream.write(lengthBytes)

        var typeByte = typeValue
        if (isCriticalBit) {
            typeByte = typeByte or CRITICAL_BIT
        }

        outputStream.write(typeByte)
    }
}
