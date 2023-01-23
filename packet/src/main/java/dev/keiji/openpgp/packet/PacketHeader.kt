package dev.keiji.openpgp.packet

import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.InvalidParameterException
import kotlin.experimental.or

private const val HIGHER_BIT = 0b10000000
private const val IS_NEW_PACKET_FORMAT = 0b01000000

private const val NEW_PACKET_FORMAT_PACKET_TAG = 0b00111111

private const val OLD_PACKET_FORMAT_PACKET_TAG = 0b00111100
private const val OLD_PACKET_FORMAT_LENGTH_TYPE = 0b00000011
private const val OLD_PACKET_FORMAT_LENGTH_ONE_OCTET = 0
private const val OLD_PACKET_FORMAT_LENGTH_TWO_OCTETS = 1
private const val OLD_PACKET_FORMAT_LENGTH_FOUR_OCTETS = 2
// private const val OLD_PACKET_FORMAT_LENGTH_INDETERMINATE = 3

class PacketHeader {
    var isOld: Boolean = false

    var tagValue: Int = 0
    var length: BigInteger = BigInteger.ZERO

    fun readFrom(inputStream: InputStream) {
        val firstByte = inputStream.read()
        isOld = !(firstByte and IS_NEW_PACKET_FORMAT == IS_NEW_PACKET_FORMAT)
        if (isOld) {
            readOldFormatFrom(firstByte, inputStream)
        } else { // New format packet-length
            readNewFormatFrom(firstByte, inputStream)
        }
    }

    private fun readOldFormatFrom(firstByte: Int, inputStream: InputStream) {
        tagValue = (firstByte and OLD_PACKET_FORMAT_PACKET_TAG) ushr 2

        val lengthType = firstByte and OLD_PACKET_FORMAT_LENGTH_TYPE
        val lengthOctets = when (lengthType) {
            OLD_PACKET_FORMAT_LENGTH_ONE_OCTET -> 1
            OLD_PACKET_FORMAT_LENGTH_TWO_OCTETS -> 2
            OLD_PACKET_FORMAT_LENGTH_FOUR_OCTETS -> 4
            else -> throw UnsupportedOperationException("Indeterminate length not supported.")
        }

        val lengthBytes = ByteArray(lengthOctets)
        inputStream.read(lengthBytes)
        length = BigInteger(+1, lengthBytes)
    }

    private fun readNewFormatFrom(firstByte: Int, inputStream: InputStream) {
        tagValue = firstByte and NEW_PACKET_FORMAT_PACKET_TAG
        length = decodeNewPacketLength(inputStream)
    }

    fun writeTo(outputStream: OutputStream) {
        if (isOld) {
            writeAsOldFormatTo(outputStream)
        } else {
            writeAsNewFormatTo(outputStream)
        }
    }

    private fun writeAsOldFormatTo(outputStream: OutputStream) {
        if (tagValue > 0b1111) {
            throw InvalidParameterException("`tag.value` must not be greater than 16, because old format tag have only 4 bit width.")
        }

        val lengthBytes = length.toByteArray()
        val offset = if (lengthBytes.first() == 0x00.toByte()) 1 else 0

        val bitLength = length.bitLength()
        val byteLength = bitLength / Byte.SIZE_BITS + if (bitLength % Byte.SIZE_BITS == 0) 0 else 1

        val lengthType = when {
            // One octet
            byteLength <= 1 -> 0

            // Two octets
            byteLength <= 2 -> 1

            // Four octets
            byteLength <= 4 -> 2

            // Indeterminate
            else -> 3
        }

        val firstByte = (tagValue shl 2) or lengthType or HIGHER_BIT
        outputStream.write(firstByte)
        outputStream.write(lengthBytes, offset, lengthBytes.size - offset)
    }

    private fun writeAsNewFormatTo(outputStream: OutputStream) {
        outputStream.write(tagValue or IS_NEW_PACKET_FORMAT or HIGHER_BIT)
        outputStream.write(encodeNewPacketLength(length))
    }

    companion object {
        // See RFC4880Bis
        fun decodeNewPacketLength(inputStream: InputStream): BigInteger {
            val octet1st = inputStream.read() and 0xFF
            if (octet1st < 192) {
                // One octet
                return BigInteger(+1, byteArrayOf(octet1st.toByte()))
            } else if (octet1st < 224) {
                // Two octets
                val octet2nd = inputStream.read()
                val bodyLen = ((octet1st - 192) shl 8) + (octet2nd + 192)
                return BigInteger.valueOf(bodyLen.toLong())
            } else if (octet1st < 0xFF) {
                // Partial
                throw UnsupportedOperationException("Partial Body Lengths $octet1st not supported")
            } else { // firstByte == 0xFF
                // Five octets
                val octet2nd = inputStream.read().toLong()
                val octet3rd = inputStream.read().toLong()
                val octet4th = inputStream.read().toLong()
                val octet5th = inputStream.read().toLong()
                val bodyLen = (octet2nd shl 24) or (octet3rd shl 16) or (octet4th shl 8) or octet5th
                return BigInteger.valueOf(bodyLen)
            }
        }

        private val THRESHOLD_192 = BigInteger.valueOf(192)
        private val THRESHOLD_8383 = BigInteger.valueOf(8383)
        private val THRESHOLD_MAX_UNSIGNED_INTEGER = BigInteger.valueOf(0xFFFFFFFF)

        fun encodeNewPacketLength(length: BigInteger): ByteArray {
            when {
                length < THRESHOLD_192 -> {
                    // One octet
                    return byteArrayOf(length.toByte())
                }

                length <= THRESHOLD_8383 -> {
                    // Two octets
                    val resultLength = 2
                    val result = ByteArray(resultLength)
                    val values = length.minus(THRESHOLD_192).toByteArray()
                    val offset = if (values.first() == 0x00.toByte()) 1 else 0
                    val valuesLength = values.size - offset
                    System.arraycopy(
                        values,
                        offset,
                        result,
                        resultLength - valuesLength,
                        valuesLength
                    )
                    result[0] = result[0].or(0b11000000.toByte())
                    return result
                }

                length <= THRESHOLD_MAX_UNSIGNED_INTEGER -> {
                    // Five octets
                    val resultLength = 4
                    val result = ByteArray(resultLength + 1 /* with header 1 byte */).also {
                        it[0] = 0xFF.toByte()
                    }
                    val values = length.toByteArray()
                    val offset = if (values.first() == 0x00.toByte()) 1 else 0
                    val valuesLength = values.size - offset
                    System.arraycopy(
                        values,
                        offset,
                        result,
                        resultLength - valuesLength + 1 /* consider 1 byte header */,
                        valuesLength
                    )
                    return result
                }

                else -> {
                    // Partial
                    throw UnsupportedOperationException("Partial Body Lengths not supported")
                }
            }
        }
    }
}
