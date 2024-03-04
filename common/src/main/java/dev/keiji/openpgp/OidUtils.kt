@file:Suppress("MagicNumber")

package dev.keiji.openpgp

import java.io.ByteArrayOutputStream

object OidUtils {
    fun toByteArray(oidStr: String): ByteArray {
        fun addContinueFlagBit(value: Int, next: Boolean = true): Byte? {
            val result = if (value != 0) {
                (value or 0b10000000).toByte()
            } else if (next) {
                0b10000000.toByte()
            } else {
                // value is 0
                return null
            }
            return result
        }

        val tokens = oidStr.split(".").map { it.toInt() }

        val baos = ByteArrayOutputStream()

        baos.write(byteArrayOf((tokens[0] * 40 + tokens[1]).toByte()))

        tokens.forEachIndexed { index, value ->
            if (index == 0 || index == 1) {
                return@forEachIndexed
            }

            if (value < 0b10000000) {
                val byte = (value and 0xFF).toByte()
                baos.write(byteArrayOf(byte))
            } else {
                val value1 = (value and 0b0000_0000000_0000000_0000000_1111111)
                val value2 = (value and 0b0000_0000000_0000000_1111111_0000000) ushr 7
                val value3 = (value and 0b0000_0000000_1111111_0000000_0000000) ushr 14
                val value4 = (value and 0b0000_1111111_0000000_0000000_0000000) ushr 21
                val value5 = (value and 0b1111_0000000_0000000_0000000_0000000.toInt()) ushr 28

                val byte1 = value1.toByte()
                val byte2 = addContinueFlagBit(value2, value3 != 0x0)
                val byte3 = addContinueFlagBit(value3, value4 != 0x0)
                val byte4 = addContinueFlagBit(value4, value5 != 0x0)
                val byte5 = addContinueFlagBit(value5, false)

                if (byte5 != null) {
                    baos.write(byteArrayOf(byte5))
                }
                if (byte4 != null) {
                    baos.write(byteArrayOf(byte4))
                }
                if (byte3 != null) {
                    baos.write(byteArrayOf(byte3))
                }
                if (byte2 != null) {
                    baos.write(byteArrayOf(byte2))
                }

                baos.write(byteArrayOf(byte1))
            }
        }

        return baos.toByteArray()
    }
}
