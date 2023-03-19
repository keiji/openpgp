package dev.keiji.openpgp

import java.io.InputStream

class Crc24(
    private var initial: Int = RFC4880_INITIAL,
    private var generator: Int = RFC4880_GENERATOR,
) {
    companion object {
        const val RFC4880_INITIAL = 0xB704CE
        const val RFC4880_GENERATOR = 0x864CFB

        private const val RESULT_BYTE_LENGTH = 3

        fun to3ByteArray(value: Int): ByteArray {
            return ByteArray(RESULT_BYTE_LENGTH).also {
                it[0] = (value shr 16).toByte()
                it[1] = (value shr 8).toByte()
                it[2] = (value shr 0).toByte()
            }
        }
    }

    private var _value: Int = initial
    val value: ByteArray
        get() {
            val intValue = _value and 0xFFFFFF
            return to3ByteArray(intValue)
        }

    fun reset() {
        _value = initial
    }

    fun update(inputStream: InputStream) {
        while (true) {
            val b = inputStream.read()
            if (b < 0) {
                break
            }
            update(b)
        }
    }

    fun update(b: Byte) {
        _value = _value xor (b.toUnsignedInt() shl 16)
        (0 until 8).forEach { _ ->
            _value = _value shl 1
            if ((_value and 0x1000000) != 0) {
                _value = _value xor generator
            }
        }
    }

    fun update(i: Int) {
        _value = _value xor (i shl 16)
        (0 until 8).forEach { _ ->
            _value = _value shl 1
            if ((_value and 0x1000000) != 0) {
                _value = _value xor generator
            }
        }
    }
}
