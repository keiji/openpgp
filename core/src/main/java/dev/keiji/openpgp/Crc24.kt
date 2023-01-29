package dev.keiji.openpgp

import java.io.InputStream

class Crc24(
    private var initial: Int = RFC4880_INITIAL,
    private var generator: Int = RFC4880_GENERATOR,
) {
    companion object {
        const val RFC4880_INITIAL = 0xB704CE
        const val RFC4880_GENERATOR = 0x864CFB
    }

    private var _value: Int = initial
    val value: Int
        get() = _value and 0xFFFFFF

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
