package dev.keiji.openpgp

private const val MASK_1ST_BYTE: Int = 0xFF
private const val MASK_2ND_BYTE: Int = MASK_1ST_BYTE shl 8
private const val MASK_3RD_BYTE: Int = MASK_2ND_BYTE shl 8
private const val MASK_4TH_BYTE: Int = MASK_3RD_BYTE shl 8

fun Byte.toUnsignedInt() = this.toInt() and MASK_1ST_BYTE

fun Int.toHex() = "%02x".format(this).uppercase()

fun Byte.toHex() = "%02x".format(this).uppercase()
fun ByteArray.toHex(delimiter: String = "") = joinToString(delimiter) { it.toHex() }

fun Int.toByteArray(): ByteArray {
    val result = ByteArray(4)
    result[3] = (this and MASK_1ST_BYTE).toByte()
    result[2] = ((this and MASK_2ND_BYTE) ushr 8).toByte()
    result[1] = ((this and MASK_3RD_BYTE) ushr 16).toByte()
    result[0] = ((this and MASK_4TH_BYTE) ushr 24).toByte()
    return result
}

fun ByteArray.toInt(): Int {
    val lastIndex = Int.SIZE_BYTES - 1
    val offset = Int.SIZE_BYTES - this.size

    var result = 0

    this.forEachIndexed { index, byte ->
        if (index > lastIndex) {
            return@forEachIndexed
        }

        val value = byte.toInt() and MASK_1ST_BYTE
        val shift = (lastIndex - index + offset) * 8
        result = result or (value shl shift)
    }
    return result
}

fun Int.to2ByteArray(): ByteArray {
    val result = ByteArray(2)
    result[1] = (this and MASK_1ST_BYTE).toByte()
    result[0] = ((this and MASK_2ND_BYTE) ushr 8).toByte()
    return result
}

private const val MASK_1ST_BYTE_LONG: Long = 0xFF
private const val MASK_2ND_BYTE_LONG: Long = MASK_1ST_BYTE_LONG shl 8
private const val MASK_3RD_BYTE_LONG: Long = MASK_2ND_BYTE_LONG shl 8
private const val MASK_4TH_BYTE_LONG: Long = MASK_3RD_BYTE_LONG shl 8
private const val MASK_5TH_BYTE_LONG: Long = MASK_4TH_BYTE_LONG shl 8
private const val MASK_6TH_BYTE_LONG: Long = MASK_5TH_BYTE_LONG shl 8
private const val MASK_7TH_BYTE_LONG: Long = MASK_6TH_BYTE_LONG shl 8
private const val MASK_8TH_BYTE_LONG: Long = MASK_7TH_BYTE_LONG shl 8

fun Long.toByteArray(): ByteArray {
    val result = ByteArray(8)
    result[7] = (this and MASK_1ST_BYTE_LONG).toByte()
    result[6] = ((this and MASK_2ND_BYTE_LONG) ushr 8).toByte()
    result[5] = ((this and MASK_3RD_BYTE_LONG) ushr 16).toByte()
    result[4] = ((this and MASK_4TH_BYTE_LONG) ushr 24).toByte()
    result[3] = ((this and MASK_5TH_BYTE_LONG) ushr 32).toByte()
    result[2] = ((this and MASK_6TH_BYTE_LONG) ushr 40).toByte()
    result[1] = ((this and MASK_7TH_BYTE_LONG) ushr 48).toByte()
    result[0] = ((this and MASK_8TH_BYTE_LONG) ushr 56).toByte()
    return result
}

fun ByteArray.toLong(): Long {
    val lastIndex = Long.SIZE_BYTES - 1
    val offset = Long.SIZE_BYTES - this.size

    var result: Long = 0

    this.forEachIndexed { index, byte ->
        if (index > lastIndex) {
            return@forEachIndexed
        }

        val value = byte.toLong() and MASK_1ST_BYTE_LONG
        val shift = (lastIndex - index + offset) * 8
        result = result or (value shl shift)
    }
    return result
}

fun parseHexString(hexString: String, delimiter: String? = null): ByteArray {
    if (delimiter == null) {
        require(hexString.length % 2 == 0) {
            "If delimiter is null, hexString length must be even number. (length: ${hexString.length})"
        }
        return hexString.chunked(2)
            .filter { it.isNotEmpty() }
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
    return hexString.split(delimiter)
        .filter { it.isNotEmpty() }
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
