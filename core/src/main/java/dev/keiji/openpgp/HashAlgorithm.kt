package dev.keiji.openpgp

sealed class HashAlgorithm(
    val id: Int,
    val textName: String,
    val oid: ByteArray? = null,
) {
    object MD5 : HashAlgorithm(
        1, "MD5",
        // 1.2.840.113549.2.5
        byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x02, 0x05, 0x05)
    )

    object SHA1 : HashAlgorithm(
        2, "SHA1",
        // 1.3.14.3.2.26
        byteArrayOf(0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05)
    )

    object RIPE_MD160 : HashAlgorithm(
        3, "RIPEMD160",
        // 1.3.36.3.2.1
        byteArrayOf(0x2B, 0x24, 0x03, 0x02, 0x01)
    )

    object Reserved4 : HashAlgorithm(4, "Reserved4")
    object Reserved5 : HashAlgorithm(5, "Reserved5")
    object Reserved6 : HashAlgorithm(6, "Reserved6")
    object Reserved7 : HashAlgorithm(7, "Reserved7")

    object SHA2_256 : HashAlgorithm(
        8, "SHA256",
        // 2.16.840.1.101.3.4.2.1
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
    )

    object SHA2_384 : HashAlgorithm(
        9, "SHA384",
        // 2.16.840.1.101.3.4.2.2
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)
    )

    object SHA2_512 : HashAlgorithm(
        10, "SHA512",
        // 2.16.840.1.101.3.4.2.3
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)
    )

    object SHA2_224 : HashAlgorithm(
        11, "SHA224",
        // 2.16.840.1.101.3.4.2.4
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04)
    )

    object SHA3_256 : HashAlgorithm(
        12, "SHA3-256",
        // 2.16.840.1.101.3.4.2.8
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08)
    )

    object Reserved13 : HashAlgorithm(13, "Reserved13")

    object SHA3_512 : HashAlgorithm(
        14, "SHA3-512",
        // 2.16.840.1.101.3.4.2.10
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A)
    )

    companion object {
        private val ORIGINAL = listOf(
            MD5,
            SHA1,
            RIPE_MD160,
            Reserved4,
            Reserved5,
            Reserved6,
            Reserved7,
            SHA2_256,
            SHA2_384,
            SHA2_512,
            SHA2_256,
            SHA2_224,
            SHA3_256,
            Reserved13,
            SHA3_512
        )

        fun findBy(id: Int) = ORIGINAL.firstOrNull { it.id == id }
    }
}
