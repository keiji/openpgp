package dev.keiji.openpgp

enum class HashAlgorithm(
    val id: Int,
    val textName: String,
) {
    MD5(1, "MD5"),
    SHA1(2, "SHA1"),
    RIPE_MD160(3, "RIPEMD160"),
    Reserved4(4, ""),
    Reserved5(5, ""),
    Reserved6(6, ""),
    Reserved7(7, ""),
    SHA2_256(8, "SHA-256"),
    SHA2_384(9, "SHA384"),
    SHA2_512(10, "SHA512"),
    SHA2_224(11, "SHA224"),
    SHA3_256(12, "SHA3-256"),
    Reserved13(13, ""),
    SHA3_512(14, "SHA3-512"),
    PrivateExperimental100(100, ""),
    PrivateExperimental101(101, ""),
    PrivateExperimental102(102, ""),
    PrivateExperimental103(103, ""),
    PrivateExperimental104(104, ""),
    PrivateExperimental105(105, ""),
    PrivateExperimental106(106, ""),
    PrivateExperimental107(107, ""),
    PrivateExperimental108(108, ""),
    PrivateExperimental109(109, ""),
    PrivateExperimental110(110, ""),
    ;

    companion object {
        fun findBy(id: Int) = values().firstOrNull { it.id == id }
    }
}
