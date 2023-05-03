package dev.keiji.openpgp

/**
 * https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-08#name-public-key-algorithms
 */
enum class PublicKeyAlgorithm(val id: Int) {
    RSA_ENCRYPT_OR_SIGN(1 /* 0x01 */),
    RSA_ENCRYPT_ONLY(2),
    RSA_SIGN_ONLY(3),
    ELGAMAL_ENCRYPT_ONLY(16),
    DSA(17),
    ECDH(18 /* 0x12 */),
    ECDSA(19 /* 0x13 */),
    RESERVED_20(20), // formerly Elgamal Encrypt or Sign
    RESERVED_FOR_DIFFIE_HELLMAN(21), // X9.42, as defined for IETF-S/MIME

    @Deprecated("")
    EDDSA_LEGACY(22 /* 0x16 */),

    RESERVED_FOR_AEDH(23),
    RESERVED_FOR_AEDSA(24),

    X25519(25),
    X448(26),
    ED25519(27),
    ED448(28),

    ExperimentalAlgorithm100(100),
    ExperimentalAlgorithm109(101),
    ExperimentalAlgorithm108(102),
    ExperimentalAlgorithm107(103),
    ExperimentalAlgorithm106(104),
    ExperimentalAlgorithm105(105),
    ExperimentalAlgorithm104(106),
    ExperimentalAlgorithm103(107),
    ExperimentalAlgorithm102(108),
    ExperimentalAlgorithm101(109),
    ExperimentalAlgorithm110(110),
    ;

    companion object {
        fun findById(id: Int) = values().firstOrNull { it.id == id }
    }
}
