package dev.keiji.openpgp.packet

enum class Tag(val value: Int) {
    Reserved(0),
    PublicKeyEncryptedSessionKey(1),
    Signature(2),
    SymmetricKeyEncryptedSessionKey(3),
    OnePassSignature(4),
    SecretKey(5),
    PublicKey(6),
    SecretSubkey(7),
    CompressedData(8),
    SymmetricallyEncryptedDataPacket(9),
    Marker(10),
    LiteralData(11),
    Trust(12),
    UserId(13),
    PublicSubkey(14),
    UserAttribute(17),
    SymEncryptedAndIntegrityProtectedData(18),
    ModificationDetectionCode(19),
    AeadEncryptedData(20),
    Padding(21),
    PrivateOrExperimentalValue60(60),
    PrivateOrExperimentalValue61(61),
    PrivateOrExperimentalValue62(62),
    PrivateOrExperimentalValue63(63),
    ;

    companion object {
        fun findBy(value: Int) = values().firstOrNull { it.value == value }
    }
}
