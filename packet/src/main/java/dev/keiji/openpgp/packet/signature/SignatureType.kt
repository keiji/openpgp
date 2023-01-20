package dev.keiji.openpgp.packet.signature

enum class SignatureType(val value: Int) {
    BinaryDocument(0x00),
    CanonicalTextDocument(0x01),
    Standalone(0x02),
    GenericCertificationOfUserId(0x10),
    PersonaCertificationOfUserId(0x11),
    CasualCertificationOfUserId(0x12),
    PositiveCertificationOfUserId(0x13),
    AttestedKey(0x16),
    SubKeyBinding(0x18),
    PrimaryKeyBinding(0x19),
    SignatureDirectlyOnKey(0x1F),
    KeyRevocation(0x20),
    SubKeyRevocation(0x28),
    CertificationRevocation(0x30),
    Timestamp(0x40),
    ThirdPartyConfirmation(0x50),
    ;

    companion object {
        fun findBy(value: Int) = values().firstOrNull { it.value == value }
    }
}
