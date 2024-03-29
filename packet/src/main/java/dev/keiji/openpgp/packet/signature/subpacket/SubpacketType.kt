@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature.subpacket

enum class SubpacketType(val value: Int) {
    Reserved0(0),
    Reserved1(1),
    SignatureCreationTime(2),
    SignatureExpirationTime(3),
    ExportableCertification(4),
    TrustSignature(5),
    RegularExpression(6),
    Revocable(7),
    Reserved8(8),
    KeyExpirationTime(9),
    PlaceholderForBackwardCompatibility(10),
    PreferredSymmetricAlgorithms(11),
    RevocationKey(12),
    Reserved13(13),
    Reserved14(14),
    Reserved15(15),
    Issuer(16),
    Reserved17(17),
    Reserved18(18),
    Reserved19(19),
    NotationData(20),
    PreferredHashAlgorithms(21),
    PreferredCompressionAlgorithms(22),
    KeyServerPreferences(23),
    PreferredKeyServer(24),
    PrimaryUserId(25),
    PolicyUri(26),
    KeyFlags(27),
    SignerUserId(28),
    ReasonForRevocation(29),
    Features(30),
    SignatureTarget(31),
    EmbeddedSignature(32),
    IssuerFingerprint(33),
    PreferredAeadAlgorithms(34),
    IntendedRecipientFingerprint(35),
    AttestedCertifications(37),
    KeyBlock(38),
    PreferredAeadCiphersuites(39),
    PrivateOrExperimental100(100),
    PrivateOrExperimental101(101),
    PrivateOrExperimental102(102),
    PrivateOrExperimental103(103),
    PrivateOrExperimental104(104),
    PrivateOrExperimental105(105),
    PrivateOrExperimental106(106),
    PrivateOrExperimental107(107),
    PrivateOrExperimental108(108),
    PrivateOrExperimental109(109),
    PrivateOrExperimental110(110),
    ;

    companion object {
        fun findBy(value: Int) = values().firstOrNull { it.value == value }
    }
}
