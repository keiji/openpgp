@file:Suppress("MagicNumber")

package dev.keiji.openpgp

enum class EllipticCurveParameter(
    val stdName: String,
    val keyLengthInBit: Int,
    val oidStr: String
) {
    Ed25519("ed25519", 256, "1.3.6.1.4.1.11591.15.1"),
    CV25519("cv25519", 256, "1.3.6.1.4.1.3029.1.5.1"),

    Secp192r1("secp192r1", 192, "1.2.840.10045.3.1.1"),
    Secp256r1("secp256r1", 256, "1.2.840.10045.3.1.7"),
    Secp384r1("secp384r1", 384, "1.3.132.0.34"),
    Secp521r1("secp521r1", 521, "1.3.132.0.35"),

    BrainpoolP160r1("brainpoolP160r1", 160, "1.3.36.3.3.2.8.1.1.1"),
    BrainpoolP192r1("brainpoolP192r1", 192, "1.3.36.3.3.2.8.1.1.3"),
    BrainpoolP224r1("brainpoolP224r1", 224, "1.3.36.3.3.2.8.1.1.5"),
    BrainpoolP256r1("brainpoolP256r1", 256, "1.3.36.3.3.2.8.1.1.7"),
    BrainpoolP320r1("brainpoolP320r1", 320, "1.3.36.3.3.2.8.1.1.9"),
    BrainpoolP384r1("brainpoolP384r1", 384, "1.3.36.3.3.2.8.1.1.11"),
    BrainpoolP512r1("brainpoolP512r1", 512, "1.3.36.3.3.2.8.1.1.13");

    val oid by lazy { OidUtils.toByteArray(oidStr) }

    companion object {
        fun findByOid(oid: ByteArray): EllipticCurveParameter? {
            return values().firstOrNull { it.oid.contentEquals(oid) }
        }

        fun findByOid(oid: String): EllipticCurveParameter? {
            return values().firstOrNull { it.oidStr == oid }
        }
    }
}
