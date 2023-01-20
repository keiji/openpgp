package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.SymmetricKeyAlgorithm

sealed class SecretKeyEncryptionType(val id: Int) {

    /* cleartext secrets || check(secrets)  */
    object ClearText : SecretKeyEncryptionType(0x00)

    /**
     * Known symmetric cipher algo ID.
     * CFB(MD5(password), secrets || check(secrets))
     */
    class SpecificAlgorithm(algorithm: SymmetricKeyAlgorithm) :
        SecretKeyEncryptionType(algorithm.id)

    /* AEAD(S2K(password), secrets, pubkey) */
    object AEAD : SecretKeyEncryptionType(0xFD)

    /* CFB(S2K(password), secrets || SHA1(secrets)) */
    object SHA1 : SecretKeyEncryptionType(0xFE)

    /* CFB(S2K(password), secrets || check(secrets)) */
    object CheckSum : SecretKeyEncryptionType(0xFF)

    companion object {
        fun findBy(id: Int): SecretKeyEncryptionType? {
            val type = listOf(
                ClearText, AEAD, SHA1, CheckSum,
            ).firstOrNull { it.id == id }
            if (type != null) {
                return type
            }

            val symmetricKeyAlgorithm = SymmetricKeyAlgorithm.findBy(id)
            if (symmetricKeyAlgorithm != null) {
                return SpecificAlgorithm(symmetricKeyAlgorithm)
            }

            return null
        }
    }
}
