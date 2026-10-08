@file:Suppress("MagicNumber")

package dev.keiji.openpgp

/**
 * https://www.rfc-editor.org/rfc/rfc9580#section-9.3
 */
sealed class SymmetricKeyAlgorithm(
    val name: String,
    val id: Int,
    /**
     * Block length of the cipher in octets, used for example
     * to determine the length of the CFB initialization vector.
     */
    val blockLength: Int,
) {
    object PlaintextOrUnencryptedData : SymmetricKeyAlgorithm("PlaintextOrUnencryptedData", 0, 0)
    object IDEA : SymmetricKeyAlgorithm("IDEA", 1, 8)
    object TripleDES : SymmetricKeyAlgorithm("TripleDES", 2, 8)
    object CAST5 : SymmetricKeyAlgorithm("CAST5", 3, 8)
    object Blowfish : SymmetricKeyAlgorithm("Blowfish", 4, 8)
    object Reserved5 : SymmetricKeyAlgorithm("Reserved5", 5, 0)
    object Reserved6 : SymmetricKeyAlgorithm("Reserved6", 6, 0)
    object AES128 : SymmetricKeyAlgorithm("AES128", 7, 16)
    object AES192 : SymmetricKeyAlgorithm("AES192", 8, 16)
    object AES256 : SymmetricKeyAlgorithm("AES256", 9, 16)
    object Twofish256 : SymmetricKeyAlgorithm("Twofish256", 10, 16)
    object Camellia128 : SymmetricKeyAlgorithm("Camellia128", 11, 16)
    object Camellia192 : SymmetricKeyAlgorithm("Camellia192", 12, 16)
    object Camellia256 : SymmetricKeyAlgorithm("Camellia256", 13, 16)

    class Private(name: String, id: Int, blockLength: Int) :
        SymmetricKeyAlgorithm(name, id, blockLength)

    companion object {
        private val PRIVATE_LIST = mutableListOf<SymmetricKeyAlgorithm>()

        fun add(symmetricKeyAlgorithm: Private) {
            PRIVATE_LIST.add(symmetricKeyAlgorithm)
        }

        fun findBy(id: Int) = listOf(
            PlaintextOrUnencryptedData,
            IDEA,
            TripleDES,
            CAST5,
            Blowfish,
            Reserved5,
            Reserved6,
            AES128,
            AES192,
            AES256,
            Twofish256,
            Camellia128,
            Camellia192,
            Camellia256,
        ).firstOrNull { it.id == id } ?: PRIVATE_LIST.firstOrNull { it.id == id }
    }
}
