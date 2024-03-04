@file:Suppress("MagicNumber")

package dev.keiji.openpgp

sealed class SymmetricKeyAlgorithm(val name: String, val id: Int) {
    object PlaintextOrUnencryptedData : SymmetricKeyAlgorithm("PlaintextOrUnencryptedData", 0)
    object IDEA : SymmetricKeyAlgorithm("IDEA", 1)
    object TripleDES : SymmetricKeyAlgorithm("TripleDES", 2)
    object CAST5 : SymmetricKeyAlgorithm("CAST5", 3)
    object Blowfish : SymmetricKeyAlgorithm("Blowfish", 4)
    object Reserved5 : SymmetricKeyAlgorithm("Reserved5", 5)
    object Reserved6 : SymmetricKeyAlgorithm("Reserved6", 6)
    object AES128 : SymmetricKeyAlgorithm("AES128", 7)
    object AES192 : SymmetricKeyAlgorithm("AES192", 8)
    object AES256 : SymmetricKeyAlgorithm("AES256", 9)
    object Twofish256 : SymmetricKeyAlgorithm("Twofish256", 10)
    object Camellia128 : SymmetricKeyAlgorithm("Camellia128", 11)
    object Camellia192 : SymmetricKeyAlgorithm("Camellia192", 12)
    object Camellia256 : SymmetricKeyAlgorithm("Camellia256", 13)

    class Private(name: String, id: Int) : SymmetricKeyAlgorithm(name, id)

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
