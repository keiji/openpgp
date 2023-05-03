package dev.keiji.openpgp

sealed class String2KeyType(
    val name: String,
    val id: Int,
    val fieldLength: Int?,
) {

    object SIMPLE : String2KeyType("Simple", 0, 2)
    object SALTED : String2KeyType("Salted", 1, 10)
    object SALTED_ITERATED : String2KeyType("Salted_Iterated", 3, 11)
    object ARGON2 : String2KeyType("Argon2", 4, 20)

    object GNU_DUMMY_S2K : String2KeyType("GNU_Dummy_S2K", 101, null)

    class Experimental(name: String, id: Int, fieldLength: Int) : String2KeyType(name, id, fieldLength)
    class Private(name: String, id: Int, fieldLength: Int) : String2KeyType(name, id, fieldLength)

    companion object {
        private val PRIVATE_LIST = mutableListOf<String2KeyType>()

        fun add(string2KeyType: Experimental) {
            PRIVATE_LIST.add(string2KeyType)
        }

        fun add(string2KeyType: Private) {
            PRIVATE_LIST.add(string2KeyType)
        }

        fun findBy(id: Int): String2KeyType? = listOf(
            SIMPLE,
            SALTED,
            SALTED_ITERATED,
            ARGON2,
            GNU_DUMMY_S2K,
        ).firstOrNull { it.id == id } ?: PRIVATE_LIST.firstOrNull { it.id == id }
    }
}
