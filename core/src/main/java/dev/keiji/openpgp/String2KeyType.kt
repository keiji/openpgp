package dev.keiji.openpgp

sealed class String2KeyType(val id: Int, val fieldLength: Int?) {

    object SIMPLE : String2KeyType(0, 2)
    object SALTED : String2KeyType(1, 10)
    object SALTED_ITERATED : String2KeyType(3, 11)
    object ARGON2 : String2KeyType(4, 20)

    class Experimental(id: Int, fieldLength: Int) : String2KeyType(id, fieldLength)
    class Private(id: Int, fieldLength: Int) : String2KeyType(id, fieldLength)

    object GNU_DUMMY_S2K : String2KeyType(101, null)

    companion object {
        fun findBy(id: Int): String2KeyType? = listOf(
            SIMPLE,
            SALTED,
            SALTED_ITERATED,
            ARGON2,
            GNU_DUMMY_S2K,
        ).firstOrNull { it.id == id }
    }
}
