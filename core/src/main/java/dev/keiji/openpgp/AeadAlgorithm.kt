package dev.keiji.openpgp

sealed class AeadAlgorithm(
    val id: Int,
    val blockLength: Int,
    val nonceLength: Int,
    val tagLength: Int,
) {
    object EAX : AeadAlgorithm(1, 16, 16, 16)
    object OCB : AeadAlgorithm(2, 16, 15, 16)
    object GCM : AeadAlgorithm(3, 16, 12, 16)

    class Private(
        id: Int,
        blockLength: Int,
        nonceLength: Int,
        tagLength: Int,
    ) : AeadAlgorithm(id, blockLength, nonceLength, tagLength)

    class Experimental(
        id: Int,
        blockLength: Int,
        nonceLength: Int,
        tagLength: Int,
    ) : AeadAlgorithm(id, blockLength, nonceLength, tagLength)

    companion object {
        private val PRIVATE_LIST = mutableListOf<AeadAlgorithm>()

        fun add(privateAeadAlgorithm: Private) {
            PRIVATE_LIST.add(privateAeadAlgorithm)
        }

        fun add(experimentalAlgorithm: Experimental) {
            PRIVATE_LIST.add(experimentalAlgorithm)
        }

        fun findBy(id: Int): AeadAlgorithm? =
            listOf(EAX, OCB, GCM).firstOrNull { it.id == id }
                ?: PRIVATE_LIST.firstOrNull { it.id == id }
    }
}
