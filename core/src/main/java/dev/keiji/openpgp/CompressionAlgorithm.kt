package dev.keiji.openpgp

enum class CompressionAlgorithm(val id: Int) {
    Uncompressed(0),

    /**
     * ZIP-compression.
     *
     * Compressed with raw [RFC1950] DEFLATE blocks.
     */
    ZIP(1),

    /**
     * ZLIB-compression.
     *
     * Compressed with RFC1950 ZLIB-style blocks.
     */
    ZLIB(2),

    /**
     * BZip2-compression.
     *
     * Compressed using the BZip2 [BZ2] algorithm.
     */
    BZip2(3),

    PrivateExperimentalAlgorithm100(100),
    PrivateExperimentalAlgorithm109(101),
    PrivateExperimentalAlgorithm108(102),
    PrivateExperimentalAlgorithm107(103),
    PrivateExperimentalAlgorithm106(104),
    PrivateExperimentalAlgorithm105(105),
    PrivateExperimentalAlgorithm104(106),
    PrivateExperimentalAlgorithm103(107),
    PrivateExperimentalAlgorithm102(108),
    PrivateExperimentalAlgorithm101(109),
    PrivateExperimentalAlgorithm110(110),
    ;

    companion object {
        fun findBy(id: Int) = values().firstOrNull { it.id == id }
    }
}
