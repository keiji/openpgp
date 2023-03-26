package dev.keiji.openpgp

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import java.io.InputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

interface CompressionAlgorithm {
    val id: Int
    val textName: String
    fun getInputStream(dataInputStream: InputStream): InputStream

    interface Private : CompressionAlgorithm

    object Uncompressed : CompressionAlgorithm {
        override val id = 0
        override val textName: String = "Uncompressed"

        override fun getInputStream(dataInputStream: InputStream) = dataInputStream
    }

    /**
     * ZIP-compression.
     *
     * Compressed with raw [RFC1950] DEFLATE blocks.
     */
    object ZIP : CompressionAlgorithm {
        override val id = 1
        override val textName: String = "ZIP"

        override fun getInputStream(dataInputStream: InputStream): InputStream {
            return InflaterInputStream(dataInputStream, Inflater(true))
        }

        override fun toString(): String {
            return "$textName($id)"
        }
    }

    /**
     * ZLIB-compression.
     *
     * Compressed with RFC1950 ZLIB-style blocks.
     */
    object ZLIB : CompressionAlgorithm {
        override val id = 2
        override val textName: String = "ZLIB"

        override fun getInputStream(dataInputStream: InputStream): InputStream {
            return InflaterInputStream(dataInputStream)
        }

        override fun toString(): String {
            return "${ZIP.textName}(${ZIP.id})"
        }
    }

    /**
     * BZip2-compression.
     *
     * Compressed using the BZip2 [BZ2] algorithm.
     */
    object BZip2 : CompressionAlgorithm {
        override val id = 3
        override val textName: String = "BZip2"

        override fun getInputStream(dataInputStream: InputStream): InputStream {
            return BZip2CompressorInputStream(dataInputStream)
        }

        override fun toString(): String {
            return "${ZIP.textName}(${ZIP.id})"
        }
    }

    companion object {
        private val PRIVATE_LIST = mutableListOf<CompressionAlgorithm>()

        fun add(privateCompressionAlgorithm: Private) {
            PRIVATE_LIST.add(privateCompressionAlgorithm)
        }

        fun findBy(id: Int): CompressionAlgorithm? =
            listOf(Uncompressed, ZIP, ZLIB, BZip2).firstOrNull { it.id == id }
                ?: PRIVATE_LIST.firstOrNull { it.id == id }
    }
}
