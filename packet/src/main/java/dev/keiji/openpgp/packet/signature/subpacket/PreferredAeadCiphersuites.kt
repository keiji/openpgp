package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.UnsupportedAeadAlgorithmException
import dev.keiji.openpgp.UnsupportedSymmetricKeyAlgorithmException
import dev.keiji.openpgp.toUnsignedInt
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.StringBuilder

class PreferredAeadCiphersuites : Subpacket() {
    override val typeValue: Int = SubpacketType.PreferredAeadCiphersuites.value

    /**
     * The ordered list of cipher/AEAD algorithm pairs, as they appear
     * on the wire.
     */
    val pairList: MutableList<Pair<SymmetricKeyAlgorithm, AeadAlgorithm>> = mutableListOf()

    /**
     * The ciphersuites grouped by symmetric cipher algorithm.
     */
    val pairMap: Map<SymmetricKeyAlgorithm, List<AeadAlgorithm>>
        get() = pairList.groupBy({ it.first }, { it.second })

    override fun readFrom(inputStream: InputStream) {
        val bytes = inputStream.readBytes()
        val pairCount = bytes.size / 2

        val buff = ByteArray(2)
        ByteArrayInputStream(bytes).use { bais ->

            @Suppress("ForEachOnRange")
            (0 until pairCount).forEach { _ ->
                bais.read(buff)

                val symmetricKeyAlgorithmByte = buff[0].toUnsignedInt()
                val symmetricKeyAlgorithm = SymmetricKeyAlgorithm.findBy(symmetricKeyAlgorithmByte)
                    ?: throw UnsupportedSymmetricKeyAlgorithmException(
                        "symmetricKeyAlgorithm id $symmetricKeyAlgorithmByte is not supported."
                    )

                val aeadAlgorithmByte = buff[1].toUnsignedInt()
                val aeadAlgorithm = AeadAlgorithm.findBy(aeadAlgorithmByte)
                    ?: throw UnsupportedAeadAlgorithmException(
                        "Aead algorithm $aeadAlgorithmByte is not supported."
                    )

                pairList.add(symmetricKeyAlgorithm to aeadAlgorithm)
            }
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        pairList.forEach { (symmetricKeyAlgorithm, aeadAlgorithm) ->
            outputStream.write(symmetricKeyAlgorithm.id)
            outputStream.write(aeadAlgorithm.id)
        }
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * PreferredAeadCiphersuites\n" +
                    ""
        )

        pairList.forEach { (symmetricKeyAlgorithm, aeadAlgorithm) ->
            sb.append("   * $symmetricKeyAlgorithm:$aeadAlgorithm\n")
        }

        return sb.toString()
    }
}
