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
     *
     */
    var pairMap: MutableMap<SymmetricKeyAlgorithm, MutableList<AeadAlgorithm>> = mutableMapOf()

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

                val aaedAlgorithmByte = buff[1].toUnsignedInt()
                val aeadAlgorithm = AeadAlgorithm.findBy(aaedAlgorithmByte)
                    ?: throw UnsupportedAeadAlgorithmException("Aaed algorithm $aaedAlgorithmByte is not supported.")
                val list = pairMap[symmetricKeyAlgorithm] ?: mutableListOf()
                list.add(aeadAlgorithm)

                pairMap[symmetricKeyAlgorithm] = list
            }
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
//        outputStream.write(ids)
    }

    override fun toDebugString(): String {
        val sb = StringBuilder()

        sb.append(
            " * PreferredAeadCiphersuites\n" +
                    ""
        )

        pairMap.keys.forEach { key ->
            pairMap[key]?.forEach { value ->
                sb.append("   * ${key}:${value}\n")
            }
        }

        return sb.toString()
    }
}
