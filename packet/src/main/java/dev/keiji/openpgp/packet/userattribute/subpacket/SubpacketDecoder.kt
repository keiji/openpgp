package dev.keiji.openpgp.packet.userattribute.subpacket

import dev.keiji.openpgp.packet.userattribute.subpacket.image.Image
import java.io.ByteArrayInputStream

object SubpacketDecoder {
    interface Callback {
        fun onSubpacketDetected(header: SubpacketHeader, byteArray: ByteArray)
    }

    fun decode(byteArray: ByteArray): List<Subpacket> {
        val packetList = mutableListOf<Subpacket>()

        decode(byteArray, object : Callback {
            override fun onSubpacketDetected(header: SubpacketHeader, byteArray: ByteArray) {
//                println("subpacketType: ${header.typeValue}, length: ${header.length}")

                val tag = SubpacketType.findBy(header.typeValue)
                val bais = ByteArrayInputStream(byteArray)

                val subpacket = when (tag) {
                    SubpacketType.Image -> Image().also { it.readFrom(bais) }
                    else -> Unknown(header.typeValue).also { it.readFrom(bais) }
                }
                packetList.add(subpacket)
            }
        })

        return packetList
    }

    fun decode(byteArray: ByteArray, callback: Callback) {
        val inputStream = ByteArrayInputStream(byteArray)

        while (inputStream.available() > 0) {
            val header = SubpacketHeader().also {
                it.readFrom(inputStream)
            }

            // The length includes the type-octet but not length-octets.
            val bodyLength = header.length - 1

            val data = ByteArray(bodyLength).also {
                inputStream.read(it)
            }
            callback.onSubpacketDetected(header, data)
        }
    }
}
