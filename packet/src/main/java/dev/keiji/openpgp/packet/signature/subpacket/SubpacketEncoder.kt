package dev.keiji.openpgp.packet.signature.subpacket

import java.io.ByteArrayOutputStream
import java.io.OutputStream

object SubpacketEncoder {

    fun encode(subpacketList: List<Subpacket>, outputStream: OutputStream) {
        subpacketList.forEach { subpacket ->
            val values = ByteArrayOutputStream().let {
                subpacket.writeTo(it)
                it.toByteArray()
            }

            val header = SubpacketHeader().also {
                // The length includes the type-octet but not length-octets.
                it.length = values.size + 1
                it.typeValue = subpacket.getType().value
                it.isCriticalBit = false
            }
            header.writeTo(outputStream)
            subpacket.writeTo(outputStream)
        }
    }
}
