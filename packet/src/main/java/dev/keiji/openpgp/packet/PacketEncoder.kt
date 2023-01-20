package dev.keiji.openpgp.packet

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.math.BigInteger

object PacketEncoder {
    fun encode(isOld: Boolean, packetList: List<Packet>, outputStream: OutputStream) {
        packetList.forEach { packet ->
            val values = ByteArrayOutputStream().let { baos ->
                packet.writeTo(baos)
                baos.toByteArray()
            }
            val length = values.size

            val header = PacketHeader().also { packetHeader ->
                packetHeader.isOld = isOld
                packetHeader.length = BigInteger.valueOf(length.toLong())
                packetHeader.tagValue = packet.tagValue
            }

            header.writeTo(outputStream)
            outputStream.write(values)
        }
    }
}
