@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.publickey

import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toInt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

abstract class PacketPublicKey : Packet() {
    override val tagValue: Int = Tag.PublicKey.value

    abstract val version: Int

    var createdDateTimeEpoch: Int = -1

    var publicKey: PublicKey? = null
    var algorithm: PublicKeyAlgorithm = PublicKeyAlgorithm.ECDSA

    override fun readContentFrom(inputStream: InputStream) {
        val createdDateTimeEpochBytes = ByteArray(4)
        inputStream.read(createdDateTimeEpochBytes)
        createdDateTimeEpoch = createdDateTimeEpochBytes.toInt()
    }

    override fun writeContentTo(outputStream: OutputStream) {
        outputStream.write(version)
        outputStream.write(createdDateTimeEpoch.toByteArray())
    }

    /**
     * Convert explicitly from PacketPublicKey or PacketSecretKey to PacketPublicKey object.
     */
    internal fun convertToWxplicitPacketPublicKey(): PacketPublicKey {
        return ByteArrayOutputStream().let {
            writeContentTo(it)
            val keyPacketBytes = it.toByteArray()
            PacketPublicKeyParser.parse(ByteArrayInputStream(keyPacketBytes))
        }
    }
}
