@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.toHex
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * The gpg-specific GNU Dummy S2K specifier, which marks a secret key
 * as a stub. It consists of the S2K type 101, the 4-octet "\0GNU"
 * magic, a 1-octet mode, and (for the mode 2 "divert to card" stub)
 * a 1-octet length followed by the serial number of the card.
 *
 * This is a gpg extension; it is not part of RFC 9580.
 */
class String2KeyGNUDummyS2K : String2Key() {
    override val type: String2KeyType = String2KeyType.GNU_DUMMY_S2K
    override val length: Int = 0

    var mode: Int = -1
    var serialNumber: ByteArray = byteArrayOf()

    override fun readFrom(inputStream: InputStream) {
        val magic = ByteArray(GNU_MAGIC.size).also {
            inputStream.read(it)
        }
        if (!magic.contentEquals(GNU_MAGIC)) {
            throw IOException("GNU Dummy S2K must start with the ${GNU_MAGIC.toHex()} magic.")
        }

        mode = inputStream.read()

        if (mode == MODE_DIVERT_TO_CARD) {
            val serialNumberLength = inputStream.read()
            serialNumber = ByteArray(serialNumberLength).also {
                inputStream.read(it)
            }
        }
    }

    override fun writeTo(outputStream: OutputStream) {
        outputStream.write(type.id)
        outputStream.write(GNU_MAGIC)
        outputStream.write(mode)

        if (mode == MODE_DIVERT_TO_CARD) {
            outputStream.write(serialNumber.size)
            outputStream.write(serialNumber)
        }
    }

    override fun toDebugString(): String {
        return " * String2KeyGNUDummyS2K\n" +
                "   * mode: $mode\n" +
                "   * serialNumber: ${serialNumber.toHex()}\n" +
                ""
    }

    companion object {
        private val GNU_MAGIC = byteArrayOf(0x00, 'G'.code.toByte(), 'N'.code.toByte(), 'U'.code.toByte())

        private const val MODE_DIVERT_TO_CARD = 2
    }
}
