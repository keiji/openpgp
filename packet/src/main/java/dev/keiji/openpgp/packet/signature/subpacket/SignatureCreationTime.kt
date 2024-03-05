@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.toByteArray
import dev.keiji.openpgp.toInt
import java.io.InputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.*

private val DATE_FORMAT = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX")

class SignatureCreationTime : Subpacket() {
    override val typeValue: Int = SubpacketType.SignatureCreationTime.value

    var value: Int = -1

    override fun readFrom(inputStream: InputStream) {
        value = ByteArray(4).let {
            inputStream.read(it)
            it.toInt()
        }
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val bytes = value.toByteArray()
        outputStream.write(bytes)
    }

    override fun toDebugString(): String {
        val cal = Calendar.getInstance().also {
            it.timeInMillis = value * 1000L
        }
        val dateTime = DATE_FORMAT.format(cal.time)
        return " * SignatureCreationTime\n" +
                "   * value: ${dateTime} ($value)\n" +
                ""
    }
}
