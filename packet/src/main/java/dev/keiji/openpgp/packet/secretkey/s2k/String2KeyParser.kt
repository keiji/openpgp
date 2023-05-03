package dev.keiji.openpgp.packet.secretkey.s2k

import dev.keiji.openpgp.String2KeyType
import java.io.InputStream

object String2KeyParser {

    fun parse(inputStream: InputStream): String2Key {
        val typeByte = inputStream.read()
        val type = String2KeyType.findBy(typeByte) ?: String2KeyType.SIMPLE

        return when (type) {
            String2KeyType.SIMPLE -> String2KeySimple().also { it.readFrom(inputStream) }
            String2KeyType.SALTED -> String2KeySalted().also { it.readFrom(inputStream) }
            String2KeyType.SALTED_ITERATED -> String2KeySaltedIterated().also {
                it.readFrom(inputStream)
            }
            String2KeyType.ARGON2 -> String2KeyArgon2().also { it.readFrom(inputStream) }
            String2KeyType.GNU_DUMMY_S2K -> {
                String2KeyGNUDummyS2K().also { it.readFrom(inputStream) }
            }
            else -> String2KeySimple().also { it.readFrom(inputStream) }
        }
    }
}
