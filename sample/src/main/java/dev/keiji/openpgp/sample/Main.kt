package dev.keiji.openpgp.sample

import dev.keiji.openpgp.packet.PacketDecoder
import java.io.File
import java.io.FileInputStream
import java.nio.charset.StandardCharsets

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("filePath must be specified.")
        return
    }

    val filePath = args[0]
    val file = File(filePath)

    if (!file.exists()) {
        println("filePath ${file.absolutePath} is not exist.")
        return
    }

    FileInputStream(file).use {
        val encoded = String(it.readAllBytes(), StandardCharsets.UTF_8)
        val packetList = PacketDecoder.decode(encoded)
        packetList.forEach { packet ->
            println(packet.toString())
        }
    }
}
