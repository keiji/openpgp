package dev.keiji.openpgp.sample

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.PacketDecoder
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.signature.PacketSignature
import dev.keiji.openpgp.toHex
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

    val packetList = FileInputStream(file).use {
        val encoded = String(it.readAllBytes(), StandardCharsets.UTF_8)
        PacketDecoder.decode(encoded)
    }

    packetList.forEach { packet ->
        println(packet.toString())
    }

    val hasSignature = packetList.any { it.tag == Tag.Signature }
    if (!hasSignature) {
        println("No signature exist.")
    } else {
        verify(packetList)
    }
}

private fun verify(packetList: List<Packet>) {
    val signatureTarget: MutableList<Packet> = mutableListOf()
    packetList.forEach {
        if (it is PacketSignature) {
            verify(signatureTarget, it)
        }
        signatureTarget.add(it)
    }
}

private fun verify(signatureTarget: List<Packet>, signature: PacketSignature) {
    val hashBytes = signature.hash(signatureTarget)
    println("signature.hash")
    println(hashBytes.toHex(""))
}
