package dev.keiji.openpgp.sample

import dev.keiji.openpgp.packet.Packet
import dev.keiji.openpgp.packet.PacketCompressedData
import dev.keiji.openpgp.packet.PacketDecoder
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.signature.PacketSignature
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.toHex
import java.io.ByteArrayInputStream
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
        val bytes = it.readAllBytes()
        val encoded = String(bytes, StandardCharsets.UTF_8)
        if (isAsciiArmoredForm(encoded)) {
            PacketDecoder.decode(encoded)
        } else {
            PacketDecoder.decode(ByteArrayInputStream(bytes))
        }
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

    val hasCompressedData = packetList.any { it.tag == Tag.CompressedData }
    if (!hasCompressedData) {
        println("No compressedData exist.")
    } else {
        val compressedData = packetList.first { it.tag == Tag.CompressedData } as PacketCompressedData
        val list = PacketDecoder.decode(compressedData.rawDataInputStream)
        list.forEach {
            println(it)
        }

        val hasSignature = list.any { it.tag == Tag.Signature }
        if (!hasSignature) {
            println("No signature exist.")
        } else {
            verify(list)
        }
    }
}

fun isAsciiArmoredForm(encoded: String): Boolean {
    val lines = encoded.lines()
    if (lines.size < 4) {
        return false
    }

    if (lines[1].isNotBlank()) {
        return false
    }

    val linesNotBlank = lines.filter { it.isNotBlank() }

    if (!linesNotBlank.first().startsWith("-----") || !linesNotBlank.first().endsWith("-----")) {
        return false
    }

    if (!linesNotBlank.last().startsWith("-----") || !linesNotBlank.last().endsWith("-----")) {
        return false
    }

    val content = linesNotBlank
        .subList(1, lines.size - 2)
        .joinToString("")
    println(content)

    return true

}

private fun verify(packetList: List<Packet>) {
    var signatureTarget: Packet? = null
    packetList.forEach {
        if (signatureTarget != null && it is PacketSignature) {
            verify(signatureTarget!!, it)
        }
        signatureTarget = it
    }
}

private fun verify(signatureTarget: Packet, signature: PacketSignature) {
    val hashBytes = signature.hash(listOf(signatureTarget))
    println("signature.hash")
    println(hashBytes.toHex(""))
}
