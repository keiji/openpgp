package dev.keiji.openpgp.sample

import dev.keiji.openpgp.packet.PacketCompressedData
import dev.keiji.openpgp.packet.PacketDecoder
import dev.keiji.openpgp.packet.Tag
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.signature.PacketSignature
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.verify
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
        PacketDecoder.decode(bytes)
    }

    packetList.forEach { packet ->
        println(packet.toString())
    }

    val signaturePacket = packetList.firstOrNull { it is PacketSignature } as PacketSignature?
    if (signaturePacket == null) {
        println("No signature exist.")
    } else if (signaturePacket is PacketSignatureV4) {
        val publicKeyPacket = packetList.firstOrNull { it is PacketPublicKey } as PacketPublicKey?
        if (publicKeyPacket == null) {
            println("compressedData is not contain any PublicKey packet.")
            return
        }

        signaturePacket.signature?.verify(
            publicKeyPacket,
            signaturePacket.hashAlgorithm,
            signaturePacket.getContentBytes(packetList)
        )
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

        val publicKeyPacket = list.firstOrNull { it is PacketPublicKey } as PacketPublicKey?
        if (publicKeyPacket == null) {
            println("compressedData is not contain any PublicKey packet.")
            return
        }

        val signaturePacket = list.firstOrNull { it is PacketSignature } as PacketSignature?
        if (signaturePacket == null) {
            println("No signature exist.")
        } else if (signaturePacket is PacketSignatureV4) {
            signaturePacket.signature?.verify(
                publicKeyPacket,
                signaturePacket.hashAlgorithm,
                signaturePacket.getContentBytes(packetList)
            )
        }
    }
}
