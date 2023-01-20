package dev.keiji.openpgp.packet

import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

class Radix64Test {

    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun testEncodeDecode() {
        val data = File(file.absolutePath, "radix64_sample1.txt")
            .readText()
            .replace("\r\n", "\n")
            .trimEnd()
        val decoded = Radix64.decode(data)
        println(decoded.toHex(":"))

        val encoded = Radix64.encode(decoded)
        println(encoded)
        assertEquals(data, encoded)
    }
}
