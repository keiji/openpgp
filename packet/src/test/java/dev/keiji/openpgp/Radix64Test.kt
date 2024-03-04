package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.File

class Radix64Test {
    companion object {
        private val LF_PATTERN = "\r(?!\n)|(?<!\r)\n".toRegex()
    }

    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun testEncodeDecode() {
        val data = File(file.absolutePath, "radix64_sample1.txt")
            .readText()
            .replace(LF_PATTERN, "\r\n")
            .trimEnd()
        val decoded = Radix64.decode(data)
        val encoded = Radix64.encode(decoded)

        assertEquals(data, encoded)
    }
}
