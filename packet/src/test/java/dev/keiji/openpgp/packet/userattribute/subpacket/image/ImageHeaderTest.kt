package dev.keiji.openpgp.packet.userattribute.subpacket.image

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ImageHeaderTest {
    @Test
    fun testToLength() {
        val expected = 16
        val actual = ImageHeader.convertBytesToLength(byteArrayOf(0x10, 0x00))
        assertEquals(expected, actual)
    }
}
