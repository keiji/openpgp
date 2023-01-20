package dev.keiji.openpgp

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

class OidUtilsTest {
    @Test
    fun oidToByteArrayTest1() {
        // MD5
        val oid = "1.2.840.113549.2.5"
        val expected = byteArrayOf(
            0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x02, 0x05
        )

        val actual = OidUtils.toByteArray(oid)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun oidToByteArrayTest2() {
        // domainComponent
        val oid = "0.9.2342.19200300.100.1.25"
        val expected = byteArrayOf(
            0x09,
            0x92.toByte(),
            0x26,
            0x89.toByte(),
            0x93.toByte(),
            0xF2.toByte(),
            0x2C,
            0x64,
            0x01,
            0x19
        )

        val actual = OidUtils.toByteArray(oid)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun oidToByteArrayTest3() {
        // secp384r1
        val oid = "1.3.132.0.34"
        val expected = byteArrayOf(
            0x2B, 0x81.toByte(), 0x04, 0x00, 0x22
        )

        val actual = OidUtils.toByteArray(oid)

        assertArrayEquals(expected, actual)
    }

    @Test
    fun oidToByteArrayTest4() {
        // EdDSA
        val oid = "1.3.6.1.4.1.11591.15.1"
        val expected = byteArrayOf(
            0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA.toByte(), 0x47, 0x0F, 0x01
        )

        val actual = OidUtils.toByteArray(oid)

        assertArrayEquals(expected, actual)
    }
}