package dev.keiji.openpgp.packet

import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeyArgon2
import dev.keiji.openpgp.packet.skesk.PacketSymmetricKeyEncryptedSessionKeyV4
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * RFC 9580 Appendix A.12: messages encrypted using an Argon2 S2K
 * (v4 SKESK + v1 SEIPD), with three session key sizes.
 */
class PacketDecoderArgon2SkeskTest {

    private val armoredMessages = listOf(
        // A.12.1 V4 SKESK Using Argon2 with AES-128.
        """
-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 128-bit key

wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+
YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH
XfA3pqV4mTzF
-----END PGP MESSAGE-----
        """,
        // A.12.2 V4 SKESK Using Argon2 with AES-192.
        """
-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 192-bit key

wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw
F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys
LVg77Mwwfgl2n/d572WciAM=
-----END PGP MESSAGE-----
        """,
        // A.12.3 V4 SKESK Using Argon2 with AES-256.
        """
-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 256-bit key

wzcECQS4eJUgIG/3mcaILEJFpmJ8AQQVnZ9l7KtagdClm9UaQ/Z6M/5roklSGpGu
623YmaXezGj80j4B+Ku1sgTdJo87X1Wrup7l0wJypZls21Uwd67m9koF60eefH/K
95D1usliXOEm8ayQJQmZrjf6K6v9PWwqMQ==
-----END PGP MESSAGE-----
        """,
    )

    private val expectedSessionKeySizes = listOf(16, 24, 32)

    @Test
    fun decodeArgon2SkeskTest() {
        armoredMessages.forEachIndexed { index, armored ->
            val pgpData = PgpData.loadAsciiArmored(
                ByteArrayInputStream(
                    armored.trimIndent().toByteArray(charset = StandardCharsets.UTF_8)
                )
            )
            val data = pgpData.blockList.firstOrNull()?.data
            assertTrue(data != null)
            data ?: return

            val packetList = PacketDecoder.decode(data)
            assertEquals(2, packetList.size)

            val skesk = packetList[0]
            assertEquals(Tag.SymmetricKeyEncryptedSessionKey, skesk.tag)
            assertTrue(skesk is PacketSymmetricKeyEncryptedSessionKeyV4)
            if (skesk is PacketSymmetricKeyEncryptedSessionKeyV4) {
                assertEquals(4, skesk.version)
                assertEquals(String2KeyType.ARGON2, skesk.string2Key?.type)

                val string2Key = skesk.string2Key
                assertTrue(string2Key is String2KeyArgon2)
                if (string2Key is String2KeyArgon2) {
                    // t = 1, p = 4, m = 2^21 KiB.
                    assertEquals(1, string2Key.passes)
                    assertEquals(4, string2Key.parallelism)
                    assertEquals(21, string2Key.memorySizeExponent)
                    assertEquals(16, string2Key.salt.size)
                }

                // The encrypted session key is the symmetric algorithm octet
                // followed by the session key of the given size.
                assertEquals(1 + expectedSessionKeySizes[index], skesk.encryptedSessionKey?.size)
            }

            // Round-trip must be byte-exact.
            val actual = ByteArrayOutputStream().let {
                PacketEncoder.encode(packetList, it)
                it.toByteArray()
            }
            assertArrayEquals(data, actual)
        }
    }
}
