package dev.keiji.openpgp.packet

import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.OpenPgpAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.publickey.PublicKeyEddsa
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.File
import java.nio.charset.StandardCharsets

class PacketDecoderPublicKeyV4Test0 {

    companion object {
        // Test vector from draft-ietf-openpgp-crypto-refresh-07
        private val TEST_VECTOR_SAMPLE_V4_ED25519_KEY = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku
Q+47JAY=
-----END PGP PUBLIC KEY BLOCK-----
        """
            .replace("\r\n", "\n")
            .trimIndent()
    }

    @Test
    fun decodeCallbackTest0() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(TEST_VECTOR_SAMPLE_V4_ED25519_KEY.toByteArray(charset = StandardCharsets.UTF_8))
        )
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        PacketDecoder.decode(
            data,
            object : PacketDecoder.Callback {
                override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                    println("${header.isLegacyFormat}: ${header.tagValue}: ${header.length}")

                    when (header.tagValue) {
                        0x06 -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("51", header.length.toString())
                        }
                    }
                }
            })
    }

    @Test
    fun decodePublicKeyEddsaTest0() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(TEST_VECTOR_SAMPLE_V4_ED25519_KEY.toByteArray(charset = StandardCharsets.UTF_8))
        )
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        val packetList = PacketDecoder.decode(data)
        assertEquals(1, packetList.size)

        val packetPublicKey = packetList[0]
        assertEquals(Tag.PublicKey, packetPublicKey.tag)
        assertTrue(packetPublicKey is PacketPublicKeyV4)
        if (packetPublicKey is PacketPublicKeyV4) {
            assertEquals(4, packetPublicKey.version)
            assertEquals(OpenPgpAlgorithm.EDDSA, packetPublicKey.algorithm)

            val publicKey = packetPublicKey.publicKey
            assertTrue(publicKey is PublicKeyEddsa)
            if (publicKey is PublicKeyEddsa) {
                assertEquals(EllipticCurveParameter.Ed25519, publicKey.ellipticCurveParameter)
                assertEquals(
                    "403F098994BDD916ED4053197934E4A87C80733A1280D62F8010992E43EE3B2406",
                    publicKey.ecPoint?.toHex("")
                )
            }

            assertEquals(1408458507, packetPublicKey.createdDateTimeEpoch)
        }
    }
}
