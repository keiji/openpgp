package dev.keiji.openpgp.packet

import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.OpenPgpAlgorithm
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV5
import dev.keiji.openpgp.packet.publickey.PublicKeyEddsa
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail

class PacketDecoderCertificateV5Test {

    companion object {
        // Test vector from draft-ietf-openpgp-crypto-refresh-07
        private val TEST_VECTOR_SAMPLE_V5_ED25519_CERTIFICATE = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
xjcFYiDQVxYAAAAtCSsGAQQB2kcPAQEHQLVQ/UIL3goq8tqYyAhqx19AG5YH
uMyAHjCOTyUpVKtRwqgFHxYKAAAAIwUCYiDQVwMVCAoEFgACAQIbAwIeCQ0n
CQMHAwkBBwEJAgcCAAAAIyIhBRtEKdW2+mmb5MgIz7teOE83FiJh8l1/FwE4
zi0wDN9LAe6QPJVjW4F4PVc/MnGWVpABAQDII7BN+BLRKYzNOhbcPvfYF4z1
eV8v9ZpnrKBtyU2VegEA4IBoRJBIBupzrKXL497Z1/H4t/zWsNOwx9Gk/NQN
7QbOPAViINBXEgAAADIKKwYBBAGXVQEFAQEHQOwq6DFNBJ25z8Z/WKRA92BG
lwBQnfJnGYBF7hPBMl1/AwEIB8KOBRgWCAAAAAkFAmIg0FcCGwwAAAAjIiEF
G0Qp1bb6aZvkyAjPu144TzcWImHyXX8XATjOLTAM30t2vVIiqtITHHtzmroU
10kwplUBANrkpE2T3XCNqLYnFEfpj0+eyNjUDX4LZye4k5SICcIkAPwNFfvq
wyg7rLV+WXlG27Z7S2gNpt1VbZSBs6IxjzXABg==
-----END PGP PUBLIC KEY BLOCK-----
        """
            .replace("\r\n", "\n")
            .trimIndent()
    }

    @Test
    fun decodeCallbackTest0() {

        PacketDecoder.decode(
            TEST_VECTOR_SAMPLE_V5_ED25519_CERTIFICATE,
            object : PacketDecoder.Callback {
                override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                    println("${header.isLegacyFormat}: ${header.tagValue}: ${header.length}")

                    when (header.tagValue) {
                        0x06 -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("55", header.length.toString())
                        }
                        0x02 -> {
                            assertFalse(header.isLegacyFormat)
                            if (header.length.toInt() != 142 && header.length.toInt() != 168) {
                                fail("")
                            }
                        }
                        0x0E -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("60", header.length.toString())
                        }
                        else -> fail("")
                    }
                }
            })
    }

    @Test
    fun decodePublicKeyEddsaTest0() {
        val packetList = PacketDecoder.decode(TEST_VECTOR_SAMPLE_V5_ED25519_CERTIFICATE)
        assertEquals(4, packetList.size)

        val packetPublicKey = packetList[0]
        assertEquals(Tag.PublicKey, packetPublicKey.tag)
        assertTrue(packetPublicKey is PacketPublicKeyV5)
        if (packetPublicKey is PacketPublicKeyV5) {
            assertEquals(5, packetPublicKey.version)
            assertEquals(OpenPgpAlgorithm.EDDSA, packetPublicKey.algorithm)

            val publicKey = packetPublicKey.publicKey
            assertTrue(publicKey is PublicKeyEddsa)
            if (publicKey is PublicKeyEddsa) {
                assertEquals(EllipticCurveParameter.Ed25519, publicKey.ellipticCurveParameter)
                assertEquals(
                    "40B550FD420BDE0A2AF2DA98C8086AC75F401B9607B8CC801E308E4F252954AB51",
                    publicKey.ecPoint?.toHex("")
                )
            }

            assertEquals(1646317655, packetPublicKey.createdDateTimeEpoch)
        }
    }
}
