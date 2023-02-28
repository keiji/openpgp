package dev.keiji.openpgp.packet

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.OpenPgpAlgorithm
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.packet.signature.SignatureEddsa
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail

class PacketDecoderSignatureV4Test {

    // Test vector from draft-ietf-openpgp-crypto-refresh-07
    private val TEST_VECTOR_SAMPLE_V4_ED25519_SIGNATURE = """
-----BEGIN PGP SIGNATURE-----
iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S
ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE
-----END PGP SIGNATURE-----
        """
        .replace("\r\n", "\n")
        .trimIndent()

    @Test
    fun decodeCallbackTest1() {
        PacketDecoder.decode(
            TEST_VECTOR_SAMPLE_V4_ED25519_SIGNATURE,
            object : PacketDecoder.Callback {
                override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                    println("${header.isLegacyFormat}: ${header.tagValue}: ${header.length}")

                    when (header.tagValue) {
                        0x02 -> {
                            assertTrue(header.isLegacyFormat)
                            assertEquals("94", header.length.toString())
                        }
                    }
                }
            })
    }

    @Test
    fun decodeSignatureEddsaTest1() {
        val packetList = PacketDecoder.decode(TEST_VECTOR_SAMPLE_V4_ED25519_SIGNATURE)
        assertEquals(1, packetList.size)

        val packetSignature = packetList[0]
        assertEquals(Tag.Signature, packetSignature.tag)
        assertTrue(packetSignature is PacketSignatureV4)
        if (packetSignature is PacketSignatureV4) {
            assertEquals(4, packetSignature.version)
            assertEquals(OpenPgpAlgorithm.EDDSA, packetSignature.publicKeyAlgorithm)

            assertEquals(SignatureType.BinaryDocument, packetSignature.signatureType)
            assertEquals(
                "F622",
                packetSignature.hash2bytes.toHex("")
            )
            assertEquals(
                HashAlgorithm.SHA2_256,
                packetSignature.hashAlgorithm
            )

            val signature = packetSignature.signature
            assertTrue(signature is SignatureEddsa)
            if (signature is SignatureEddsa) {
                assertEquals(
                    "56F90CCA98E2102637BD983FDB16C131DFD27ED82BF4DDE5606E0D756AED3366",
                    signature.r?.toHex("")
                )
                assertEquals(
                    "D09C4FA11527F038E0F57F2201D82F2EA2C9033265FA6CEB489E854BAE61B404",
                    signature.s?.toHex("")
                )
            } else {
                fail("")
            }
        }
    }
}
