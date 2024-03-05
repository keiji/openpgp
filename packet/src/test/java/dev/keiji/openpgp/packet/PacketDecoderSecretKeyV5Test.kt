package dev.keiji.openpgp.packet

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.CompressionAlgorithm
import dev.keiji.openpgp.EllipticCurveParameter
import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.PublicKeyAlgorithm
import dev.keiji.openpgp.packet.publickey.PublicKeyEddsa
import dev.keiji.openpgp.packet.secretkey.PacketSecretKeyV5
import dev.keiji.openpgp.packet.secretkey.PacketSecretSubkeyV5
import dev.keiji.openpgp.packet.secretkey.s2k.SecretKeyEncryptionType
import dev.keiji.openpgp.packet.signature.PacketSignatureV5
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.packet.signature.subpacket.Features
import dev.keiji.openpgp.packet.signature.subpacket.IssuerFingerprint
import dev.keiji.openpgp.packet.signature.subpacket.KeyFlags
import dev.keiji.openpgp.packet.signature.subpacket.PreferredAeadCiphersuites
import dev.keiji.openpgp.packet.signature.subpacket.PreferredCompressionAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.PreferredHashAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.SignatureCreationTime
import dev.keiji.openpgp.packet.signature.subpacket.SubpacketType
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.nio.charset.StandardCharsets

class PacketDecoderSecretKeyV5Test {
    companion object {
        // Test vector from draft-ietf-openpgp-crypto-refresh-07
        private val TEST_VECTOR_SAMPLE_V5_ED25519_KEY = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
xV0FYiDQVxYAAAAtCSsGAQQB2kcPAQEHQLVQ/UIL3goq8tqYyAhqx19AG5YH
uMyAHjCOTyUpVKtRAAABAKmpvxTlZ9KQ6j+aOEk8fYe/h0L8K5pJsuAYhvSV
mL28EbTCqAUfFgoAAAAjBQJiINBXAxUICgQWAAIBAhsDAh4JDScJAwcDCQEH
AQkCBwIAAAAjIiEFG0Qp1bb6aZvkyAjPu144TzcWImHyXX8XATjOLTAM30sB
7pA8lWNbgXg9Vz8ycZZWkAEBAMgjsE34EtEpjM06Ftw+99gXjPV5Xy/1mmes
oG3JTZV6AQDggGhEkEgG6nOspcvj3tnX8fi3/Naw07DH0aT81A3tBsdiBWIg
0FcSAAAAMgorBgEEAZdVAQUBAQdA7CroMU0EnbnPxn9YpED3YEaXAFCd8mcZ
gEXuE8EyXX8DAQgHAAAA/1b9bxwV0acRUcifrLiKHd0VVifoISz2PSVd4q5I
c1+gD+HCjgUYFggAAAAJBQJiINBXAhsMAAAAIyIhBRtEKdW2+mmb5MgIz7te
OE83FiJh8l1/FwE4zi0wDN9Ldr1SIqrSExx7c5q6FNdJMKZVAQDa5KRNk91w
jai2JxRH6Y9PnsjY1A1+C2cnuJOUiAnCJAD8DRX76sMoO6y1fll5Rtu2e0to
DabdVW2UgbOiMY81wAY=
-----END PGP PRIVATE KEY BLOCK-----
        """
            .replace("\r\n", "\n")
            .trimIndent()

    }

    @Test
    fun decodeCallbackTest() {
        val secretKeyPgpData = PgpData.loadAsciiArmored(
            TEST_VECTOR_SAMPLE_V5_ED25519_KEY.byteInputStream(charset = StandardCharsets.UTF_8)
        )
        val secretKeyData = secretKeyPgpData.blockList[0].data
        assertNotNull(secretKeyData)
        secretKeyData ?: return

        PacketDecoder.decode(
            secretKeyData,
            object : PacketDecoder.Callback {
                override fun onPacketDetected(header: PacketHeader, byteArray: ByteArray) {
                    println("${header.isLegacyFormat}: ${header.tagValue}: ${header.length}")

                    when (header.tagValue) {
                        0x05 -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("93", header.length.toString())
                        }
                        0x02 -> {
                            assertFalse(header.isLegacyFormat)
                            if ("168" != header.length.toString() && "142" != header.length.toString()) {
                                fail("")
                            }
                        }
                        0x07 -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("98", header.length.toString())
                        }
                        else -> fail("")
                    }
                }
            })
    }

    @Test
    fun decodeSecretKeyEddsaTest0() {
        val secretKeyPgpData = PgpData.loadAsciiArmored(
            TEST_VECTOR_SAMPLE_V5_ED25519_KEY.byteInputStream(charset = StandardCharsets.UTF_8)
        )
        val secretKeyData = secretKeyPgpData.blockList[0].data
        assertNotNull(secretKeyData)
        secretKeyData ?: return

        val packetList = PacketDecoder.decode(secretKeyData)
        assertEquals(4, packetList.size)

        val packetSecretKey = packetList[0]
        assertEquals(Tag.SecretKey, packetSecretKey.tag)
        assertTrue(packetSecretKey is PacketSecretKeyV5)
        if (packetSecretKey is PacketSecretKeyV5) {
            assertEquals(5, packetSecretKey.version)
            assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY, packetSecretKey.algorithm)
            assertEquals(1646317655, packetSecretKey.createdDateTimeEpoch)

            assertNull(packetSecretKey.symmetricKeyEncryptionAlgorithm)
            assertEquals(SecretKeyEncryptionType.ClearText, packetSecretKey.string2keyUsage)
            assertNull(packetSecretKey.initializationVector?.toHex(""))
            assertNull(packetSecretKey.nonce?.toHex(""))

            val publicKey = packetSecretKey.publicKey
            assertTrue(publicKey is PublicKeyEddsa)
            if (publicKey is PublicKeyEddsa) {
                assertEquals(EllipticCurveParameter.Ed25519, publicKey.ellipticCurveParameter)
                assertEquals(
                    "40B550FD420BDE0A2AF2DA98C8086AC75F401B9607B8CC801E308E4F252954AB51",
                    publicKey.ecPoint?.toHex("")
                )
            }
        }

        val packetSignature1 = packetList[1]
        assertEquals(Tag.Signature, packetSignature1.tag)
        assertTrue(packetSignature1 is PacketSignatureV5)
        if (packetSignature1 is PacketSignatureV5) {
            assertEquals(5, packetSignature1.version)
            assertEquals(SignatureType.SignatureDirectlyOnKey, packetSignature1.signatureType)

            assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY, packetSignature1.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_512, packetSignature1.hashAlgorithm)

            assertEquals("01EE", packetSignature1.hash2bytes.toHex(""))
            assertEquals("903C95635B81783D573F327196569001", packetSignature1.salt.toHex(""))

            val hashedSubpacketList = packetSignature1.hashedSubpacketList
            assertEquals(6, hashedSubpacketList.size)

            val hashedSubpacket0 = hashedSubpacketList[0]
            assertEquals(SubpacketType.SignatureCreationTime, hashedSubpacket0.getType())
            assertTrue(hashedSubpacket0 is SignatureCreationTime)
            if (hashedSubpacket0 is SignatureCreationTime) {
                assertEquals(1646317655, hashedSubpacket0.value)
            }

            val hashedSubpacket1 = hashedSubpacketList[1]
            assertEquals(SubpacketType.PreferredHashAlgorithms, hashedSubpacket1.getType())
            assertTrue(hashedSubpacket1 is PreferredHashAlgorithms)
            if (hashedSubpacket1 is PreferredHashAlgorithms) {
                assertEquals(2, hashedSubpacket1.ids.size)
                assertEquals(
                    HashAlgorithm.SHA2_256,
                    hashedSubpacket1.ids[0]
                )
                assertEquals(
                    HashAlgorithm.SHA2_512,
                    hashedSubpacket1.ids[1]
                )
            }

            val hashedSubpacket2 = hashedSubpacketList[2]
            assertEquals(SubpacketType.PreferredCompressionAlgorithms, hashedSubpacket2.getType())
            assertTrue(hashedSubpacket2 is PreferredCompressionAlgorithms)
            if (hashedSubpacket2 is PreferredCompressionAlgorithms) {
                assertEquals(3, hashedSubpacket2.ids.size)
                assertEquals(
                    CompressionAlgorithm.Uncompressed,
                    hashedSubpacket2.ids[0]
                )
                assertEquals(
                    CompressionAlgorithm.ZLIB,
                    hashedSubpacket2.ids[1]
                )
                assertEquals(
                    CompressionAlgorithm.ZIP,
                    hashedSubpacket2.ids[2]
                )
            }

            val hashedSubpacket3 = hashedSubpacketList[3]
            assertEquals(SubpacketType.KeyFlags, hashedSubpacket3.getType())
            assertTrue(hashedSubpacket3 is KeyFlags)
            if (hashedSubpacket3 is KeyFlags) {
                assertEquals("03", hashedSubpacket3.flags.toHex(""))
            }

            val hashedSubpacket4 = hashedSubpacketList[4]
            assertEquals(SubpacketType.Features, hashedSubpacket4.getType())
            assertTrue(hashedSubpacket4 is Features)
            if (hashedSubpacket4 is Features) {
                assertEquals("09", hashedSubpacket4.flags.toHex(""))
            }

            val hashedSubpacket5 = hashedSubpacketList[5]
            assertEquals(SubpacketType.PreferredAeadCiphersuites, hashedSubpacket5.getType())
            assertTrue(hashedSubpacket5 is PreferredAeadCiphersuites)
            if (hashedSubpacket5 is PreferredAeadCiphersuites) {
                val pairMap = hashedSubpacket5.pairMap
                assertEquals(2, pairMap.size)

                assertArrayEquals(
                    arrayOf(SymmetricKeyAlgorithm.AES256.id, SymmetricKeyAlgorithm.AES128.id),
                    pairMap.keys.map { it.id }.toTypedArray()
                )

                assertEquals(3, pairMap[SymmetricKeyAlgorithm.AES256]?.size)
                assertEquals(AeadAlgorithm.GCM, pairMap[SymmetricKeyAlgorithm.AES256]?.get(0))
                assertEquals(AeadAlgorithm.EAX, pairMap[SymmetricKeyAlgorithm.AES256]?.get(1))
                assertEquals(AeadAlgorithm.OCB, pairMap[SymmetricKeyAlgorithm.AES256]?.get(2))

                assertEquals(3, pairMap[SymmetricKeyAlgorithm.AES128]?.size)
                assertEquals(AeadAlgorithm.GCM, pairMap[SymmetricKeyAlgorithm.AES128]?.get(0))
                assertEquals(AeadAlgorithm.EAX, pairMap[SymmetricKeyAlgorithm.AES128]?.get(1))
                assertEquals(AeadAlgorithm.OCB, pairMap[SymmetricKeyAlgorithm.AES128]?.get(2))
            }

            val subpacketList = packetSignature1.subpacketList
            assertEquals(1, subpacketList.size)

            val subpacket0 = subpacketList[0]
            assertEquals(SubpacketType.IssuerFingerprint, subpacket0.getType())
            assertTrue(subpacket0 is IssuerFingerprint)
            if (subpacket0 is IssuerFingerprint) {
                assertEquals(5, subpacket0.version)
                assertEquals(
                    "1B4429D5B6FA699BE4C808CFBB5E384F37162261F25D7F170138CE2D300CDF4B",
                    subpacket0.fingerprint.toHex("")
                )
            }
        }

        val packetSecretSubkey = packetList[2]
        assertEquals(Tag.SecretSubkey, packetSecretSubkey.tag)
        assertTrue(packetSecretSubkey is PacketSecretSubkeyV5)
        if (packetSecretSubkey is PacketSecretSubkeyV5) {
            assertEquals(PublicKeyAlgorithm.ECDH, packetSecretSubkey.algorithm)
            assertNull(packetSecretSubkey.symmetricKeyEncryptionAlgorithm)
            assertEquals(1646317655, packetSecretSubkey.createdDateTimeEpoch)
            assertEquals(SecretKeyEncryptionType.ClearText, packetSecretSubkey.string2keyUsage)
            assertEquals("0000", packetSecretSubkey.checkSum?.toHex(""))
            assertNull(packetSecretSubkey.aeadAlgorithm)
            assertNull(packetSecretSubkey.nonce)
            assertNull(packetSecretSubkey.initializationVector)
        }

        val packetSignature2 = packetList[3]
        assertEquals(Tag.Signature, packetSignature2.tag)
        assertTrue(packetSignature2 is PacketSignatureV5)
        if (packetSignature2 is PacketSignatureV5) {
            assertEquals(5, packetSignature2.version)
            assertEquals(SignatureType.SubKeyBinding, packetSignature2.signatureType)

            assertEquals(PublicKeyAlgorithm.EDDSA_LEGACY, packetSignature2.publicKeyAlgorithm)
            assertEquals(HashAlgorithm.SHA2_256, packetSignature2.hashAlgorithm)

            assertEquals("76BD", packetSignature2.hash2bytes.toHex(""))
            assertEquals("5222AAD2131C7B739ABA14D74930A655", packetSignature2.salt.toHex(""))

            val hashedSubpacketList = packetSignature2.hashedSubpacketList
            assertEquals(2, hashedSubpacketList.size)

            val hashedSubpacket0 = hashedSubpacketList[0]
            assertEquals(SubpacketType.SignatureCreationTime, hashedSubpacket0.getType())
            assertTrue(hashedSubpacket0 is SignatureCreationTime)
            if (hashedSubpacket0 is SignatureCreationTime) {
                assertEquals(1646317655, hashedSubpacket0.value)
            }

            val hashedSubpacket1 = hashedSubpacketList[1]
            assertEquals(SubpacketType.KeyFlags, hashedSubpacket1.getType())
            assertTrue(hashedSubpacket1 is KeyFlags)
            if (hashedSubpacket1 is KeyFlags) {
                assertEquals("0C", hashedSubpacket1.flags.toHex(""))
            }
        }
    }
}
