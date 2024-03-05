package dev.keiji.openpgp.packet

import dev.keiji.openpgp.AeadAlgorithm
import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.PgpData
import dev.keiji.openpgp.String2KeyType
import dev.keiji.openpgp.SymmetricKeyAlgorithm
import dev.keiji.openpgp.packet.secretkey.s2k.String2KeySaltedIterated
import dev.keiji.openpgp.packet.seipd.PacketSymEncryptedAndIntegrityProtectedDataV2
import dev.keiji.openpgp.packet.skesk.PacketSymmetricKeyEncryptedSessionKeyV5
import dev.keiji.openpgp.parseHexString
import dev.keiji.openpgp.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

class PacketAeadEncryptedTest {
    companion object {
        // Test vector from draft-ietf-openpgp-crypto-refresh-07
        private val TEST_VECTOR_SAMPLE_AEAD_EAX_PACKET = """
-----BEGIN PGP MESSAGE-----
w0AFHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+Np0a4jjV+iuVOuH4dcF
ddcvYCMpkFI+mlkJSSJAa+HD0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq
pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1
QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=
-----END PGP MESSAGE-----
        """.replace("\r\n", "\n")
            .trimIndent()
    }

    @Test
    fun decodeCallbackTest() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(TEST_VECTOR_SAMPLE_AEAD_EAX_PACKET.toByteArray(charset = StandardCharsets.UTF_8))
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
                        0x03 -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("64", header.length.toString())
                        }

                        0x12 -> {
                            assertFalse(header.isLegacyFormat)
                            assertEquals("105", header.length.toString())
                        }

                        else -> fail("")
                    }
                }
            })
    }

    @Test
    fun decodeAeadEncryptedTest() {
        val pgpData = PgpData.loadAsciiArmored(
            ByteArrayInputStream(TEST_VECTOR_SAMPLE_AEAD_EAX_PACKET.toByteArray(charset = StandardCharsets.UTF_8))
        )
        val data = pgpData.blockList[0].data
        assertNotNull(data)
        data ?: return

        val packetList = PacketDecoder.decode(data)
        assertEquals(2, packetList.size)

        val packetSymmetricKeyEncryptedSessionKey = packetList[0]
        assertEquals(Tag.SymmetricKeyEncryptedSessionKey, packetSymmetricKeyEncryptedSessionKey.tag)
        assertTrue(packetSymmetricKeyEncryptedSessionKey is PacketSymmetricKeyEncryptedSessionKeyV5)
        if (packetSymmetricKeyEncryptedSessionKey is PacketSymmetricKeyEncryptedSessionKeyV5) {
            assertEquals(5, packetSymmetricKeyEncryptedSessionKey.version)
            assertEquals(AeadAlgorithm.EAX, packetSymmetricKeyEncryptedSessionKey.aeadAlgorithm)
            assertEquals(
                SymmetricKeyAlgorithm.AES128,
                packetSymmetricKeyEncryptedSessionKey.symmetricKeyAlgorithm
            )
            assertEquals(
                "69224F919993B3506FA3B59A6A73CFF8",
                packetSymmetricKeyEncryptedSessionKey.initializationVector?.toHex("")
            )
            assertEquals(
                "DA746B88E357E8AE54EB87E1D70575D72F60232990523E9A59094922406BE1C3",
                packetSymmetricKeyEncryptedSessionKey.encryptedSessionKeyWithTag?.toHex("")
            )

            assertEquals(
                String2KeyType.SALTED_ITERATED,
                packetSymmetricKeyEncryptedSessionKey.string2Key.type
            )

            val string2Key = packetSymmetricKeyEncryptedSessionKey.string2Key
            assertTrue(string2Key is String2KeySaltedIterated)
            if (string2Key is String2KeySaltedIterated) {
                assertEquals(
                    HashAlgorithm.SHA2_256,
                    string2Key.hashAlgorithm
                )
                assertEquals(
                    65011712,
                    string2Key.iterationCount
                )
                assertEquals(
                    "A5AE579D1FC5D82B",
                    string2Key.salt.toHex("")
                )
            }
        }

        val packetSymEncryptedAndIntegrityProtectedData = packetList[1]
        assertEquals(
            Tag.SymEncryptedAndIntegrityProtectedData,
            packetSymEncryptedAndIntegrityProtectedData.tag
        )
        assertTrue(packetSymEncryptedAndIntegrityProtectedData is PacketSymEncryptedAndIntegrityProtectedDataV2)
        if (packetSymEncryptedAndIntegrityProtectedData is PacketSymEncryptedAndIntegrityProtectedDataV2) {
            assertEquals(
                SymmetricKeyAlgorithm.AES128,
                packetSymEncryptedAndIntegrityProtectedData.cipherAlgorithm
            )
            assertEquals(
                AeadAlgorithm.EAX,
                packetSymEncryptedAndIntegrityProtectedData.aeadAlgorithm
            )
            assertEquals(
                4096,
                packetSymEncryptedAndIntegrityProtectedData.chunkSize
            )
            assertEquals(
                "9FF90E3B321964F3A42913C8DCC6619325015227EFB7EAEAA49F04C2E674175D",
                packetSymEncryptedAndIntegrityProtectedData.salt.toHex("")
            )
            assertEquals(
                "4A3D226ED6AFCB9CA9AC122C1470E11C63D4C0AB241C6A938AD48BF99A5A99B90BBA8325DE" +
                        "61047540258AB7959A95AD051DDA96EB",
                packetSymEncryptedAndIntegrityProtectedData.encryptedDataAndTag
                    .toHex("")
            )
            assertEquals(
                "15431DFEF5F5E2255CA78261546E339A",
                packetSymEncryptedAndIntegrityProtectedData.authenticationTag
                    .toHex("")
            )
        }
    }

    @Test
    fun encodeAeadEncryptedTest() {

        val packetSymmetricKeyEncryptedSessionKey =
            PacketSymmetricKeyEncryptedSessionKeyV5().also { packetSymmetricKeyEncryptedSessionKey ->
                packetSymmetricKeyEncryptedSessionKey.symmetricKeyAlgorithm =
                    SymmetricKeyAlgorithm.AES128
                packetSymmetricKeyEncryptedSessionKey.aeadAlgorithm = AeadAlgorithm.EAX
                packetSymmetricKeyEncryptedSessionKey.string2Key =
                    String2KeySaltedIterated().also { s2key ->
                        s2key.hashAlgorithm = HashAlgorithm.SHA2_256
                        s2key.salt = parseHexString("A5AE579D1FC5D82B", null)
                        s2key.iterationCount = 255
                    }
                packetSymmetricKeyEncryptedSessionKey.initializationVector =
                    parseHexString(
                        "69224F919993B3506FA3B59A6A73CFF8",
                        null
                    )
                packetSymmetricKeyEncryptedSessionKey.encryptedSessionKeyWithTag =
                    parseHexString(
                        "DA746B88E357E8AE54EB87E1D70575D72F60232990523E9A59094922406BE1C3",
                        null
                    )
            }

        val packetSymEncryptedAndIntegrityProtectedData =
            PacketSymEncryptedAndIntegrityProtectedDataV2().also { packetSymEncryptedAndIntegrityProtectedData ->
                packetSymEncryptedAndIntegrityProtectedData.cipherAlgorithm =
                    SymmetricKeyAlgorithm.AES128
                packetSymEncryptedAndIntegrityProtectedData.aeadAlgorithm = AeadAlgorithm.EAX
                packetSymEncryptedAndIntegrityProtectedData.chunkSize = 6
                packetSymEncryptedAndIntegrityProtectedData.encryptedDataAndTag = parseHexString(
                    "4A3D226ED6AFCB9CA9AC122C1470E11C63D4C0AB241C6A938AD48BF99A5A99B90BBA8325DE" +
                            "61047540258AB7959A95AD051DDA96EB",
                    null
                )
                packetSymEncryptedAndIntegrityProtectedData.salt = parseHexString(
                    "9FF90E3B321964F3A42913C8DCC6619325015227EFB7EAEAA49F04C2E674175D",
                    null
                )
                packetSymEncryptedAndIntegrityProtectedData.authenticationTag = parseHexString(
                    "15431DFEF5F5E2255CA78261546E339A",
                    null
                )

            }

        val packetList = listOf(
            packetSymmetricKeyEncryptedSessionKey,
            packetSymEncryptedAndIntegrityProtectedData,
        )

        val encoded = ByteArrayOutputStream().let { baos ->
            PacketEncoder.encode(false, packetList, baos)
            baos.toByteArray()
        }

        assertEquals(
            "C340" +
                    "051E07010B0308FFA5AE579D1FC5D82B" +
                    "69224F919993B3506FA3B59A6A73CFF8" +
                    "DA746B88E357E8AE54EB87E1D70575D72F60232990523E9A59094922406BE1C3" +
                    "D269" +
                    "02070106" +
                    "9FF90E3B321964F3A42913C8DCC6619325015227EFB7EAEAA49F04C2E674175D" +
                    "4A3D226ED6AFCB9CA9AC122C1470E11C63D4C0AB241C6A938AD48BF99A5A99B90BBA8325DE" +
                    "61047540258AB7959A95AD051DDA96EB" +
                    "15431DFEF5F5E2255CA78261546E339A",
            encoded.toHex("")
        )
    }
}
