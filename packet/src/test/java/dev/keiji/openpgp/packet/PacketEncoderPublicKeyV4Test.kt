package dev.keiji.openpgp.packet

import dev.keiji.openpgp.*
import dev.keiji.openpgp.packet.publickey.PacketPublicKeyV4
import dev.keiji.openpgp.packet.publickey.PacketPublicSubkeyV4
import dev.keiji.openpgp.packet.publickey.PublicKeyEcdsa
import dev.keiji.openpgp.packet.publickey.PublicKeyRsa
import dev.keiji.openpgp.packet.signature.SignatureEcdsa
import dev.keiji.openpgp.packet.signature.SignatureRsa
import dev.keiji.openpgp.packet.signature.PacketSignatureV4
import dev.keiji.openpgp.SignatureType
import dev.keiji.openpgp.packet.signature.subpacket.Features
import dev.keiji.openpgp.packet.signature.subpacket.Issuer
import dev.keiji.openpgp.packet.signature.subpacket.IssuerFingerprint
import dev.keiji.openpgp.packet.signature.subpacket.KeyExpirationTime
import dev.keiji.openpgp.packet.signature.subpacket.KeyFlags
import dev.keiji.openpgp.packet.signature.subpacket.KeyServerPreferences
import dev.keiji.openpgp.packet.signature.subpacket.PreferredCompressionAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.PreferredHashAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.PreferredSymmetricAlgorithms
import dev.keiji.openpgp.packet.signature.subpacket.SignatureCreationTime
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File

class PacketEncoderPublicKeyV4Test {
    private var path = "src/test/resources"
    private val file = File(path)

    @Test
    fun encodePublicKeyEcdsaTest() {
        val data = File(
            file.absolutePath,
            "FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD_publickey_armored.gpg"
        )
            .readText()
            .replace("\r\n", "\n")
            .trimEnd()
        val (body, _) = PacketDecoder.split(data)
        val expected = Radix64.decode(body)

        val packetPublicKey = PacketPublicKeyV4().also {
            it.algorithm = OpenPgpAlgorithm.ECDSA
            it.createdDateTimeEpoch = 1669682020

            it.publicKey = PublicKeyEcdsa().also {
                it.ellipticCurveParameter = EllipticCurveParameter.Secp256r1
                it.ecPoint = parseHexString(
                    "04854E700A5524ADE7A11BF615C2F117AAA08EBFF455C4349B8B132878E2AAC52777573ED9594ECB013D5212C475DAFEF67D417BED81403F140A17506D7406244C",
                    null
                )
            }
        }

        val packetUserId = PacketUserId().also {
            it.userId = "Keiji TEST (test) <TEST@test.com>"
        }

        val packetSignature = createEcdsaSignaturePacket()

        val packetList = listOf(
            packetPublicKey,
            packetUserId,
            packetSignature,
        )

        val actual = ByteArrayOutputStream().let {
            PacketEncoder.encode(true, packetList, it)
            it.toByteArray()
        }

        val expectedHex = expected.toHex("")
        val actualHex = actual.toHex("")
        assertEquals(expectedHex, actualHex)
    }

    private fun createEcdsaSignaturePacket(): PacketSignatureV4 {
        val signaturePacket = PacketSignatureV4()
            .also {
                it.signatureType = SignatureType.PositiveCertificationOfUserId
                it.publicKeyAlgorithm = OpenPgpAlgorithm.ECDSA
                it.hashAlgorithm = HashAlgorithm.SHA2_256
            }

        signaturePacket.hashedSubpacketList = listOf(
            IssuerFingerprint().also {
                it.version = 4
                it.fingerprint =
                    parseHexString("FE:FF:2E:18:5C:F8:F0:63:AD:2E:42:46:3E:58:DE:6C:C9:26:B4:AD", delimiter = ":")
            },
            SignatureCreationTime().also {
                it.value = 1669682020
            },
            KeyFlags().also {
                it.flags = byteArrayOf(0x03.toByte())
            },
            PreferredSymmetricAlgorithms().also {
                it.ids = listOf(
                    SymmetricKeyAlgorithm.AES256,
                    SymmetricKeyAlgorithm.AES192,
                    SymmetricKeyAlgorithm.AES128,
                    SymmetricKeyAlgorithm.TripleDES,
                )
            },
            PreferredHashAlgorithms().also {
                it.ids = listOf(
                    HashAlgorithm.SHA2_512,
                    HashAlgorithm.SHA2_384,
                    HashAlgorithm.SHA2_256,
                    HashAlgorithm.SHA2_224,
                    HashAlgorithm.SHA1,
                )
            },
            PreferredCompressionAlgorithms().also {
                it.ids = listOf(
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZip2,
                    CompressionAlgorithm.ZIP,
                )
            },
            Features().also {
                it.flags = byteArrayOf(0x01)
            },
            KeyServerPreferences().also {
                it.flags = byteArrayOf(0x80.toByte())
            }
        )

        signaturePacket.subpacketList = listOf(
            Issuer().also {
                it.keyId = parseHexString("3E:58:DE:6C:C9:26:B4:AD", delimiter = ":")
            }
        )

        signaturePacket.hash2bytes = byteArrayOf(0xF6.toByte(), 0x1D)

        signaturePacket.signature = SignatureEcdsa().also {
            it.r =
                parseHexString(
                    "14:BC:C2:22:F5:97:DF:80:7D:AB:36:7D:8C:61:43:77:24:85:74:49:13:97:C9:AB:5B:3E:C6:3D:0B:13:72:A9",
                    delimiter = ":"
                )
            it.s =
                parseHexString(
                    "1E:F8:08:2B:5E:C9:CF:D8:8A:B9:0A:0C:11:79:D4:A5:70:6A:90:6D:B2:79:D0:2F:B7:DC:CB:E8:43:0D:C9:B2",
                    delimiter = ":"
                )
        }

        return signaturePacket
    }

    @Test
    fun encodePublicKeyRsa3072Test() {
        val data = File(
            file.absolutePath,
            "BEE2304E4B50BA1E4627E845A7B65607A26BC985_rsa3072_publickey.gpg"
        )
            .readText()
            .replace("\r\n", "\n")
            .trimEnd()
        val (body, _) = PacketDecoder.split(data)
        val expected = Radix64.decode(body)

        val packetPublicKey = PacketPublicKeyV4().also {
            it.algorithm = OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN
            it.createdDateTimeEpoch = 1669533494

            it.publicKey = PublicKeyRsa().also {
                it.n = parseHexString(
                    "BBC55BA0253DFB1D7E90D475C4EDA97A1813ABE9332FE737C888FE8DF1D7D209A92B6A849FFB0E94634C57E0DEB93214D843303F5ACFF31A747C0D181795A7DC10694BECA04C7673036CB7BBC44F9608AEE06655EDC8624A0CE2A8B783165B535883EA4286FAEAC31911D74B970B7BD609ABD7B1EB1285B83EF90995EDCB709F0847EBBE5DFCFBAFBF851AF97B87E044466F9824700219BE737B8B62A2D4C3A64121C822BAC466EC810F84B572A2E6A841E3C4E486AB7C5142850AD7B97A1BE034EDB99A1F7C060203A8F25A3E34A10635B119F7685F941C45E6DAA9C88E8C828BCDF65A9FAECCB83D38BB3836EE4F1B9CF2DE643BB5C9E5DDC345E0FD56BCF69EB0B5A12F75106715C307BC81B15A98A7CE453ED6853890477B78E9E18FE69B953FF28950CD1110789F3BD5AEA29E23F10B7CFC98CB1900D04395090BE37470A91FE71020A2D45F9428B3A11E1A05DB14EFE5BD7B5F51723F0D144F948B83D1E0C3DBF5BD813DBC5E6E0DCE12F829D416B6D651162C7E0DC3B9C174DD421D27",
                    null
                )
                it.e = parseHexString(
                    "010001",
                    null
                )
            }
        }

        val packetUserId = PacketUserId().also {
            it.userId = "TEST ARIYAMA <keiji@test.com>"
        }

        val packetSignature1 = createRsa3072SignaturePacket1()

        val packetPublicSubkey = PacketPublicSubkeyV4().also {
            it.algorithm = OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN
            it.createdDateTimeEpoch = 1669533494

            it.publicKey = PublicKeyRsa().also {
                it.n = parseHexString(
                    "CD94F3E77BE0072D2BF0764FB401D466F12B8EF4DB45BCF2DD3B026D34E53A4F1CAA2CD81CCE8105982A09FC94B4AF9774E938E2D839806F39F121E79944E60B15BB24F227394598127ED14FB582599F910AE7B6FF87142511197D4F8B7784E5F1737E46F11653CB92AA93EB4CEBEB8D9DEE07DA69CE7D30AC6971432B0126E3822BDBA32EA351FE7A15E438D5598590BED54D838F0F938642B038799DA64A8D1027946BE16C65AF91C268ADBB0D666329AFDC2197E33C0C100FF64AB495665323F421DBDA902D9F8E3666C562D43636338DDC1E54E2F4A1259A9D29CCDA3398B4EDB86FA3B9BA23FB675988C2EBB9DF0E592AB4F05E3A40583E9A1721AB09BEA986EC9B23C8B6FD9E02EBFDB23C81786687C189980AE8C46D1014A9B8F5AD9F97E3F3CEE9590D5882BB1EFD12CC094FE7A35336A5B7800A97F6F944D65538218A6D5A78A06C9CBCB574381A1FAF940FF632E27D57787DD71AFA00354C0DE68D495819C7976E685D0C558FFA52D0E582B932BA334D63052470DB8A8FE266D743",
                    null
                )
                it.e = parseHexString(
                    "010001",
                    null
                )
            }
        }

        val packetSignature2 = createRsa3072SignaturePacket2()

        val packetList = listOf(
            packetPublicKey,
            packetUserId,
            packetSignature1,
            packetPublicSubkey,
            packetSignature2,
        )

        val actual = ByteArrayOutputStream().let {
            PacketEncoder.encode(true, packetList, it)
            it.toByteArray()
        }

        val expectedHex = expected.toHex("")
        val actualHex = actual.toHex("")
        assertEquals(expectedHex, actualHex)
    }

    private fun createRsa3072SignaturePacket1(): PacketSignatureV4 {
        val signaturePacket = PacketSignatureV4()
            .also {
                it.signatureType = SignatureType.PositiveCertificationOfUserId
                it.publicKeyAlgorithm = OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN
                it.hashAlgorithm = HashAlgorithm.SHA2_256
            }

        signaturePacket.hashedSubpacketList = listOf(
            IssuerFingerprint().also {
                it.version = 4
                it.fingerprint =
                    parseHexString("BE:E2:30:4E:4B:50:BA:1E:46:27:E8:45:A7:B6:56:07:A2:6B:C9:85", delimiter = ":")
            },
            SignatureCreationTime().also {
                it.value = 1669533494
            },
            KeyFlags().also {
                it.flags = byteArrayOf(0x03.toByte())
            },
            KeyExpirationTime().also {
                it.value = 63072000
            },
            PreferredSymmetricAlgorithms().also {
                it.ids = listOf(
                    SymmetricKeyAlgorithm.AES256,
                    SymmetricKeyAlgorithm.AES192,
                    SymmetricKeyAlgorithm.AES128,
                    SymmetricKeyAlgorithm.TripleDES,
                )
            },
            PreferredHashAlgorithms().also {
                it.ids = listOf(
                    HashAlgorithm.SHA2_512,
                    HashAlgorithm.SHA2_384,
                    HashAlgorithm.SHA2_256,
                    HashAlgorithm.SHA2_224,
                    HashAlgorithm.SHA1,
                )
            },
            PreferredCompressionAlgorithms().also {
                it.ids = listOf(
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZip2,
                    CompressionAlgorithm.ZIP,
                )
            },
            Features().also {
                it.flags = byteArrayOf(0x01)
            },
            KeyServerPreferences().also {
                it.flags = byteArrayOf(0x80.toByte())
            }
        )

        signaturePacket.subpacketList = listOf(
            Issuer().also {
                it.keyId = parseHexString("A7:B6:56:07:A2:6B:C9:85", delimiter = ":")
            }
        )

        signaturePacket.hash2bytes = byteArrayOf(0x47.toByte(), 0x4D)

        signaturePacket.signature = SignatureRsa().also {
            it.value = parseHexString(
                "0BE6816708B4156D25F8A90CF399271554A109919DF3A3E5A365EF323DDE7C164DDE42A351871902607ACD6A6682AC2B7241C5D8F664D8A877AD8152C4C937CEB524EA18FE12BD94A005630E6BF2DDAD3D81681E1476EAAE9FFE630040582E91848864401B3C587DB29E92242B6B1B87F7EFFCBC123BC99EFF64C54A5700C67DC03ECDD312558CB43F6F6009E4A77FA2343104353258D17ACD272C2917F698F115F6360253DC0305B9DDD45616DD109FC5360FD07C19F26EDA20015C49FA5EF66D7730E1359AA452B4134C88CAECC39692E2C85CCE78EE72412EE0B19B77187A6EFA09D7C9355BC3F2B3859BC19983152727A9F5B34E36DC51E3F0AD67FCCCB0CF783AD9830B783969B467D406604D819B847823245D2E74F4504ADFBEEDBFD6F57B87F2EA39428409A14B4CA6CE27126716CD641995A520909373ACA6D2A1E08F003DF316EDF25B9AACE8D9230D4B32EF50B99E495AC043972048262465555B5D17FFB8821E2C481718A896A654704E3298465330D9B5DBD53B9C0815F7A3AF",
                delimiter = null
            )
        }

        return signaturePacket
    }

    private fun createRsa3072SignaturePacket2(): PacketSignatureV4 {
        val signaturePacket = PacketSignatureV4()
            .also {
                it.signatureType = SignatureType.SubKeyBinding
                it.publicKeyAlgorithm = OpenPgpAlgorithm.RSA_ENCRYPT_OR_SIGN
                it.hashAlgorithm = HashAlgorithm.SHA2_256
            }

        signaturePacket.hashedSubpacketList = listOf(
            IssuerFingerprint().also {
                it.version = 4
                it.fingerprint =
                    parseHexString("BE:E2:30:4E:4B:50:BA:1E:46:27:E8:45:A7:B6:56:07:A2:6B:C9:85", delimiter = ":")
            },
            SignatureCreationTime().also {
                it.value = 1669533494
            },
            KeyFlags().also {
                it.flags = byteArrayOf(12)
            },
            KeyExpirationTime().also {
                it.value = 63072000
            },
        )

        signaturePacket.subpacketList = listOf(
            Issuer().also {
                it.keyId = parseHexString("A7:B6:56:07:A2:6B:C9:85", delimiter = ":")
            }
        )

        signaturePacket.hash2bytes = byteArrayOf(0x7B.toByte(), 0xAC.toByte())

        signaturePacket.signature = SignatureRsa().also {
            it.value = parseHexString(
                "32EF13A87BECC538122CEA1D498A8C4214FAD5E796AA76F1AF6651E03C1AA232ECE21998C0E8D94D18DB39311B94CCBAD2B1C94921551D1645E79E1A4208C1078B1C5FFC0F16703266FE0F3103B77580B3F166E71092A33D1B0544EA094088FAD2A5AE194B728CC35865E0FC53CD185574B0418ABBED4F0964B5CBD22FD6CDDD8F4A646B15A695F88D1EA90D5F557306EC341796192A2627A29CFF575D02CB539A9D1308D0AFADE94F742524218A173DBA6D6823FFF7B435197DA0FC622A16785FE273FA53CAA86B9A9E3A62F7EBB0B9E89B6ADD08F0BA3B923470C2C07488CC2A73452078DEED079D105AD55609DE79A30993B4A9048F112A3925E081123B7F9FA748D76AF6A8E1E69C8D0E2E80E87941A86169892960F966C845E42EEC4F359885474E530375B251DD638F7806F0C9436383C351F8024C4992485B1DA31419054C5431AD83835A833A03DD2EE729E1B7BF4F54C92C92B1F4493722D1EA8F02C088A70048A610E20914CA51BF786B0FDBA0D52765067A3EF68D315FCE5BD6EE",
                delimiter = null
            )
        }

        return signaturePacket
    }

    @Test
    fun decodePublicKeySignedTest() {
        val data = File(
            file.absolutePath,
            "0EE13652E9E9D0BF7115A3C9A71E2CA57AC1F09A_ecdsa_publickey_signedby_FEFF2E185CF8F063AD2E42463E58DE6CC926B4AD.gpg"
        )
            .readText()
            .replace("\r\n", "\n")
            .trimEnd()
        val (body, _) = PacketDecoder.split(data)
        val expected = Radix64.decode(body)

        val packetPublicKey = PacketPublicKeyV4().also {
            it.algorithm = OpenPgpAlgorithm.EDDSA
            it.createdDateTimeEpoch = 1669448543

            it.publicKey = PublicKeyEcdsa().also {
                it.ellipticCurveParameter = EllipticCurveParameter.Ed25519
                it.ecPoint = parseHexString(
                    "40798EE8F951B43F308C4B5B29684678A0F2893E021532F070B5B5C94E1D01EE33",
                    null
                )
            }
        }

        val packetUserId = PacketUserId().also {
            it.userId = "TEST ARIYAMA (test) <keiji@test.com>"
        }

        val packetSignature1 = createEddsaSignedSignature1Packet()
        val packetSignature2 = createEcdsaSignedSignature2Packet()

        val packetList = listOf(
            packetPublicKey,
            packetUserId,
            packetSignature1,
            packetSignature2,
        )

        val actual = ByteArrayOutputStream().let {
            PacketEncoder.encode(true, packetList, it)
            it.toByteArray()
        }

        val expectedHex = expected.toHex("")
        val actualHex = actual.toHex("")
        assertEquals(expectedHex, actualHex)
    }

    private fun createEddsaSignedSignature1Packet(): PacketSignatureV4 {
        val signaturePacket = PacketSignatureV4()
            .also {
                it.signatureType = SignatureType.PositiveCertificationOfUserId
                it.publicKeyAlgorithm = OpenPgpAlgorithm.EDDSA
                it.hashAlgorithm = HashAlgorithm.SHA2_256
            }

        signaturePacket.hashedSubpacketList = listOf(
            IssuerFingerprint().also {
                it.version = 4
                it.fingerprint =
                    parseHexString("0E:E1:36:52:E9:E9:D0:BF:71:15:A3:C9:A7:1E:2C:A5:7A:C1:F0:9A", delimiter = ":")
            },
            SignatureCreationTime().also {
                it.value = 1669448543
            },
            KeyFlags().also {
                it.flags = byteArrayOf(0x03.toByte())
            },
            PreferredSymmetricAlgorithms().also {
                it.ids = listOf(
                    SymmetricKeyAlgorithm.AES256,
                    SymmetricKeyAlgorithm.AES192,
                    SymmetricKeyAlgorithm.AES128,
                    SymmetricKeyAlgorithm.TripleDES,
                )
            },
            PreferredHashAlgorithms().also {
                it.ids = listOf(
                    HashAlgorithm.SHA2_512,
                    HashAlgorithm.SHA2_384,
                    HashAlgorithm.SHA2_256,
                    HashAlgorithm.SHA2_224,
                    HashAlgorithm.SHA1,
                )
            },
            PreferredCompressionAlgorithms().also {
                it.ids = listOf(
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZip2,
                    CompressionAlgorithm.ZIP,
                )
            },
            Features().also {
                it.flags = byteArrayOf(0x01)
            },
            KeyServerPreferences().also {
                it.flags = byteArrayOf(0x80.toByte())
            }
        )

        signaturePacket.subpacketList = listOf(
            Issuer().also {
                it.keyId = parseHexString("A7:1E:2C:A5:7A:C1:F0:9A", delimiter = ":")
            }
        )

        signaturePacket.hash2bytes = byteArrayOf(0xFF.toByte(), 0xD2.toByte())

        signaturePacket.signature = SignatureEcdsa().also {
            it.r =
                parseHexString(
                    "32:60:1B:C7:1E:D4:7D:87:FC:B7:53:5B:DB:AF:F8:41:05:1C:B8:7F:C2:E4:D0:1A:6A:B0:90:0E:12:EA:F5:8B",
                    delimiter = ":"
                )
            it.s =
                parseHexString(
                    "1E:5B:16:DA:F2:35:D4:08:66:12:B8:EE:DB:A2:96:58:5E:F1:11:5F:94:7F:0D:2B:E8:03:CA:8A:B2:BD:99:0F",
                    delimiter = ":"
                )
        }

        return signaturePacket
    }

    private fun createEcdsaSignedSignature2Packet(): PacketSignatureV4 {
        val signaturePacket = PacketSignatureV4()
            .also {
                it.signatureType = SignatureType.GenericCertificationOfUserId
                it.publicKeyAlgorithm = OpenPgpAlgorithm.ECDSA
                it.hashAlgorithm = HashAlgorithm.SHA2_256
            }

        signaturePacket.hashedSubpacketList = listOf(
            IssuerFingerprint().also {
                it.version = 4
                it.fingerprint =
                    parseHexString("FE:FF:2E:18:5C:F8:F0:63:AD:2E:42:46:3E:58:DE:6C:C9:26:B4:AD", delimiter = ":")
            },
            SignatureCreationTime().also {
                it.value = 1671637004
            },
        )

        signaturePacket.subpacketList = listOf(
            Issuer().also {
                it.keyId = parseHexString("3E:58:DE:6C:C9:26:B4:AD", delimiter = ":")
            }
        )

        signaturePacket.hash2bytes = byteArrayOf(0x5A.toByte(), 0xB8.toByte())

        signaturePacket.signature = SignatureEcdsa().also {
            it.r =
                parseHexString(
                    "B7:01:D7:2D:4D:09:C2:D8:0C:A3:3B:04:FA:EC:CB:6D:F3:62:77:B6:B4:C8:75:2A:8D:DE:DF:75:99:1D:CA:BD",
                    delimiter = ":"
                )
            it.s =
                parseHexString(
                    "EE:E8:68:0C:49:BC:4E:E6:03:EA:BA:6A:0D:24:B2:7F:BA:D2:03:F9:48:54:22:C4:81:B7:2A:58:AC:B1:76:37",
                    delimiter = ":"
                )
        }

        return signaturePacket
    }
}
