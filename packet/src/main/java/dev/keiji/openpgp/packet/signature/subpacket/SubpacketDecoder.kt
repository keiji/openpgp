package dev.keiji.openpgp.packet.signature.subpacket

import java.io.ByteArrayInputStream

object SubpacketDecoder {
    interface Callback {
        fun onSubpacketDetected(header: SubpacketHeader, byteArray: ByteArray)
    }

    fun decode(byteArray: ByteArray): List<Subpacket> {
        val packetList = mutableListOf<Subpacket>()

        decode(byteArray, object : Callback {
            override fun onSubpacketDetected(header: SubpacketHeader, byteArray: ByteArray) {
//                println("subpacketType: ${header.typeValue}, length: ${header.length}")

                val tag = SubpacketType.findBy(header.typeValue)
                val bais = ByteArrayInputStream(byteArray)

                val subpacket = when (tag) {
                    SubpacketType.IssuerFingerprint -> IssuerFingerprint().also { it.readFrom(bais) }
                    SubpacketType.SignatureCreationTime -> SignatureCreationTime().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.SignatureExpirationTime -> SignatureExpirationTime().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.KeyFlags -> KeyFlags().also { it.readFrom(bais) }
                    SubpacketType.PreferredAeadAlgorithms -> PreferredAeadAlgorithms().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.PreferredSymmetricAlgorithms -> PreferredSymmetricAlgorithms().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.PreferredHashAlgorithms -> PreferredHashAlgorithms().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.PreferredCompressionAlgorithms -> PreferredCompressionAlgorithms().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.KeyExpirationTime -> KeyExpirationTime().also { it.readFrom(bais) }
                    SubpacketType.ExportableCertification -> ExportableCertification().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.Revocable -> Revocable().also { it.readFrom(bais) }
                    SubpacketType.TrustSignature -> TrustSignature().also { it.readFrom(bais) }
                    SubpacketType.RegularExpression -> RegularExpression().also { it.readFrom(bais) }
                    SubpacketType.NotationData -> NotationData().also { it.readFrom(bais) }
                    SubpacketType.Features -> Features().also { it.readFrom(bais) }
                    SubpacketType.KeyServerPreferences -> KeyServerPreferences().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.Issuer -> Issuer().also { it.readFrom(bais) }
                    SubpacketType.AttestedCertifications -> AttestedCertifications().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.EmbeddedSignature -> EmbeddedSignature().also { it.readFrom(bais) }
                    SubpacketType.SignerUserId -> SignersUserId().also { it.readFrom(bais) }
                    SubpacketType.ReasonForRevocation -> ReasonForRevocation().also {
                        it.readFrom(bais)
                    }

                    SubpacketType.PrimaryUserId -> PrimaryUserId().also { it.readFrom(bais) }
                    SubpacketType.SignatureTarget -> SignatureTarget().also { it.readFrom(bais) }
                    SubpacketType.KeyBlock -> KeyBlock().also { it.readFrom(bais) }
                    SubpacketType.PreferredAeadCiphersuites -> {
                        PreferredAeadCiphersuites().also { it.readFrom(bais) }
                    }

                    else -> Unknown(header.typeValue).also { it.readFrom(bais) }
                }
                packetList.add(subpacket)
            }
        })

        return packetList
    }

    fun decode(byteArray: ByteArray, callback: Callback) {
        val inputStream = ByteArrayInputStream(byteArray)

        while (inputStream.available() > 0) {
            val header = SubpacketHeader().also {
                it.readFrom(inputStream)
            }

            // The length includes the type-octet but not length-octets.
            val bodyLength = header.length - 1

            val data = ByteArray(bodyLength).also {
                inputStream.read(it)
            }
            callback.onSubpacketDetected(header, data)
        }
    }
}
