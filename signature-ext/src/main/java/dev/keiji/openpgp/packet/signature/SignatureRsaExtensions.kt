package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import dev.keiji.openpgp.packet.Utils
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PublicKeyRsa
import dev.keiji.openpgp.packet.publickey.toNativePublicKey
import dev.keiji.openpgp.toHex
import java.io.ByteArrayOutputStream
import java.security.Signature

fun SignatureRsa.verify(
    packetPublicKey: PacketPublicKey,
    hashAlgorithm: HashAlgorithm,
    contentBytes: ByteArray,
): Boolean {
    val nativeSignature = toNativeSignature()

    val publicKey = packetPublicKey.publicKey
    if (publicKey is PublicKeyRsa) {
        val nativePublicKey = publicKey.toNativePublicKey()

        val hashBytes = Utils.createHashBytes(hashAlgorithm, contentBytes)
        val digestInfo = createDigestInfoAsDer(hashAlgorithm, hashBytes)

        val sign = Signature.getInstance("NONEwithRSA").also {
            it.initVerify(nativePublicKey)
            it.update(digestInfo)
        }
        return sign.verify(nativeSignature)
    }

    return false
}

/**
 *
 * ```
 *      DigestInfo ::= SEQUENCE {
 *          digestAlgorithm SEQUENCE  {
 *               algorithm   OBJECT IDENTIFIER,
 *               parameters  ANY DEFINED BY algorithm OPTIONAL  },
 *          digest OCTET STRING }
 * ```
 */
private fun createDigestInfoAsDer(hashAlgorithm: HashAlgorithm, contentHash: ByteArray): ByteArray {
    val hashAlgorithmOid = hashAlgorithm.oid
    hashAlgorithmOid
        ?: throw UnsupportedHashAlgorithmException("hashAlgorithm ${hashAlgorithm.textName} doesn't have oid.")

    val hashAlgorithmOidLength = hashAlgorithmOid.size
    val contentHashLength = contentHash.size

    val digestAlgorithmSequenceLength = (1 + 1 + hashAlgorithmOidLength) + (1 + 1)
    val digestInfoSequenceLength = (1 + 1 + digestAlgorithmSequenceLength) + (1 + 1 + contentHashLength)

    return ByteArrayOutputStream().let {
        it.write(0x30) // Tag: SEQUENCE
        it.write(digestInfoSequenceLength)

        it.write(0x30) // Tag: SEQUENCE
        it.write(digestAlgorithmSequenceLength)

        it.write(0x06) // OBJECT IDENTIFIER
        it.write(hashAlgorithmOidLength)
        it.write(hashAlgorithmOid)

        it.write(0x05) // Tag: NULL
        it.write(0x00) // length

        // digest
        it.write(0x04) // Tag: OCTET STRING
        it.write(contentHashLength)
        it.write(contentHash)

        it.toByteArray()
    }
}

fun SignatureRsa.toNativeSignature(): ByteArray? {
    return value
}
