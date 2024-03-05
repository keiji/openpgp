package dev.keiji.openpgp.packet.signature

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.packet.Utils
import dev.keiji.openpgp.packet.publickey.PacketPublicKey
import dev.keiji.openpgp.packet.publickey.PublicKeyEcdsa
import dev.keiji.openpgp.packet.publickey.toNativePublicKey
import java.io.ByteArrayOutputStream
import java.security.Signature

fun SignatureEcdsa.verify(
    packetPublicKey: PacketPublicKey,
    hashAlgorithm: HashAlgorithm,
    contentBytes: ByteArray,
): Boolean {
    val nativeSignature = toNativeSignature()

    val publicKey = packetPublicKey.publicKey
    if (publicKey is PublicKeyEcdsa) {
        val nativePublicKey = publicKey.toNativePublicKey()

        val hashBytes = Utils.createHashBytes(hashAlgorithm, contentBytes)

        val sign = Signature.getInstance("NoneWithECDSA").also {
            it.initVerify(nativePublicKey)
            it.update(hashBytes)
        }
        return sign.verify(nativeSignature)
    }

    return false
}

/**
 * The class for decoding ASN.1 structure and encoding to appropriate structure for OpenPGP.
 *
 * [Background]
 * It seem to be ASN.1 structure that Signature data getting from java.security.Signature class.
 *
 * Sample data below.
 *
 * ```
 * 30:44:
 *    02:20:
 *        61:50:06:8D:CD:82:04:A4:
 *        A9:F0:2B:E2:69:4A:96:32:
 *        BE:2C:90:3A:AC:4E:A1:55:
 *        90:32:82:15:7A:53:38:56:
 *     02:20:
 *        6E:52:12:D0:3E:11:EE:F3:
 *        C4:2A:41:78:C7:28:37:4B:
 *        12:C7:E2:65:EB:93:AE:1D:
 *        84:E3:23:F7:6D:B3:A4:00
 * ```
 *
 * Android and Java API document are not written about this behavior.
 * https://developer.android.com/reference/java/security/Signature
 * https://docs.oracle.com/javase/8/docs/api/java/security/Signature.html
 *
 * And in JavaCard OS document, this specification is written explicitly.
 * https://docs.oracle.com/javacard/3.0.5/api/javacard/security/Signature.html
 *
 * > The signature is encoded as an ASN.1 sequence of two INTEGER values,
 * > r and s, in that order: SEQUENCE ::= { r INTEGER, s INTEGER }
 */
fun SignatureEcdsa.toNativeSignature(): ByteArray? {
    val rSnapshot = r ?: return null
    val sSnapshot = s ?: return null

    val rLength = rSnapshot.size
    val sLength = sSnapshot.size

    val length = 1 + 1 + rLength + 1 + 1 + sLength

    @Suppress("MagicNumber")
    return ByteArrayOutputStream().let {
        it.write(0x30)
        it.write(length)

        it.write(0x02)
        it.write(rLength)
        it.write(rSnapshot)

        it.write(0x02)
        it.write(sLength)
        it.write(sSnapshot)

        it.toByteArray()
    }
}
