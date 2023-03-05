package dev.keiji.openpgp.packet

import dev.keiji.openpgp.HashAlgorithm
import dev.keiji.openpgp.UnsupportedHashAlgorithmException
import java.security.MessageDigest

object Utils {
    private fun getMessageDigest(hashAlgorithm: HashAlgorithm): MessageDigest {
        val algorithmName = when (hashAlgorithm) {
            HashAlgorithm.MD5 -> "MD5"
            HashAlgorithm.SHA1 -> "SHA-1"
            HashAlgorithm.SHA2_256 -> "SHA-256"
            HashAlgorithm.SHA2_384 -> "SHA-384"
            HashAlgorithm.SHA2_512 -> "SHA-512"
            else -> throw UnsupportedHashAlgorithmException("hashAlgorithm ${hashAlgorithm.textName} is not supported.")
        }
        return MessageDigest.getInstance(algorithmName)
    }

    fun createHashBytes(hashAlgorithm: HashAlgorithm, contentBytes: ByteArray): ByteArray {
        return getMessageDigest(hashAlgorithm).let {
            it.update(contentBytes)
            it.digest()
        }
    }
}
