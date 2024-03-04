package dev.keiji.openpgp

import java.security.MessageDigest

object KdfUtils {
    private const val EXPBIAS = 6

    /**
     * In OpenPGP Card Application specification,
     * https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf
     *
     * ```
     * If the KDF format is supported, the maximum length for all passwords in the PW status
     * bytes should be at least 64 bytes, to be able to store a SHA512 hash value.
     * ```
     */
    fun iteration(
        dataBytes: ByteArray,
        salt: ByteArray,
        iterationCount: Long,
        digestAlgorithm: String = "SHA-256",
    ): ByteArray {
        var count = calculateIterationCount(iterationCount)

        val messageDigest = MessageDigest.getInstance(digestAlgorithm)

        // https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/pg/src/main/java/org/bouncycastle/openpgp/operator/PGPUtil.java#L132-L163
        @Suppress("LoopWithTooManyJumpStatements")
        while (count > 0) {
            if (count < salt.size) {
                messageDigest.update(salt, 0, count.toInt())
                break
            } else {
                messageDigest.update(salt)
                count -= salt.size
            }

            if (count < dataBytes.size) {
                messageDigest.update(dataBytes, 0, count.toInt())
                break
            } else {
                messageDigest.update(dataBytes)
                count -= dataBytes.size
            }
        }

        return messageDigest.digest()
    }

    /**
     * https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#name-iterated-and-salted-s2k
     * ```
     * The count is coded into a one-octet number using the following formula:
     *
     * #define EXPBIAS 6
     * count = ((Int32)16 + (c & 15)) << ((c >> 4) + EXPBIAS);
     * ```
     */
    fun calculateIterationCount(iterationCount: Long): Long {
        return if (iterationCount >= 0x100) { /* 256 */
            iterationCount
        } else {
            (16 + (iterationCount and 15)) shl (((iterationCount ushr 4) + EXPBIAS).toInt())
        }
    }
}
