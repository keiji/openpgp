@file:Suppress("MagicNumber")

package dev.keiji.openpgp.packet.signature.subpacket

import dev.keiji.openpgp.UnsupportedRevocationCodeException
import dev.keiji.openpgp.toHex
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

class ReasonForRevocation : Subpacket() {
    enum class Reason(val value: Int) {
        NoReasonSpecified(0),
        KeyIsSuperseded(1),
        KeyMaterialHasBeenCompromised(2),
        KeyIsRetiredAndNoLongerUsed(3),
        UserIdInformationIsNoLongerValid(32),
        PrivateUse100(100),
        PrivateUse101(101),
        PrivateUse102(102),
        PrivateUse103(103),
        PrivateUse104(104),
        PrivateUse105(105),
        PrivateUse106(106),
        PrivateUse107(107),
        PrivateUse108(108),
        PrivateUse109(109),
        PrivateUse110(110),
        ;

        companion object {
            fun findBy(value: Int): Reason? = values().firstOrNull { it.value == value }
        }
    }

    override val typeValue: Int = SubpacketType.ReasonForRevocation.value

    var code: Reason = Reason.NoReasonSpecified

    var reason: String? = null

    override fun readFrom(inputStream: InputStream) {
        val codeByte = inputStream.read()
        code = Reason.findBy(codeByte)
            ?: throw UnsupportedRevocationCodeException("Revocation code $codeByte is not supported.")

        val reasonBytes = inputStream.readBytes()
        reason = String(reasonBytes, StandardCharsets.UTF_8)
    }

    override fun writeContentTo(outputStream: OutputStream) {
        val codeByte = code.value
        outputStream.write(codeByte)

        val reasonBytes = reason?.toByteArray(charset = Charsets.UTF_8)
        reasonBytes?.also {
            outputStream.write(it)
        }
    }

    override fun toDebugString(): String {
        return " * ReasonForRevocation\n" +
                "   * code: ${code.value.toHex()}\n" +
                "   * reason: $reason\n" +
                ""
    }
}
