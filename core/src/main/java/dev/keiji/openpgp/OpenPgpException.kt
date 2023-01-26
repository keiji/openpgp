package dev.keiji.openpgp

open class OpenPgpException(override val message: String?) : Exception(message)

open class UnsupportedAlgorithmException(
    override val message: String?,
) : OpenPgpException(message)

class UnsupportedPublicKeyAlgorithmException(
    override val message: String?,
) : UnsupportedAlgorithmException(message)

class UnsupportedSignatureTypeException(override val message: String?) : OpenPgpException(message)
class UnsupportedVersionException(override val message: String?) : OpenPgpException(message)
class UnsupportedRevocationCodeException(override val message: String?) : OpenPgpException(message)

class UnsupportedSubpacketTypeException(override val message: String?) : OpenPgpException(message)
class UnsupportedSymmetricKeyAlgorithmException(override val message: String?) :
    OpenPgpException(message)

class UnsupportedHashAlgorithmException(override val message: String?) : OpenPgpException(message)
class UnsupportedS2KUsageTypeException(override val message: String?) : OpenPgpException(message)
class UnsupportedCompressionAlgorithmException(override val message: String?) :
    OpenPgpException(message)

class UnsupportedAeadAlgorithmException(override val message: String?) : OpenPgpException(message)

class UnsupportedUserAttributeImageVersionException(override val message: String?) : OpenPgpException(message)

class ObsoletePacketDetectedException(override val message: String?) : OpenPgpException(message)
